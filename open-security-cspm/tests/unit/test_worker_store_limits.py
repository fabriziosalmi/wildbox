"""The worker does not wait for ever for the scan store, and a scan whose
last write fails is not lost (#788).

The worker's Redis client had no timeout. #778 gave the API's clients theirs
and left the worker's as "a decision of its own": a limit on the replies can
fail the write that ends a scan, and with it the report of an account that
took an hour to scan. Without one, a Redis that accepts and never answers
held the task where it was, for ever.

The decision: the client has the API's limits, and the write that ends a scan
is made again, a bounded number of times, each failure logged. When the
report cannot be stored the scan ends as failed, with that reason, as soon as
the store answers; when the store stays away for all of it, the worker goes
on to its next task, says by its id which scan it left in progress, and the
record expires with the retention.

The scans are started through the API and run by the worker's own task, in
this process (route_probes). The store is the fake Redis behind a door that
can be shut: a command sent while it is shut ends as the real client's does
at its read timeout. One test asks the real client, in a worker process of
its own, of a server that never answers.
"""

import json
import logging
import subprocess
import sys

import pytest
import redis
from app import connections, scan_store, worker
from route_probes import HEADERS, run_worker, start_scan
from stalls import SERVICE_ROOT, Silent

PAUSES = list(worker.FINAL_WRITE_PAUSES)
ATTEMPTS = len(PAUSES) + 1


class Door:
    """The fake Redis, which answers while ``answers()`` says so."""

    def __init__(self, server):
        self._server = server
        self.answers = lambda: True
        # The commands that got no answer.
        self.unanswered = []
        # Called with the name of each command that was answered.
        self.answered = lambda name: None

    def _ask(self, target, name):
        def command(*args, **kwargs):
            if not self.answers():
                self.unanswered.append(name)
                raise redis.exceptions.TimeoutError("Timeout reading from socket")
            result = getattr(target, name)(*args, **kwargs)
            self.answered(name)
            return result

        return command

    def __getattr__(self, name):
        return self._ask(self._server, name)

    def pipeline(self):
        return _Pipe(self, self._server.pipeline())


class _Pipe:
    def __init__(self, door, pipe):
        self._door = door
        self._pipe = pipe

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._pipe.reset()

    def multi(self):
        # No command is sent: redis-py queues from here on.
        self._pipe.multi()

    def __getattr__(self, name):
        return self._door._ask(self._pipe, name)


@pytest.fixture
def scan(world, monkeypatch, caplog):
    """A queued scan, the worker's store behind a door, and the pauses the
    worker took instead of sleeping."""
    door = Door(world.redis)
    monkeypatch.setattr(worker, "redis_client", door)
    pauses = []
    monkeypatch.setattr(worker, "_pause", pauses.append)
    scan_id = start_scan(
        world.client,
        account_id="777777777777",
        check_ids=[check.metadata.check_id for check in world.checks],
    )
    caplog.set_level(logging.WARNING, logger=worker.__name__)

    class Scan:
        id = scan_id

        def run(self):
            return run_worker(world.queue, scan_id)

        def metadata(self):
            return scan_store.load_metadata(world.redis, scan_id)

        def report(self):
            return scan_store.load_report(world.redis, scan_id)

        def status(self):
            response = world.client.get(f"/api/v1/scans/{scan_id}", headers=HEADERS)
            assert response.status_code == 200, response.text
            return response.json()["status"]

        def said(self, level=logging.WARNING):
            return [
                record.getMessage()
                for record in caplog.records
                if record.name == worker.__name__ and record.levelno >= level
            ]

    scan = Scan()
    scan.door = door
    scan.pauses = pauses
    scan.world = world
    return scan


def _shut_from_the_last_write(scan, opens_after=None):
    """The store answers the scan's reads, and stops when the write that
    ends the scan begins. ``opens_after``: it answers again once the worker
    has paused that many times."""
    state = {"shut": False}
    real = scan_store.complete_scan

    def complete_scan(*args, **kwargs):
        state["shut"] = True
        return real(*args, **kwargs)

    worker.scan_store.complete_scan = complete_scan
    scan.door.answers = lambda: not state["shut"] or (
        opens_after is not None and len(scan.pauses) >= opens_after
    )
    return lambda: setattr(worker.scan_store, "complete_scan", real)


@pytest.fixture
def shut(scan):
    restore = []

    def shut_from_the_last_write(opens_after=None):
        restore.append(_shut_from_the_last_write(scan, opens_after))

    yield shut_from_the_last_write
    for undo in restore:
        undo()


# --- The client ------------------------------------------------------------------


def test_the_workers_scan_store_client_has_the_limits_the_apis_has():
    kwargs = worker.redis_client.connection_pool.connection_kwargs

    # main: neither key was there.
    assert kwargs["socket_connect_timeout"] == connections.REDIS_CONNECT_TIMEOUT_SECONDS
    assert kwargs["socket_timeout"] == connections.REDIS_READ_TIMEOUT_SECONDS
    assert kwargs["decode_responses"] is True


def test_a_worker_process_gives_up_on_a_redis_that_never_answers():
    """The real client, in a process that imports what the worker imports."""
    silent = Silent()
    script = (
        "import time; from app import worker; started = time.monotonic()\n"
        "try:\n"
        "    worker.scan_store.load_metadata(worker.redis_client, 'scan')\n"
        "    print('answered')\n"
        "except Exception as error:\n"
        "    print(type(error).__module__, type(error).__name__,"
        " round(time.monotonic() - started))\n"
    )
    try:
        # main: no answer, and the test ends this at its own limit.
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=SERVICE_ROOT,
            env={**__import__("os").environ, "REDIS_URL": silent.url},
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        silent.close()

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == (
        f"redis.exceptions TimeoutError {connections.REDIS_READ_TIMEOUT_SECONDS:.0f}"
    )


# --- The write that ends a scan ---------------------------------------------------


def test_a_last_write_the_store_does_not_answer_is_made_again(scan, shut):
    shut(opens_after=2)

    result = scan.run()

    # The third attempt was answered: the scan is completed, with its report.
    assert result.state == "SUCCESS" and result.result["status"] == "completed"
    assert scan.metadata()["status"] == "completed"
    assert "failure_reason" not in scan.metadata()
    assert scan.report()["scan_id"] == scan.id
    assert scan.status() == "completed"
    assert scan.pauses == PAUSES[:2]
    assert scan.said() == [
        f"Scan {scan.id}: its report could not be written, attempt 1 of "
        f"{ATTEMPTS} (TimeoutError): trying again in 1 seconds",
        f"Scan {scan.id}: its report could not be written, attempt 2 of "
        f"{ATTEMPTS} (TimeoutError): trying again in 3 seconds",
    ]


def test_a_report_that_cannot_be_stored_ends_the_scan_as_failed_with_that_reason(
    scan, shut
):
    """The store is away for every attempt at the report, and back when the
    worker records the failure."""
    shut(opens_after=len(PAUSES) + 1)
    # One pause more than the report's attempts take: the failure's first
    # attempt goes unanswered too, and its second is answered.

    result = scan.run()

    assert result.state == "FAILURE"
    assert isinstance(result.result, worker.ScanReportNotStored)
    metadata = scan.metadata()
    assert metadata["status"] == "failed"
    assert (
        metadata["failure_reason"]
        == scan_store.REPORT_NOT_STORED
        == "report_not_stored"
    )
    assert "failed_at" in metadata and "completed_at" not in metadata
    # Not completed, so no report, and the team's figures do not count it.
    assert scan.report() is None
    assert scan.status() == "failed"
    assert scan.pauses == PAUSES + PAUSES[:1]
    errors = scan.said(logging.ERROR)
    assert errors == [
        f"Scan {scan.id}: its report could not be written, attempt {ATTEMPTS} of "
        f"{ATTEMPTS} (TimeoutError): given up"
    ]


def test_a_store_that_stays_away_does_not_hold_the_worker_and_is_said(scan, shut):
    shut()
    ttl_before = scan.world.redis.ttl(scan_store.metadata_key(scan.id))

    result = scan.run()

    # The task ended: the worker takes its next one. main: it never did.
    assert result.state == "FAILURE"
    assert isinstance(result.result, worker.ScanReportNotStored)
    # Every attempt of the two writes, and no more.
    assert scan.pauses == PAUSES + PAUSES
    assert len(scan.door.unanswered) == 2 * ATTEMPTS
    assert scan.said(logging.ERROR) == [
        f"Scan {scan.id}: its report could not be written, attempt {ATTEMPTS} of "
        f"{ATTEMPTS} (TimeoutError): given up",
        f"Scan {scan.id}: its failure could not be written, attempt {ATTEMPTS} of "
        f"{ATTEMPTS} (TimeoutError): given up",
        f"Scan {scan.id} failed and could not be marked failed (TimeoutError): "
        "its record says it is in progress until it expires, "
        "CSPM_REPORT_RETENTION_DAYS after it started",
    ]
    # Nothing was written: the record is the one the scan started with, and
    # it expires when it would have.
    assert scan.metadata()["status"] == "started"
    assert scan.report() is None
    assert 0 < scan.world.redis.ttl(scan_store.metadata_key(scan.id)) == ttl_before
    assert ttl_before == scan_store.retention_seconds()


def test_a_write_that_reached_redis_and_lost_its_reply_is_not_made_twice(scan):
    """The transaction ran and the client did not hear so. The second
    attempt finds the scan completed, and the task says completed."""
    lost = []

    def lose_the_first_reply(name):
        if name == "execute" and not lost:
            lost.append(name)
            raise redis.exceptions.TimeoutError("Timeout reading from socket")

    scan.door.answered = lose_the_first_reply

    result = scan.run()

    assert lost == ["execute"]
    assert result.state == "SUCCESS" and result.result["status"] == "completed"
    assert scan.metadata()["status"] == "completed"
    assert scan.report()["scan_id"] == scan.id
    assert scan.pauses == PAUSES[:1]


def test_a_scan_whose_first_read_gets_no_answer_fails_and_is_marked_when_it_can_be(
    scan,
):
    """Not the last write: the task's first read of the store. It ended the
    task as the store's own error; the failure is still recorded."""
    asked = []
    scan.door.answers = lambda: bool(asked.append(1)) or len(asked) > 1

    result = scan.run()

    assert result.state == "FAILURE"
    assert isinstance(result.result, redis.exceptions.TimeoutError)
    assert scan.metadata()["status"] == "failed"
    assert "failure_reason" not in scan.metadata()
    assert scan.pauses == []


def test_an_error_that_is_not_the_stores_absence_is_not_tried_again(scan, shut):
    def refuse(*args, **kwargs):
        raise redis.exceptions.ResponseError("OOM command not allowed")

    real = scan_store.complete_scan
    worker.scan_store.complete_scan = refuse
    try:
        result = scan.run()
    finally:
        worker.scan_store.complete_scan = real

    assert result.state == "FAILURE"
    assert scan.pauses == []
    assert scan.metadata()["status"] == "failed"
    assert "failure_reason" not in scan.metadata()


def test_the_pauses_are_few_and_fit_a_restart_of_redis():
    """Bounded: four attempts, the last one 13 seconds after the first. A
    Redis that restarts with an append-only file to load is back sooner."""
    assert PAUSES == [1.0, 3.0, 9.0]
    assert PAUSES == sorted(PAUSES)
    worst = sum(PAUSES) + ATTEMPTS * connections.REDIS_READ_TIMEOUT_SECONDS
    assert worst == 25.0


def test_the_reason_is_kept_with_the_scan_and_only_for_a_failure(fake_redis):
    scan_store.save_metadata(
        fake_redis, {"scan_id": "s-1", "team_id": "t-1", "status": "started"}
    )

    scan_store.fail_scan(fake_redis, "s-1", "2026-10-06T10:00:00", "report_not_stored")

    stored = json.loads(fake_redis.get(scan_store.metadata_key("s-1")))
    assert stored["status"] == "failed"
    assert stored["failure_reason"] == "report_not_stored"
    assert stored["failed_at"] == "2026-10-06T10:00:00"
