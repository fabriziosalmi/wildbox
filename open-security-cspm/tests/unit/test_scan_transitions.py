"""A scan ends once: completed, failed or cancelled, whoever gets there first (#778).

The API cancels a scan; the worker completes or fails it. They are two
processes, and each read the scan's metadata, decided, and wrote it back in
separate commands. Two that crossed decided on the same reading:

- a completion that read before a cancellation and wrote after it left a
  scan the API had answered "cancelled" for recorded as completed;
- a cancellation that read before a completion and wrote after it left a
  scan recorded as cancelled, without its completion time, whose report was
  stored and counted in the team's figures;
- ``complete_scan`` did not look at the status at all.

The races are made here, not waited for: the client the operation under test
uses lets the other operation in right after its first read of the scan's
metadata, which is the moment the two used to cross. Every race runs on the
suite's Redis double and on a Redis server (a throwaway container), so the
double's WATCH is held to the server's. The server tests need Docker: they
are skipped where there is none, and CI sets WILDBOX_REQUIRE_DOCKER_TESTS=1
so that they run there.
"""

import os
import shutil
import subprocess
import time
import uuid

import pytest
import redis
from app import scan_store, worker
from route_probes import HEADERS, TEAM, run_worker

REDIS_IMAGE = "redis:7-alpine"  # the image docker-compose.yml runs
AT = "2026-10-06T12:00:00"
REPORT = {"scan_id": "set-by-the-store", "status": "completed", "results": []}


# --- The two stores ----------------------------------------------------------------


def _docker_available():
    if not shutil.which("docker"):
        return False
    return (
        subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode
        == 0
    )


@pytest.fixture(scope="module")
def redis_server():
    """A Redis server in a container, for this module, removed at its end."""
    if not _docker_available():
        if os.environ.get("WILDBOX_REQUIRE_DOCKER_TESTS") == "1":
            pytest.fail("docker is required for these tests and is not available")
        pytest.skip("docker is not available")
    container = f"wbtest778-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", container]
        + ["-p", "127.0.0.1::6379", REDIS_IMAGE],
        check=True,
        capture_output=True,
        timeout=300,
    )
    try:
        published = subprocess.run(
            ["docker", "port", container, "6379/tcp"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.split()[0]
        client = redis.from_url(f"redis://{published}/0", decode_responses=True)
        deadline = time.monotonic() + 60
        while True:
            try:
                if client.ping():
                    break
            except redis.exceptions.RedisError:
                if time.monotonic() > deadline:
                    raise
            time.sleep(0.2)
        yield client
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container], capture_output=True, timeout=60
        )


@pytest.fixture(params=["double", "server"])
def store(request):
    """The store the scans are in: the suite's double, then a Redis server."""
    if request.param == "double":
        return request.getfixturevalue("fake_redis")
    client = request.getfixturevalue("redis_server")
    client.flushdb()
    return client


def _started(store):
    """A scan as the API records it when it queues it; its id."""
    scan_id = str(uuid.uuid4())
    scan_store.save_metadata(
        store,
        {
            "scan_id": scan_id,
            "provider": "aws",
            "account_id": "123456789012",
            "status": "started",
            "started_at": "2026-10-06T11:00:00",
            "requested_by": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            "team_id": TEAM,
        },
    )
    return scan_id


# --- A race, made ------------------------------------------------------------------


class Crossing:
    """A client that lets ``other`` run right after the first read of ``key``.

    Whether the read is the client's own GET or one made inside a pipeline:
    the operation under test has read the scan, has not written it yet, and
    the other operation runs to its end on the plain client.
    """

    def __init__(self, client, key, other):
        self._client = client
        self._key = key
        self._other = other
        self.crossed = 0

    def _after_read(self, key):
        if key == self._key and not self.crossed:
            self.crossed += 1
            self._other()

    def get(self, key):
        value = self._client.get(key)
        self._after_read(key)
        return value

    def pipeline(self, *args, **kwargs):
        return _CrossingPipeline(self._client.pipeline(*args, **kwargs), self)

    def __getattr__(self, name):
        return getattr(self._client, name)


class _CrossingPipeline:
    def __init__(self, pipeline, crossing):
        self._pipeline = pipeline
        self._crossing = crossing

    def __enter__(self):
        self._pipeline.__enter__()
        return self

    def __exit__(self, *exc_info):
        return self._pipeline.__exit__(*exc_info)

    def get(self, key):
        value = self._pipeline.get(key)
        self._crossing._after_read(key)
        return value

    def __getattr__(self, name):
        return getattr(self._pipeline, name)


OPERATIONS = {
    "complete": lambda client, scan_id: scan_store.complete_scan(
        client, scan_id, dict(REPORT), AT
    ),
    "fail": lambda client, scan_id: scan_store.fail_scan(client, scan_id, AT),
    "cancel": lambda client, scan_id: scan_store.cancel_scan(client, scan_id, AT),
}
ENDS = {"complete": "completed", "fail": "failed", "cancel": "cancelled"}
TIME_FIELDS = {
    "completed": "completed_at",
    "failed": "failed_at",
    "cancelled": "cancelled_at",
}


def _assert_ended_as(store, scan_id, status):
    """The scan has that final status, and nothing of any other end."""
    metadata = scan_store.load_metadata(store, scan_id)
    assert metadata["status"] == status
    for end, field in TIME_FIELDS.items():
        assert (field in metadata) == (end == status), metadata
    # A report for a completed scan, and for no other.
    report = scan_store.load_report(store, scan_id)
    assert (report is not None) == (status == "completed")
    # Still the team's, with the retention of its metadata.
    assert [m["scan_id"] for m in scan_store.team_scan_metadata(store, TEAM)] == [
        scan_id
    ]
    assert store.ttl(scan_store.metadata_key(scan_id)) > 0


RACES = [
    (first, second) for first in OPERATIONS for second in OPERATIONS if first != second
]


@pytest.mark.parametrize(
    "slow, quick", RACES, ids=[f"{a} crossed by {b}" for a, b in RACES]
)
def test_two_ends_that_cross_leave_the_one_that_wrote_first(store, slow, quick):
    """``slow`` reads the scan in progress; ``quick`` then ends it; ``slow``
    goes on. The scan is what ``quick`` made it, whole, and ``slow`` is told
    it did not end the scan."""
    scan_id = _started(store)
    outcomes = {}
    crossing = Crossing(
        store,
        scan_store.metadata_key(scan_id),
        lambda: outcomes.update(quick=OPERATIONS[quick](store, scan_id)),
    )

    outcomes["slow"] = OPERATIONS[slow](crossing, scan_id)

    assert crossing.crossed == 1
    _assert_ended_as(store, scan_id, ENDS[quick])
    # complete_scan and cancel_scan answer whether they ended the scan.
    assert outcomes["quick"] in (True, None)
    assert outcomes["slow"] in (False, None)
    assert (outcomes["slow"] is None) == (slow == "fail")


@pytest.mark.parametrize("first", list(OPERATIONS))
@pytest.mark.parametrize("second", list(OPERATIONS))
def test_a_scan_that_ended_is_not_ended_again(store, first, second):
    """One after the other, no race: the first end stays, whatever comes."""
    scan_id = _started(store)
    OPERATIONS[first](store, scan_id)
    stored = store.get(scan_store.metadata_key(scan_id))
    report = store.get(scan_store.report_key(scan_id))

    outcome = OPERATIONS[second](store, scan_id)

    assert outcome in (False, None)
    assert store.get(scan_store.metadata_key(scan_id)) == stored
    assert store.get(scan_store.report_key(scan_id)) == report
    _assert_ended_as(store, scan_id, ENDS[first])


@pytest.mark.parametrize("operation", list(OPERATIONS))
def test_each_end_of_a_scan_in_progress(store, operation):
    scan_id = _started(store)

    outcome = OPERATIONS[operation](store, scan_id)

    assert outcome in (True, None)
    _assert_ended_as(store, scan_id, ENDS[operation])
    assert scan_store.load_metadata(store, scan_id)[TIME_FIELDS[ENDS[operation]]] == AT
    if operation == "complete":
        assert scan_store.load_report(store, scan_id) == {**REPORT, "scan_id": scan_id}
        assert store.ttl(scan_store.report_key(scan_id)) > 0


@pytest.mark.parametrize("operation", list(OPERATIONS))
def test_a_scan_that_is_gone_is_not_ended(store, operation):
    scan_id = str(uuid.uuid4())

    outcome = OPERATIONS[operation](store, scan_id)

    assert outcome in (False, None)
    assert store.get(scan_store.metadata_key(scan_id)) is None
    assert store.get(scan_store.report_key(scan_id)) is None
    assert list(scan_store.team_scan_metadata(store, TEAM)) == []


def test_a_scan_deleted_under_an_end_is_not_brought_back(store):
    """The metadata goes (its retention ends, or the scan is forgotten)
    between the read and the write: the write must not make it again."""
    scan_id = _started(store)
    crossing = Crossing(
        store,
        scan_store.metadata_key(scan_id),
        lambda: scan_store.forget_scan(store, scan_id, TEAM),
    )

    assert scan_store.complete_scan(crossing, scan_id, dict(REPORT), AT) is False

    assert store.get(scan_store.metadata_key(scan_id)) is None
    assert store.get(scan_store.report_key(scan_id)) is None


def test_the_watch_does_not_outlive_the_transaction(store):
    """The connection goes back to the pool unwatched: a later transaction
    on it is not refused for a key this one watched."""
    first, second = _started(store), _started(store)

    assert scan_store.cancel_scan(store, first, AT) is True
    # Refused without a write: the watch is dropped by hand.
    assert scan_store.cancel_scan(store, first, AT) is False
    store.setex(scan_store.metadata_key(first), 60, "{}")
    assert scan_store.cancel_scan(store, second, AT) is True


# --- Through the API and the worker's own task ---------------------------------------


def test_a_scan_cancelled_while_the_worker_runs_it_stays_cancelled(world, monkeypatch):
    """The revocation does not always stop the worker's process in time
    (the worker restarted; ``terminate`` reaches a child that is past its
    last check). The scan the API answered "cancelled" for ended as
    completed, with a report: the completion never looked at the status."""
    scan_id = world.scans.queued
    opened = []

    def create_session(provider, credentials):
        # The worker has taken the scan and decrypted its credentials: it
        # is running. The cancellation comes now, and does not stop it.
        response = world.client.delete(f"/api/v1/scans/{scan_id}", headers=HEADERS)
        opened.append(response.status_code)
        return object()

    monkeypatch.setattr(worker, "_create_cloud_session", create_session)

    result = run_worker(world.queue, scan_id)

    assert opened == [200]
    assert result.state == "SUCCESS"
    assert result.result == {"scan_id": scan_id, "status": "cancelled"}
    status = world.client.get(f"/api/v1/scans/{scan_id}", headers=HEADERS).json()
    assert status["status"] == "cancelled"
    assert status["completed_at"] is None
    metadata = scan_store.load_metadata(world.redis, scan_id)
    assert "completed_at" not in metadata and metadata["cancelled_at"]
    assert scan_store.load_report(world.redis, scan_id) is None
    report = world.client.get(f"/api/v1/scans/{scan_id}/report", headers=HEADERS)
    assert report.status_code == 400, report.text


def test_a_scan_whose_metadata_is_gone_still_ends_its_task_as_before(world):
    """Not a cancellation: the worker's answer for this case is unchanged."""
    scan_id = world.scans.queued
    world.redis.delete(scan_store.metadata_key(scan_id))

    result = run_worker(world.queue, scan_id)

    assert result.state == "SUCCESS"
    assert result.result["status"] == "completed"
    assert scan_store.load_report(world.redis, scan_id) is None


# --- The result backend, on the Redis server --------------------------------------


def test_the_result_backend_takes_its_subscription_up_again_after_a_lost_connection(
    redis_server,
):
    """What Celery does when the connection it listens on for results is
    lost while no task is subscribed to (#788).

    With redis-py 5.0.1 it raised AttributeError: that release alone named
    Connection.register_connect_callback with a leading underscore, and
    Celery's ResultConsumer._reconnect_pubsub calls the public name. In the
    API it showed in the log, as "Exception ignored in
    AsyncResult.__del__". This test failed that way on the lock of 0.12.1,
    on the Redis server of this module, and passes since the lock has
    redis-py 5.0.8 (open-security-cspm/requirements.in says why).

    Here because it needs a server that answers a new connection, which this
    module has.
    """
    from celery import Celery

    address = redis_server.connection_pool.connection_kwargs
    url = f"redis://{address['host']}:{address['port']}/0"
    app = Celery("cspm-test", broker="memory://", backend=url)

    app.backend.result_consumer._reconnect_pubsub()

    assert app.backend.result_consumer._pubsub.connection is not None
