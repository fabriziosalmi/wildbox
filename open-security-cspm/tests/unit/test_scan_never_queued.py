"""A scan that could not be queued is not left recorded (#778).

``POST /api/v1/scans`` writes the scan's credentials and metadata, then
queues the task. When the broker refused the task the answer was 503, and
what had been written stayed: the scan read ``queued`` in the team's
figures until its retention ended, 90 days by default, with no task behind
it and an id the caller was never told; its credentials waited five minutes
in Redis for a worker that would not come.

Each test looks at the answer and at what the store holds afterwards.
"""

import logging

import pytest
import redis
from app import main, scan_store
from celery.exceptions import OperationalError
from route_probes import HEADERS, TEAM, scan_request

MARKER = "queue-3.internal:6379 said no"


def _store(world):
    """Everything the fake Redis holds, by key."""
    world.redis.keys("*")  # drops what has expired
    return {
        "values": dict(world.redis.values),
        "index": dict(world.redis.zsets.get(scan_store.team_index_key(TEAM), {})),
    }


def _summary(world):
    response = world.client.get("/api/v1/dashboard/summary", headers=HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


class Refusing:
    """A broker that refuses the task, and remembers which scan it was."""

    def __init__(self, error, after=0):
        self.error = error
        self.after = after
        self.taken = []
        self.refused = []

    def apply_async(self, args, task_id):
        if len(self.taken) < self.after:
            self.taken.append(task_id)
            return
        self.refused.append(task_id)
        raise self.error


@pytest.mark.parametrize(
    "error, status",
    [
        (OperationalError(MARKER), 503),
        (redis.exceptions.TimeoutError(MARKER), 503),
        (redis.exceptions.ConnectionError(MARKER), 503),
        # Not unavailability: a 500, and no more of a scan for that.
        (RuntimeError(MARKER), 500),
    ],
    ids=lambda value: type(value).__name__ if isinstance(value, Exception) else "",
)
def test_a_scan_the_broker_refuses_leaves_nothing_behind(
    world, monkeypatch, error, status
):
    before = _store(world)
    summary = _summary(world)
    broker = Refusing(error)
    monkeypatch.setattr(main, "run_cspm_scan_task", broker)

    response = world.client.post(
        "/api/v1/scans", json=scan_request("777777777777"), headers=HEADERS
    )

    assert response.status_code == status, response.text
    assert MARKER not in response.text
    (scan_id,) = broker.refused
    assert scan_id not in response.text
    # No metadata, no credentials, no entry in the team's index.
    assert world.redis.get(scan_store.metadata_key(scan_id)) is None
    assert world.redis.get(scan_store.credentials_key(scan_id)) is None
    assert world.redis.zscore(scan_store.team_index_key(TEAM), scan_id) is None
    assert _store(world) == before
    # So it is not a scan of the team's: not counted, and not found.
    assert _summary(world) == summary
    read = world.client.get(f"/api/v1/scans/{scan_id}", headers=HEADERS)
    assert read.status_code == 404, read.text


def test_the_scan_was_recorded_while_it_was_being_queued(world, monkeypatch):
    """What the cleanup removes is there to remove: a worker that takes the
    task at once finds the scan's metadata and its credentials."""
    seen = {}

    class Looking:
        def apply_async(self, args, task_id):
            seen["metadata"] = scan_store.load_metadata(world.redis, task_id)
            seen["credentials"] = world.redis.get(scan_store.credentials_key(task_id))
            seen["indexed"] = world.redis.zscore(
                scan_store.team_index_key(TEAM), task_id
            )
            raise OperationalError(MARKER)

    monkeypatch.setattr(main, "run_cspm_scan_task", Looking())

    world.client.post("/api/v1/scans", json=scan_request(), headers=HEADERS)

    assert seen["metadata"]["status"] == "started"
    assert seen["credentials"]
    assert seen["indexed"] is not None


def test_a_batch_keeps_the_scans_it_queued_and_not_the_one_it_could_not(
    world, monkeypatch
):
    before = _store(world)
    broker = Refusing(OperationalError(MARKER), after=1)
    monkeypatch.setattr(main, "run_cspm_scan_task", broker)

    response = world.client.post(
        "/api/v1/batch/scans",
        json={
            "scans": [
                scan_request("111111111111"),
                scan_request("222222222222"),
                scan_request("333333333333"),
            ]
        },
        headers=HEADERS,
    )

    assert response.status_code == 503, response.text
    (queued,), (refused,) = broker.taken, broker.refused
    # The first is with the workers: it is the team's, and will run.
    metadata = scan_store.load_metadata(world.redis, queued)
    assert metadata["status"] == "started" and metadata["account_id"] == "111111111111"
    assert world.redis.get(scan_store.credentials_key(queued))
    # The second was refused, the third never tried.
    assert world.redis.get(scan_store.metadata_key(refused)) is None
    assert world.redis.get(scan_store.credentials_key(refused)) is None
    after = _store(world)
    assert set(after["index"]) - set(before["index"]) == {queued}
    assert set(after["values"]) - set(before["values"]) == {
        scan_store.metadata_key(queued),
        scan_store.credentials_key(queued),
    }


def test_a_scan_whose_record_could_not_be_indexed_is_not_left_half_written(
    world, monkeypatch
):
    """The store fails between the metadata and the index: nothing was
    queued, and the metadata does not stay without its index entry."""
    before = _store(world)
    written = []

    def failing_zadd(key, mapping):
        written.extend(mapping)
        raise redis.exceptions.ConnectionError(MARKER)

    monkeypatch.setattr(world.redis, "zadd", failing_zadd)

    response = world.client.post("/api/v1/scans", json=scan_request(), headers=HEADERS)

    assert response.status_code == 503, response.text
    (scan_id,) = written
    assert len(world.queue.calls) == 4  # the world's own scans: nothing new
    assert world.redis.get(scan_store.metadata_key(scan_id)) is None
    assert world.redis.get(scan_store.credentials_key(scan_id)) is None
    assert _store(world) == before


def test_a_cleanup_that_fails_too_answers_the_first_error_and_says_so_in_the_log(
    world, monkeypatch, caplog
):
    """The broker and the store are the same Redis in the stack: when one
    stops answering, as a rule so does the other."""
    broker = Refusing(OperationalError(MARKER))
    monkeypatch.setattr(main, "run_cspm_scan_task", broker)

    def failing_delete(*keys):
        raise redis.exceptions.TimeoutError("the store did not answer either")

    monkeypatch.setattr(world.redis, "delete", failing_delete)

    with caplog.at_level(logging.ERROR):
        response = world.client.post(
            "/api/v1/scans", json=scan_request(), headers=HEADERS
        )

    assert response.status_code == 503, response.text
    assert response.json()["error"]["message"] == main.DEPENDENCY_UNAVAILABLE_MESSAGE
    (scan_id,) = broker.refused
    assert (
        f"Scan {scan_id} could not be queued, and its record could not be removed"
        in (caplog.text)
    )
    # The broker's error is the one logged as the cause of the 503.
    assert MARKER in caplog.text


def test_a_store_that_fails_at_the_first_write_is_not_asked_to_clean_up(
    world, monkeypatch
):
    """Nothing was written, and a Redis that does not answer would hold the
    removal as long as it held the write: measured on a paused Redis, six
    seconds for the 503 instead of three."""
    before = _store(world)
    asked = []

    def failing_setex(key, seconds, value):
        asked.append(("setex", key))
        raise redis.exceptions.TimeoutError(MARKER)

    monkeypatch.setattr(world.redis, "setex", failing_setex)
    monkeypatch.setattr(world.redis, "delete", lambda *keys: asked.append(("delete",)))
    monkeypatch.setattr(world.redis, "zrem", lambda *args: asked.append(("zrem",)))

    response = world.client.post("/api/v1/scans", json=scan_request(), headers=HEADERS)

    assert response.status_code == 503, response.text
    assert [command for command, *_ in asked] == ["setex"]
    assert asked[0][1].endswith(":creds")
    assert len(world.queue.calls) == 4
    assert _store(world) == before


def test_a_scan_that_is_queued_is_recorded_as_before(world):
    response = world.client.post(
        "/api/v1/scans", json=scan_request("888888888888"), headers=HEADERS
    )

    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]
    assert world.queue.config_of(scan_id)["credential_ref"] == (
        scan_store.credentials_key(scan_id)
    )
    assert scan_store.load_metadata(world.redis, scan_id)["status"] == "started"
    assert world.redis.get(scan_store.credentials_key(scan_id))
    assert world.redis.ttl(scan_store.credentials_key(scan_id)) == 300
    assert world.redis.zscore(scan_store.team_index_key(TEAM), scan_id) is not None


def test_forgetting_a_scan_removes_its_three_records_and_no_other(world):
    before = _store(world)
    scan_id = world.scans.queued
    other = world.scans.running

    scan_store.forget_scan(world.redis, scan_id, TEAM)

    after = _store(world)
    assert set(before["values"]) - set(after["values"]) == {
        scan_store.metadata_key(scan_id),
        scan_store.credentials_key(scan_id),
    }
    assert set(before["index"]) - set(after["index"]) == {scan_id}
    assert scan_store.load_metadata(world.redis, other)["status"] == "started"
    # Forgetting what is not there is not an error.
    scan_store.forget_scan(world.redis, scan_id, TEAM)
    assert _store(world) == after
