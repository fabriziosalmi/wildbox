"""DELETE /api/v1/scans/{id} cancels a scan in progress, and only that (#766).

The route revoked the task and wrote ``cancelled`` whatever the scan's
state. A scan that had completed then read ``cancelled``, with no
completion time, while its report still read ``completed`` and kept
counting in the team's summaries; a failed scan lost its failure the same
way; and a task long finished was revoked on every worker.

A scan that is queued or running is cancelled. One that already has a final
status answers 409 and is left exactly as it is.
"""

import logging
import threading

import pytest
from app import scan_store, worker
from route_probes import HEADERS, NO_SUCH_SCAN, OTHER_TEAM_HEADERS, run_worker


def _stored(world, scan_id):
    return world.redis.get(scan_store.metadata_key(scan_id))


def _status(world, scan_id):
    response = world.client.get(f"/api/v1/scans/{scan_id}", headers=HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def _cancel(world, scan_id, headers=HEADERS):
    return world.client.delete(f"/api/v1/scans/{scan_id}", headers=headers)


@pytest.mark.parametrize("state", ["queued", "running"])
def test_a_scan_in_progress_is_cancelled(world, state):
    scan_id = getattr(world.scans, state)
    assert _status(world, scan_id)["status"] == state

    response = _cancel(world, scan_id)

    assert response.status_code == 200, response.text
    assert response.json() == {"message": "Scan cancelled successfully"}
    assert world.celery.control.revoked == [(scan_id, True)]
    assert _status(world, scan_id)["status"] == "cancelled"
    metadata = scan_store.load_metadata(world.redis, scan_id)
    assert metadata["status"] == "cancelled"
    assert metadata["cancelled_at"]


def test_a_completed_scan_is_not_cancelled(world):
    scan_id = world.scans.completed
    stored = _stored(world, scan_id)
    status = _status(world, scan_id)
    report = world.redis.get(scan_store.report_key(scan_id))
    summary = world.client.get("/api/v1/compliance/summary", headers=HEADERS).json()
    assert status["status"] == "completed" and status["completed_at"]

    response = _cancel(world, scan_id)

    assert response.status_code == 409, response.text
    error = response.json()["error"]
    assert error["code"] == 409
    assert error["message"] == "Scan is already completed and cannot be cancelled"
    # Its status, its times and its report, as they were.
    assert _stored(world, scan_id) == stored
    assert _status(world, scan_id) == status
    assert world.redis.get(scan_store.report_key(scan_id)) == report
    assert (
        world.client.get("/api/v1/compliance/summary", headers=HEADERS).json()
        == summary
    )
    # And a task that ended long ago is not revoked on the workers.
    assert world.celery.control.revoked == []


def test_a_failed_scan_is_not_cancelled(world):
    scan_id = world.scans.failed
    stored = _stored(world, scan_id)

    response = _cancel(world, scan_id)

    assert response.status_code == 409, response.text
    assert (
        response.json()["error"]["message"]
        == "Scan is already failed and cannot be cancelled"
    )
    assert _stored(world, scan_id) == stored
    assert _status(world, scan_id)["status"] == "failed"
    assert world.celery.control.revoked == []


def test_a_cancelled_scan_is_not_cancelled_again(world):
    scan_id = world.scans.running
    assert _cancel(world, scan_id).status_code == 200
    stored = _stored(world, scan_id)

    response = _cancel(world, scan_id)

    assert response.status_code == 409, response.text
    assert (
        response.json()["error"]["message"]
        == "Scan is already cancelled and cannot be cancelled"
    )
    # The time of the cancellation is the first one's.
    assert _stored(world, scan_id) == stored
    assert world.celery.control.revoked == [(scan_id, True)]


def test_a_scan_that_completes_while_it_is_being_cancelled_stays_completed(world):
    """The worker stores the report between the route's look at the scan and
    its write: the write must not put what it read earlier over it."""
    scan_id = world.scans.queued

    def revoke_too_late(task_id, terminate=False):
        # The worker is another process; here, another thread, which has
        # finished the scan by the time the revocation returns.
        finishing = threading.Thread(target=run_worker, args=(world.queue, task_id))
        finishing.start()
        finishing.join()

    world.celery.control.revoke = revoke_too_late

    response = _cancel(world, scan_id)

    assert response.status_code == 409, response.text
    assert (
        response.json()["error"]["message"]
        == "Scan finished before it could be cancelled"
    )
    status = _status(world, scan_id)
    assert status["status"] == "completed" and status["completed_at"]
    assert "cancelled_at" not in scan_store.load_metadata(world.redis, scan_id)
    assert scan_store.load_report(world.redis, scan_id) is not None


# --- A cancelled scan is not run ---------------------------------------------------
# Found on real containers: a scan cancelled while no worker was up was run
# when one came up. Celery keeps a revocation in the memory of the workers
# that received it; the queued task was delivered all the same, DELETE having
# answered "Scan cancelled successfully".


@pytest.fixture
def sessions(monkeypatch):
    """Every cloud session the worker opens: one per scan it really runs."""
    opened = []

    def create_session(provider, credentials):
        opened.append(provider)
        return object()

    monkeypatch.setattr(worker, "_create_cloud_session", create_session)
    return opened


def test_a_scan_cancelled_before_a_worker_took_it_is_never_run(world, sessions):
    scan_id = world.scans.queued
    credentials = scan_store.credentials_key(scan_id)
    assert world.redis.get(credentials)

    assert _cancel(world, scan_id).status_code == 200
    # Its credentials do not wait five more minutes for a worker.
    assert world.redis.get(credentials) is None
    stored = _stored(world, scan_id)

    # The revocation reached no worker; one takes the task later.
    result = run_worker(world.queue, scan_id)

    assert sessions == []
    assert result.state == "SUCCESS"
    assert result.result == {"scan_id": scan_id, "status": "cancelled"}
    assert _stored(world, scan_id) == stored
    assert _status(world, scan_id)["status"] == "cancelled"
    assert scan_store.load_report(world.redis, scan_id) is None


def test_the_worker_reads_the_cancellation_from_the_store(world, sessions, caplog):
    """Whatever recorded it: here the store alone, with the credentials still
    waiting, as when the API stops between its two writes."""
    scan_id = world.scans.queued
    credentials = scan_store.credentials_key(scan_id)
    assert scan_store.cancel_scan(world.redis, scan_id, "2026-10-06T12:00:00")
    assert world.redis.get(credentials)

    with caplog.at_level(logging.ERROR):
        result = run_worker(world.queue, scan_id)

    assert sessions == []
    assert result.result == {"scan_id": scan_id, "status": "cancelled"}
    assert world.redis.get(credentials) is None
    assert _status(world, scan_id)["status"] == "cancelled"
    # Not a failure: nothing for the operator to look into.
    assert caplog.records == []


def test_a_scan_that_was_not_cancelled_is_run(world, sessions):
    scan_id = world.scans.queued

    result = run_worker(world.queue, scan_id)

    assert len(sessions) == 1
    assert result.result["status"] == "completed"
    assert _status(world, scan_id)["status"] == "completed"


@pytest.mark.parametrize("state", ["queued", "running", "completed", "failed"])
def test_another_team_cannot_cancel_nor_learn_the_state(world, state):
    scan_id = getattr(world.scans, state)
    stored = _stored(world, scan_id)

    response = _cancel(world, scan_id, headers=OTHER_TEAM_HEADERS)

    # 403 whatever the state: a 409 would tell the other team it finished.
    assert response.status_code == 403, response.text
    assert response.json()["error"]["message"] == "Access denied"
    assert _stored(world, scan_id) == stored
    assert world.celery.control.revoked == []


def test_a_scan_that_does_not_exist_is_a_404(world):
    response = _cancel(world, NO_SUCH_SCAN)

    assert response.status_code == 404, response.text
    assert world.celery.control.revoked == []


# --- scan_store.cancel_scan -------------------------------------------------------


def test_the_store_cancels_only_what_is_in_progress(world):
    at = "2026-10-06T12:00:00"

    assert scan_store.cancel_scan(world.redis, world.scans.queued, at) is True
    for state in ("completed", "failed"):
        scan_id = getattr(world.scans, state)
        stored = _stored(world, scan_id)
        assert scan_store.cancel_scan(world.redis, scan_id, at) is False
        assert _stored(world, scan_id) == stored
    assert scan_store.cancel_scan(world.redis, world.scans.queued, "later") is False
    assert (
        scan_store.load_metadata(world.redis, world.scans.queued)["cancelled_at"] == at
    )
    assert scan_store.cancel_scan(world.redis, NO_SUCH_SCAN, at) is False
    assert world.redis.get(scan_store.metadata_key(NO_SUCH_SCAN)) is None


def test_a_cancelled_scan_keeps_its_place_in_the_teams_index(world):
    """Cancelling writes through save_metadata: the scan is still the team's,
    and still counted, with the retention of every other record."""
    scan_id = world.scans.queued
    before = world.client.get("/api/v1/dashboard/summary", headers=HEADERS).json()

    assert _cancel(world, scan_id).status_code == 200

    after = world.client.get("/api/v1/dashboard/summary", headers=HEADERS).json()
    assert after["total_scans"] == before["total_scans"] == 4
    assert world.redis.ttl(scan_store.metadata_key(scan_id)) > 0
