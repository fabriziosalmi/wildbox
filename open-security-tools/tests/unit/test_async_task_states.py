"""Every Celery state of an async task reads back as a defined answer (#619).

Reading a task right after cancelling it answered 500 now and then: the router
read ``AsyncResult.state`` and then ``AsyncResult.info``, two reads of the
result backend for a task that has not finished, and the worker marked the
task REVOKED in between. ``info`` then held a TaskRevokedError, which the
response could not serialize.

These tests store real results in an in-memory Celery result backend, so the
router decodes them as it does in production, in each terminal state, and
with the state changing while a request is being answered.
"""

import logging
import os
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

pytest.importorskip("celery")

from celery import Celery  # noqa: E402
from celery.exceptions import Retry  # noqa: E402
from celery.result import AsyncResult  # noqa: E402

ALICE = str(uuid.uuid4())
TEAM = str(uuid.uuid4())
TOOL = "hash_generator"
# Text that must never reach a client: what a failure's message can carry.
INTERNAL = "/srv/app/secret-path at 10.0.0.7"


@pytest.fixture
def results(monkeypatch):
    """A Celery result backend in memory, the one the router reads."""
    from app.api import async_router

    app = Celery("test-async-task-states", backend="cache+memory://")
    monkeypatch.setattr(async_router, "celery_app", app)
    return app.backend


@pytest.fixture
def revoked(monkeypatch):
    """The task ids the router asked Celery to revoke, and how."""
    from app.api import async_router

    calls = []

    class RecordingResult(AsyncResult):
        def revoke(self, terminate=False, **kwargs):
            calls.append((self.id, terminate))

    monkeypatch.setattr(async_router, "AsyncResult", RecordingResult)
    return calls


@pytest.fixture
def api(task_ownership, results, revoked):
    from app.api import async_router
    from app.auth import verify_api_key
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    app = FastAPI()
    app.include_router(async_router.router)
    caller = GatewayUser(user_id=ALICE, team_id=TEAM, role="member")
    app.dependency_overrides[verify_api_key] = lambda: caller
    # raise_server_exceptions=False: a 500 is an answer to assert on, not an
    # exception that ends the test before it can say which state caused it.
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def task_id(task_ownership):
    """A task Alice submitted."""
    task_id = str(uuid.uuid4())
    task_ownership.record(task_id, user_id=ALICE, team_id=TEAM, tool_name=TOOL)
    return task_id


def read(api, task_id):
    response = api.get(f"/api/tasks/{task_id}")
    assert response.status_code == 200, response.text
    return response.json()


def patch_backend(monkeypatch, backend, name, replacement):
    """Replace a method of the result backend for the request as well.

    Celery keeps a backend that is not thread-safe per thread, and the test
    client answers in a worker thread, so the request reads through another
    instance of the same class (over the same in-memory store).
    """
    monkeypatch.setattr(type(backend), name, replacement)


def raises(exception):
    """A real exception, with the traceback a worker would store."""
    try:
        raise exception
    except type(exception) as e:
        return e


# --- one state at a time ----------------------------------------------------------


@pytest.mark.parametrize("reason", ["terminated", "revoked", "expired"])
def test_a_revoked_task_reads_as_cancelled(api, results, task_id, reason):
    results.mark_as_revoked(task_id, reason)

    body = read(api, task_id)

    assert body["state"] == "REVOKED"
    assert body["status"] == "cancelled"
    assert body["completed_at"]


def test_a_failure_carries_the_exception_class_only(api, results, task_id):
    results.mark_as_failure(task_id, raises(RuntimeError(INTERNAL)))

    response = api.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "FAILURE"
    assert body["status"] == "failed"
    assert body["error"] == "Task execution failed (RuntimeError)"
    assert INTERNAL not in response.text


def test_a_failure_stored_with_a_custom_meta_reads_as_failed(api, results, task_id):
    """``update_state(state=FAILURE, meta={...})`` stores a dict Celery cannot
    turn back into an exception: ``AsyncResult.state`` itself raises (#624)."""
    results.store_result(task_id, {"error": INTERNAL}, "FAILURE")
    with pytest.raises(ValueError, match="exception type"):
        AsyncResult(task_id, app=results.app).state

    response = api.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "FAILURE"
    assert body["status"] == "failed"
    assert body["error"] == "Task execution failed"
    assert INTERNAL not in response.text


def test_a_custom_failure_meta_names_its_exception_class_when_it_has_one(
    api, results, task_id
):
    results.store_result(
        task_id, {"exc_type": "ToolCrashed", "exc_message": INTERNAL}, "FAILURE"
    )

    body = read(api, task_id)

    assert body["error"] == "Task execution failed (ToolCrashed)"


def test_a_successful_task_reads_its_result(api, results, task_id):
    results.store_result(
        task_id,
        {"status": "completed", "result": {"ok": True}, "duration": 0.5},
        "SUCCESS",
    )

    body = read(api, task_id)

    assert body["state"] == "SUCCESS"
    assert body["status"] == "completed"
    assert body["result"] == {"ok": True}
    assert body["completed_at"]


def test_a_task_the_backend_has_not_seen_is_pending(api, task_id):
    body = read(api, task_id)

    assert body["state"] == "PENDING"
    assert body["status"] == "pending"


def test_a_running_task_shows_its_progress_and_not_the_worker(api, results, task_id):
    results.store_result(
        task_id, {"pid": 4242, "hostname": "celery@worker-7"}, "STARTED"
    )
    assert "info" not in read(api, task_id)

    results.store_result(
        task_id,
        {"tool_name": TOOL, "started_at": 1.5, "status": "executing"},
        "RUNNING",
    )
    body = read(api, task_id)

    assert body["status"] == "running"
    assert body["info"] == {"tool_name": TOOL, "started_at": 1.5, "status": "executing"}


def test_a_retried_task_names_the_exception_class_only(api, results, task_id):
    results.mark_as_retry(task_id, raises(Retry(INTERNAL)))

    response = api.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "retrying"
    assert response.json()["info"] == "Task execution failed (Retry)"
    assert INTERNAL not in response.text


def test_a_custom_state_reads_as_unknown(api, results, task_id):
    results.store_result(task_id, {"step": 3}, "PROGRESS")

    body = read(api, task_id)

    assert body["state"] == "PROGRESS"
    assert body["status"] == "unknown"


def test_an_undecodable_record_reads_as_unknown(api, results, task_id):
    results.set(results.get_key_for_task(task_id), b"\x00 not a result")

    body = read(api, task_id)

    assert body["state"] == "UNKNOWN"
    assert body["status"] == "unknown"


# --- the state changes while the request is answered -----------------------------


def test_a_task_revoked_between_two_backend_reads_is_still_answered(
    api, results, task_id, monkeypatch
):
    """The race of #619, made deterministic: the worker writes REVOKED right
    after the first read of the result backend."""
    results.store_result(task_id, {"tool_name": TOOL, "status": "executing"}, "RUNNING")
    read_meta = type(results).get_task_meta
    reads = []

    def worker_revokes_after_each_read(backend, tid, *args, **kwargs):
        meta = read_meta(backend, tid, *args, **kwargs)
        reads.append(meta["status"])
        backend.mark_as_revoked(tid, "terminated")
        return meta

    patch_backend(monkeypatch, results, "get_task_meta", worker_revokes_after_each_read)

    body = read(api, task_id)

    # Answered from the one read: running then, cancelled on the next read.
    assert reads == ["RUNNING"]
    assert body["status"] == "running"
    assert read(api, task_id)["status"] == "cancelled"


@pytest.mark.parametrize(
    "finish",
    [
        lambda backend, tid: backend.mark_as_revoked(tid, "terminated"),
        lambda backend, tid: backend.mark_as_failure(tid, raises(KeyError(INTERNAL))),
        lambda backend, tid: backend.store_result(tid, {"error": INTERNAL}, "FAILURE"),
        lambda backend, tid: backend.store_result(
            tid, {"status": "completed"}, "SUCCESS"
        ),
    ],
    ids=["revoked", "failure", "failure-custom-meta", "success"],
)
def test_a_task_that_finishes_after_the_owner_check_is_still_answered(
    api, results, task_id, task_ownership, monkeypatch, finish
):
    results.store_result(task_id, {"tool_name": TOOL, "status": "executing"}, "RUNNING")
    owned_by = task_ownership.owned_by

    def owner_check_then_the_worker_finishes(tid, user_id):
        owner = owned_by(tid, user_id)
        finish(results, tid)
        return owner

    monkeypatch.setattr(
        task_ownership, "owned_by", owner_check_then_the_worker_finishes
    )

    response = api.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    assert response.json()["status"] in {"cancelled", "failed", "completed"}
    assert INTERNAL not in response.text


# --- cancelling and listing -------------------------------------------------------


def test_cancelling_a_running_task_terminates_it(api, results, task_id, revoked):
    results.store_result(task_id, {"tool_name": TOOL}, "RUNNING")

    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    assert revoked == [(task_id, True)]


@pytest.mark.parametrize(
    "finish",
    [
        lambda backend, tid: backend.mark_as_revoked(tid, "terminated"),
        lambda backend, tid: backend.store_result(tid, {"error": INTERNAL}, "FAILURE"),
    ],
    ids=["revoked", "failure-custom-meta"],
)
def test_a_finished_task_cannot_be_cancelled_in_any_state(
    api, results, task_id, revoked, finish
):
    finish(results, task_id)

    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 400, response.text
    assert revoked == []


def test_the_list_answers_for_tasks_in_every_state(api, results, task_ownership):
    states = {
        "revoked": lambda tid: results.mark_as_revoked(tid, "terminated"),
        "failure": lambda tid: results.mark_as_failure(tid, raises(ValueError("x"))),
        "custom": lambda tid: results.store_result(tid, {"error": "x"}, "FAILURE"),
        "success": lambda tid: results.store_result(
            tid, {"status": "refused"}, "SUCCESS"
        ),
        "pending": lambda tid: None,
    }
    expected = {}
    for name, finish in states.items():
        tid = str(uuid.uuid4())
        task_ownership.record(tid, ALICE, TEAM, TOOL)
        finish(tid)
        expected[tid] = name

    response = api.get("/api/tasks")

    assert response.status_code == 200, response.text
    statuses = {t["task_id"]: t["status"] for t in response.json()["tasks"]}
    assert {expected[tid]: status for tid, status in statuses.items()} == {
        "revoked": "cancelled",
        "failure": "failed",
        "custom": "failed",
        "success": "refused",
        "pending": "pending",
    }


def test_an_unreachable_result_backend_answers_503(api, results, task_id, monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    def unreachable(*args, **kwargs):
        raise RedisConnectionError("connection refused")

    patch_backend(monkeypatch, results, "get_task_meta", unreachable)

    assert api.get(f"/api/tasks/{task_id}").status_code == 503
    assert api.delete(f"/api/tasks/{task_id}").status_code == 503
    assert api.get("/api/tasks").status_code == 503


# --- what the logs show when a request fails -------------------------------------


def test_a_failed_request_logs_the_exception_class_and_traceback(caplog):
    """The 500 of #619 was logged as "HTTP request failed" and nothing more."""
    from app.middleware import RequestLoggingMiddleware
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.get("/boom")
    def boom():
        raise ValueError("unserializable")

    with caplog.at_level(logging.ERROR, logger="app.middleware"):
        response = TestClient(app).get("/boom")

    assert response.status_code == 500
    failed = [
        r for r in caplog.records if r.getMessage().startswith("HTTP request failed")
    ]
    assert failed[0].getMessage() == "HTTP request failed: ValueError"
    assert failed[0].exc_info is not None
