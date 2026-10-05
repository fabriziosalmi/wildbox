"""A cancelled task never runs, and reads ``cancelled`` at once (#743).

``DELETE /api/tasks/{id}`` asked Celery to revoke the task and answered
"Task cancellation requested". A revocation is a broadcast that the workers
running at that moment keep in memory. For a pending task with no worker
alive, or with one that restarts before it takes the task, nobody held it:
the task ran when a worker came back, and until then its owner read
``pending``.

The owner's cancellation is now a record in Redis, written before the
broadcast. The task reads it first when it starts and does not run, and the
API reads it to answer. ``test_async_task_lifecycle_worker.py`` shows the
defect and the fix with a real worker that starts after the cancellation;
this file covers the routes and the task with stand-ins.
"""

import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app import async_metrics, tasks  # noqa: E402
from app.task_ownership import OWNER_TTL_SECONDS  # noqa: E402

ALICE = str(uuid.uuid4())
BOB = str(uuid.uuid4())
TEAM = str(uuid.uuid4())
TOOL = "hash_generator"
INPUT = {"input_text": "wildbox"}
MARKER = "wildbox:tools:task-cancelled:{}"


class Celery:
    """What Celery holds for each task, and what it was asked to revoke."""

    def __init__(self, ownership):
        self.ownership = ownership
        self.states = {}
        self.revoked = []
        self.recorded_when_revoked = []
        self.fail_revoke = False

    def apply_async(self, task_id=None, kwargs=None):
        self.states[task_id] = "PENDING"

    def result_for(self, task_id, app=None):
        celery = self

        class Result:
            def revoke(self, terminate=False):
                if celery.fail_revoke:
                    raise OSError("broker unreachable")
                # The record must be there before any worker hears of it.
                celery.recorded_when_revoked.append(
                    celery.ownership.is_cancelled(task_id)
                )
                celery.revoked.append((task_id, terminate))

        return Result()

    def get_task_meta(self, task_id):
        return {
            "status": self.states.get(task_id, "PENDING"),
            "result": (
                {"status": "completed", "result": {}}
                if self.states.get(task_id) == "SUCCESS"
                else None
            ),
            "date_done": None,
        }


@pytest.fixture
def celery(monkeypatch, task_ownership):
    from app.api import async_router

    fake = Celery(task_ownership)
    monkeypatch.setattr(
        async_router.execute_tool_async, "apply_async", fake.apply_async
    )
    monkeypatch.setattr(async_router, "AsyncResult", fake.result_for)
    monkeypatch.setattr(async_router, "celery_app", SimpleNamespace(backend=fake))
    return fake


@pytest.fixture
def api(celery):
    from app.api import async_router
    from app.auth import verify_api_key
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    app = FastAPI()
    app.include_router(async_router.router)
    client = TestClient(app, raise_server_exceptions=False)

    def as_user(user_id):
        client.caller = GatewayUser(
            user_id=user_id, team_id=TEAM, role="member", auth_type="session"
        )

    client.as_user = as_user
    as_user(ALICE)
    app.dependency_overrides[verify_api_key] = lambda: client.caller
    return client


def submit(api):
    response = api.post(f"/api/tools/{TOOL}/async", json=INPUT)
    assert response.status_code == 202, response.text
    return response.json()["task_id"]


# --- the routes ---------------------------------------------------------------


def test_a_cancellation_is_recorded_before_the_workers_are_told(
    api, celery, fake_redis
):
    task_id = submit(api)

    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "cancelled"
    assert fake_redis.kv[MARKER.format(task_id)] == "1"
    # For as long as the task can wait in the queue and be read.
    assert fake_redis.ttl[MARKER.format(task_id)] == OWNER_TTL_SECONDS
    assert celery.revoked == [(task_id, True)]
    assert celery.recorded_when_revoked == [True]


def test_a_cancelled_task_reads_cancelled_while_celery_still_says_pending(api, celery):
    """No worker has dropped it yet: the result backend knows nothing."""
    task_id = submit(api)
    assert api.get(f"/api/tasks/{task_id}").json()["status"] == "pending"

    api.delete(f"/api/tasks/{task_id}")

    assert celery.states[task_id] == "PENDING"
    body = api.get(f"/api/tasks/{task_id}").json()
    assert body["state"] == "REVOKED"
    assert body["status"] == "cancelled"
    assert body["message"] == "Task was cancelled"
    (listed,) = api.get("/api/tasks").json()["tasks"]
    assert (listed["task_id"], listed["state"], listed["status"]) == (
        task_id,
        "REVOKED",
        "cancelled",
    )


@pytest.mark.parametrize("state", ["STARTED", "RUNNING", "RETRY"])
def test_a_task_cancelled_while_it_runs_reads_cancelled_too(api, celery, state):
    task_id = submit(api)
    celery.states[task_id] = state

    assert api.delete(f"/api/tasks/{task_id}").status_code == 200

    assert api.get(f"/api/tasks/{task_id}").json()["status"] == "cancelled"


def test_a_task_that_finished_before_it_could_be_stopped_reads_as_it_finished(
    api, celery
):
    task_id = submit(api)
    celery.states[task_id] = "RUNNING"
    api.delete(f"/api/tasks/{task_id}")

    # The run ended on its own before the worker stopped it.
    celery.states[task_id] = "SUCCESS"

    assert api.get(f"/api/tasks/{task_id}").json()["status"] == "completed"
    assert api.get("/api/tasks").json()["tasks"][0]["status"] == "completed"


def test_a_task_cannot_be_cancelled_twice(api, celery):
    task_id = submit(api)
    api.delete(f"/api/tasks/{task_id}")

    again = api.delete(f"/api/tasks/{task_id}")

    assert again.status_code == 400, again.text
    assert again.json()["detail"] == (
        "Task cannot be cancelled (current state: REVOKED)"
    )
    assert celery.revoked == [(task_id, True)]


def test_a_finished_task_is_not_marked_cancelled(api, celery, fake_redis):
    task_id = submit(api)
    celery.states[task_id] = "SUCCESS"

    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 400
    assert MARKER.format(task_id) not in fake_redis.kv
    assert celery.revoked == []


def test_only_the_owner_can_cancel(api, celery, fake_redis):
    task_id = submit(api)

    api.as_user(BOB)
    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 404
    assert MARKER.format(task_id) not in fake_redis.kv
    assert celery.revoked == []
    # And Bob does not learn of Alice's cancellation either.
    api.as_user(ALICE)
    api.delete(f"/api/tasks/{task_id}")
    api.as_user(BOB)
    assert api.get(f"/api/tasks/{task_id}").status_code == 404
    assert api.get("/api/tasks").json()["tasks"] == []


def test_a_cancellation_that_cannot_be_recorded_is_not_claimed(
    api, celery, fake_redis, monkeypatch
):
    task_id = submit(api)

    def unreachable(*args, **kwargs):
        raise RedisConnectionError("Error 111 connecting to wildbox-redis:6379")

    monkeypatch.setattr(fake_redis, "set", unreachable)

    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 503, response.text
    assert "wildbox-redis" not in response.text
    # Without the record the broadcast alone would be the old promise.
    assert celery.revoked == []


def test_when_the_workers_cannot_be_told_the_record_is_taken_back(
    api, celery, fake_redis
):
    task_id = submit(api)
    celery.fail_revoke = True

    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 503, response.text
    assert MARKER.format(task_id) not in fake_redis.kv
    # The caller can try again.
    celery.fail_revoke = False
    assert api.delete(f"/api/tasks/{task_id}").status_code == 200


def test_reading_fails_closed_when_the_record_cannot_be_read(
    api, celery, fake_redis, monkeypatch
):
    task_id = submit(api)
    api.delete(f"/api/tasks/{task_id}")
    owner_key = f"wildbox:tools:task-owner:{task_id}"
    stored = dict(fake_redis.kv)

    def marker_unreadable(key):
        if key == MARKER.format(task_id):
            raise RedisConnectionError("connection reset")
        return stored.get(key)

    monkeypatch.setattr(fake_redis, "get", marker_unreadable)

    assert owner_key in stored
    # Not "pending": the service does not know, and says so.
    assert api.get(f"/api/tasks/{task_id}").status_code == 503


# --- the task -----------------------------------------------------------------------


@pytest.fixture
def worker(monkeypatch, task_ownership):
    """The task as a worker runs it, and what it did instead of running."""
    seen = SimpleNamespace(revoked=[], outcomes=[], tools=[])

    def mark_as_revoked(task_id, reason="", request=None, **kwargs):
        seen.revoked.append((task_id, reason))

    def check(tool_name, input_data, load=None):
        seen.tools.append(tool_name)
        raise AssertionError("a cancelled task reached the checks before its run")

    monkeypatch.setattr(
        tasks.execute_tool_async.backend, "mark_as_revoked", mark_as_revoked
    )
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kw: None)
    monkeypatch.setattr(
        async_metrics,
        "record_outcome",
        lambda task_id, tool, outcome, **kw: seen.outcomes.append(
            (task_id, tool, outcome)
        ),
    )
    monkeypatch.setattr(async_metrics, "record_taken", lambda task_id: None)
    seen.check = check
    seen.ownership = task_ownership
    return seen


def run(task_id):
    """Run the task in this process through Celery's tracer, as a worker does."""
    return tasks.execute_tool_async.apply(
        kwargs={"tool_name": TOOL, "input_data": INPUT, "user_id": ALICE},
        task_id=task_id,
    )


def test_a_cancelled_task_does_not_run(worker, monkeypatch):
    monkeypatch.setattr(tasks, "check_tool_request", worker.check)
    worker.ownership.cancel("task-1")

    result = run("task-1")

    assert worker.tools == []
    assert worker.revoked == [("task-1", "cancelled by its owner")]
    assert worker.outcomes == [("task-1", TOOL, "cancelled")]
    # Not a result, not a failure, nothing to retry.
    assert result.state == "IGNORED"


def test_a_task_nobody_cancelled_runs(worker):
    worker.ownership.cancel("another-task")

    result = run("task-2")

    assert result.state == "SUCCESS"
    assert result.result["status"] == "completed"
    assert worker.revoked == []


def test_the_task_does_not_run_unasked_when_the_record_cannot_be_read(
    worker, fake_redis, monkeypatch
):
    """Fail closed: a task whose cancellation cannot be checked is retried."""
    monkeypatch.setattr(tasks, "check_tool_request", worker.check)

    def unreachable(key):
        raise RedisConnectionError("connection reset")

    monkeypatch.setattr(fake_redis, "get", unreachable)

    with pytest.raises(RedisConnectionError):
        tasks._cancelled_by_its_owner("task-3")
    result = run("task-3")

    assert worker.tools == []
    assert result.state != "SUCCESS"


def test_without_redis_there_is_no_record_to_ask_for(monkeypatch):
    from app import task_ownership
    from app.config import settings

    monkeypatch.setattr(task_ownership, "_ownership", None)
    monkeypatch.setattr(settings, "redis_url", None)

    assert tasks._cancelled_by_its_owner("task-4") is False
    assert tasks._cancelled_by_its_owner(None) is False
