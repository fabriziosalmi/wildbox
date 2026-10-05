"""Async tasks belong to the user who submitted them (#567).

The task endpoints answered for any task id: Celery's result backend does not
know who submitted a task, and reports an id it has never seen as PENDING. The
owner is now recorded at submission, and a caller reads, cancels and lists only
their own tasks. Anything else is 404, the same answer as for an id that does
not exist.
"""

import json
import uuid
from types import SimpleNamespace

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

pytest.importorskip("celery")

from app import task_ownership as ownership_module  # noqa: E402
from app.task_ownership import OWNER_TTL_SECONDS, TaskOwnership  # noqa: E402

ALICE = str(uuid.uuid4())
BOB = str(uuid.uuid4())
TEAM = str(uuid.uuid4())
OTHER_TEAM = str(uuid.uuid4())
TOOL = "hash_generator"


class FakeResult:
    """What AsyncResult reports for one task id."""

    def __init__(self, state="PENDING", result=None):
        self.state = state
        self.result = result
        self.info = result
        self.date_done = None
        self.revoked = []

    def revoke(self, terminate=False):
        self.revoked.append(terminate)


@pytest.fixture
def backend(monkeypatch):
    """The Celery side: what was queued, and the result for each task id."""
    from app.api import async_router

    class Backend:
        queued = []
        results = {}
        fail_queueing = False

        def apply_async(self, task_id=None, kwargs=None):
            if self.fail_queueing:
                raise OSError("broker unreachable")
            self.queued.append({"task_id": task_id, "kwargs": kwargs})
            # Queued after the owner record exists: a worker can finish the
            # task at once, and its owner must be able to read it then.
            assert ownership_module._ownership.owned_by(task_id, kwargs["user_id"])
            return None

        def result_for(self, task_id, app=None):
            return self.results.setdefault(task_id, FakeResult())

    fake = Backend()
    fake.queued = []
    fake.results = {}
    monkeypatch.setattr(
        async_router.execute_tool_async, "apply_async", fake.apply_async
    )
    monkeypatch.setattr(async_router, "AsyncResult", fake.result_for)

    # The router reads a task's meta from the result backend in one call; it
    # answers from the same FakeResult (test_async_task_states.py exercises a
    # real Celery backend).
    class ResultBackend:
        def get_task_meta(self, task_id):
            result = fake.results.get(task_id, FakeResult())
            return {
                "status": result.state,
                "result": result.result,
                "date_done": result.date_done,
            }

    monkeypatch.setattr(
        async_router, "celery_app", SimpleNamespace(backend=ResultBackend())
    )
    return fake


@pytest.fixture
def api(task_ownership, backend):
    """A client for the async router, calling as whoever ``api.caller`` names."""
    from app.api import async_router
    from app.auth import verify_api_key
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    app = FastAPI()
    app.include_router(async_router.router)
    client = TestClient(app)
    client.caller = GatewayUser(user_id=ALICE, team_id=TEAM, role="member", auth_type="session")
    app.dependency_overrides[verify_api_key] = lambda: client.caller
    return client


def as_user(api, user_id, team_id=TEAM, role="member"):
    from open_security_shared.gateway_auth import GatewayUser

    api.caller = GatewayUser(user_id=user_id, team_id=team_id, role=role, auth_type="session")


def submit(api, tool=TOOL):
    response = api.post(f"/api/tools/{tool}/async", json={"input_text": "wildbox"})
    assert response.status_code == 202, response.text
    return response.json()["task_id"]


# --- submission ---------------------------------------------------------------


def test_submission_records_the_owner_and_points_at_the_gateway_path(
    api, backend, task_ownership
):
    response = api.post(f"/api/tools/{TOOL}/async", json={"input_text": "wildbox"})

    assert response.status_code == 202, response.text
    body = response.json()
    task_id = body["task_id"]
    assert body["status_url"] == f"/api/v1/tasks/{task_id}"
    assert backend.queued == [
        {
            "task_id": task_id,
            "kwargs": {
                "tool_name": TOOL,
                "input_data": {"input_text": "wildbox"},
                "user_id": ALICE,
                "timeout": None,
            },
        }
    ]
    owner = task_ownership.owned_by(task_id, ALICE)
    assert owner["team_id"] == TEAM
    assert owner["tool_name"] == TOOL


def test_a_submission_that_cannot_be_queued_leaves_no_record(
    api, backend, task_ownership, fake_redis
):
    backend.fail_queueing = True

    response = api.post(f"/api/tools/{TOOL}/async", json={"input_text": "wildbox"})

    assert response.status_code == 503, response.text
    assert fake_redis.kv == {}
    assert task_ownership.list_for(ALICE, 50) == []


# --- reading --------------------------------------------------------------------


def test_the_owner_reads_the_result(api, backend):
    task_id = submit(api)
    backend.results[task_id] = FakeResult(
        "SUCCESS",
        {"status": "completed", "result": {"ok": True}, "tool_name": TOOL},
    )

    response = api.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["result"] == {"ok": True}
    assert body["tool_name"] == TOOL


def test_another_user_cannot_read_the_task(api, backend):
    task_id = submit(api)
    backend.results[task_id] = FakeResult(
        "SUCCESS", {"status": "completed", "result": {"secret": "alice's"}}
    )

    as_user(api, BOB)
    response = api.get(f"/api/tasks/{task_id}")

    assert response.status_code == 404, response.text
    assert "alice's" not in response.text
    # Indistinguishable from an id that does not exist.
    unknown = api.get(f"/api/tasks/{uuid.uuid4()}")
    assert unknown.status_code == 404
    assert unknown.json() == response.json()


@pytest.mark.parametrize(
    "team_id, role",
    [(TEAM, "member"), (TEAM, "owner"), (TEAM, "admin"), (OTHER_TEAM, "admin")],
)
def test_neither_a_teammate_nor_an_admin_reads_someone_elses_task(
    api, backend, team_id, role
):
    task_id = submit(api)

    as_user(api, BOB, team_id=team_id, role=role)

    assert api.get(f"/api/tasks/{task_id}").status_code == 404


def test_an_unknown_task_is_not_found_instead_of_pending(api):
    """AsyncResult reports any id it has never seen as PENDING."""
    response = api.get(f"/api/tasks/{uuid.uuid4()}")

    assert response.status_code == 404, response.text


def test_a_task_without_an_owner_record_is_not_readable(api, backend):
    """A task submitted before the upgrade has a result and no owner."""
    task_id = str(uuid.uuid4())
    backend.results[task_id] = FakeResult("SUCCESS", {"status": "completed"})

    assert api.get(f"/api/tasks/{task_id}").status_code == 404
    assert api.delete(f"/api/tasks/{task_id}").status_code == 404
    assert api.get("/api/tasks").json()["tasks"] == []


def test_a_corrupt_owner_record_is_not_readable(api, fake_redis):
    task_id = str(uuid.uuid4())
    fake_redis.kv[f"wildbox:tools:task-owner:{task_id}"] = "not json"

    assert api.get(f"/api/tasks/{task_id}").status_code == 404


# --- cancelling -----------------------------------------------------------------


def test_the_owner_cancels_a_pending_task(api, backend):
    task_id = submit(api)

    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "cancelled"
    assert backend.results[task_id].revoked == [True]


def test_another_user_cannot_cancel_the_task(api, backend):
    task_id = submit(api)

    as_user(api, BOB)
    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 404, response.text
    assert backend.results.get(task_id, FakeResult()).revoked == []


def test_a_finished_task_cannot_be_cancelled(api, backend):
    task_id = submit(api)
    backend.results[task_id] = FakeResult("SUCCESS", {"status": "completed"})

    response = api.delete(f"/api/tasks/{task_id}")

    assert response.status_code == 400, response.text
    assert backend.results[task_id].revoked == []


# --- listing --------------------------------------------------------------------


def test_the_list_holds_the_callers_tasks_only_newest_first(api, backend):
    first = submit(api)
    second = submit(api, tool="base64_tool")
    as_user(api, BOB)
    bobs = submit(api)
    backend.results[second] = FakeResult("SUCCESS", {"status": "refused"})

    as_user(api, ALICE)
    response = api.get("/api/tasks")

    assert response.status_code == 200, response.text
    body = response.json()
    assert [task["task_id"] for task in body["tasks"]] == [second, first]
    assert body["count"] == 2
    assert body["tasks"][0]["tool_name"] == "base64_tool"
    assert body["tasks"][0]["status"] == "refused"
    assert body["tasks"][1]["status"] == "pending"
    assert body["tasks"][1]["status_url"] == f"/api/v1/tasks/{first}"

    as_user(api, BOB)
    assert [t["task_id"] for t in api.get("/api/tasks").json()["tasks"]] == [bobs]


def test_the_list_respects_its_limit(api):
    for _ in range(3):
        submit(api)

    assert len(api.get("/api/tasks?limit=2").json()["tasks"]) == 2
    assert api.get("/api/tasks?limit=0").status_code == 422
    assert api.get("/api/tasks?limit=101").status_code == 422


# --- the owner records ----------------------------------------------------------


def test_an_owner_record_outlives_the_celery_result():
    from app.celery_app import celery_app

    assert OWNER_TTL_SECONDS > celery_app.conf.result_expires


def test_records_expire_and_leave_the_list(fake_redis):
    ownership = TaskOwnership(fake_redis)
    ownership.record("old", ALICE, TEAM, TOOL, now=1000.0)
    ownership.record("new", ALICE, TEAM, TOOL, now=1000.0 + OWNER_TTL_SECONDS)

    assert fake_redis.ttl["wildbox:tools:task-owner:old"] == OWNER_TTL_SECONDS
    assert fake_redis.ttl[f"wildbox:tools:user-tasks:{ALICE}"] == OWNER_TTL_SECONDS
    listed = ownership.list_for(ALICE, 50, now=1001.0 + OWNER_TTL_SECONDS)
    assert [owner["task_id"] for owner in listed] == ["new"]


def test_an_index_entry_without_its_record_is_dropped(fake_redis):
    ownership = TaskOwnership(fake_redis)
    ownership.record("kept", ALICE, TEAM, TOOL, now=1.0)
    ownership.record("expired", ALICE, TEAM, TOOL, now=2.0)
    ownership.record("bobs", BOB, TEAM, TOOL, now=3.0)
    del fake_redis.kv["wildbox:tools:task-owner:expired"]
    # An index entry that names a task someone else owns is not listed either.
    fake_redis.zsets[f"wildbox:tools:user-tasks:{ALICE}"]["bobs"] = 3.0

    listed = ownership.list_for(ALICE, 50, now=4.0)

    assert [owner["task_id"] for owner in listed] == ["kept"]
    assert set(fake_redis.zsets[f"wildbox:tools:user-tasks:{ALICE}"]) == {"kept"}
    assert json.loads(fake_redis.kv["wildbox:tools:task-owner:bobs"])["user_id"] == BOB


# --- when Redis is not there ------------------------------------------------------


def test_redis_errors_answer_503_not_a_task(api, monkeypatch, task_ownership):
    def unreachable(*args, **kwargs):
        raise RedisConnectionError("connection refused")

    monkeypatch.setattr(task_ownership, "owned_by", unreachable)
    monkeypatch.setattr(task_ownership, "list_for", unreachable)
    monkeypatch.setattr(task_ownership, "record", unreachable)

    assert api.get(f"/api/tasks/{uuid.uuid4()}").status_code == 503
    assert api.delete(f"/api/tasks/{uuid.uuid4()}").status_code == 503
    assert api.get("/api/tasks").status_code == 503
    response = api.post(f"/api/tools/{TOOL}/async", json={"input_text": "x"})
    assert response.status_code == 503


def test_without_redis_url_the_endpoints_answer_503(api, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(ownership_module, "_ownership", None)
    monkeypatch.setattr(settings, "redis_url", None)

    assert api.get(f"/api/tasks/{uuid.uuid4()}").status_code == 503
    response = api.post(f"/api/tools/{TOOL}/async", json={"input_text": "x"})
    assert response.status_code == 503
