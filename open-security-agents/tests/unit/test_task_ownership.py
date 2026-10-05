"""Reading and cancelling a task fail closed on its owner record (#650).

``DELETE /v1/analyze/{task_id}`` read ``if task_owner and ...``: with the
owner record missing the comparison was skipped and any authenticated caller,
of any team, could revoke the task. The celery id, which is all the handler
needs to revoke, was written after the owner record with the same TTL, so it
outlived it. GET had been fixed for the same defect (WILDBO-ERR-05); both now
go through one helper.
"""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

SECRET = "gateway-secret-for-tests"
OWNER = {
    "user_id": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "team_id": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "role": "member",
}
# Another user in another team: the tenant boundary the defect crossed.
OTHER = {
    "user_id": "0b3f0e4c-8d1a-4c2e-9f5b-1a2b3c4d5e6f",
    "team_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "role": "admin",
}
TASK_ID = "11111111-2222-4333-8444-555555555555"
CELERY_ID = "celery-task-1"


class FakeRedis:
    """The subset of redis-py the endpoints call, with each key's TTL."""

    def __init__(self):
        self.store = {}
        self.ttl = {}

    def get(self, key):
        value = self.store.get(key)
        if value is None:
            return None
        return value if isinstance(value, bytes) else str(value).encode()

    def setex(self, key, ttl, value):
        self.store[key] = value
        self.ttl[key] = ttl

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)
            self.ttl.pop(key, None)

    def pipeline(self):
        return self

    def execute(self):
        return []


class PendingResult:
    def __init__(self, task_id, app=None):
        self.id = task_id
        self.state = "PENDING"
        self.info = None
        self.result = None
        self.date_done = None


@pytest.fixture
def api(monkeypatch):
    """The app with Redis, Celery and the rate limit replaced."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    redis = FakeRedis()
    monkeypatch.setattr(main, "redis_client", redis)
    monkeypatch.setattr(main.limiter, "enabled", False)

    revoked = []
    control = SimpleNamespace(
        revoke=lambda task_id, terminate=False: revoked.append(task_id)
    )
    monkeypatch.setattr(main, "celery_app", SimpleNamespace(control=control))
    monkeypatch.setattr(main, "AsyncResult", PendingResult)

    def delay(**kwargs):
        return SimpleNamespace(id=CELERY_ID)

    monkeypatch.setattr(main.run_threat_enrichment_task, "delay", delay)
    return TestClient(main.app), redis, revoked


def headers(caller):
    return {
        "X-Wildbox-User-ID": caller["user_id"],
        "X-Wildbox-Team-ID": caller["team_id"],
        "X-Wildbox-Role": caller["role"],
        "X-Gateway-Secret": SECRET,
    }


def store_task(redis, owner=OWNER["user_id"]):
    redis.setex(f"task:{TASK_ID}:celery_id", 3600, CELERY_ID)
    redis.setex(
        f"task:{TASK_ID}:metadata",
        3600,
        '{"created_at": "2026-10-03T10:00:00+00:00"}',
    )
    if owner is not None:
        redis.setex(f"task:{TASK_ID}:user_id", 3600, owner)


def call(client, method, caller):
    return client.request(method, f"/v1/analyze/{TASK_ID}", headers=headers(caller))


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_a_task_without_an_owner_record_is_not_found(api, method):
    client, redis, revoked = api
    store_task(redis, owner=None)

    response = call(client, method, OWNER)

    assert response.status_code == 404, response.text
    assert revoked == []


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_another_users_task_is_not_found(api, method):
    client, redis, revoked = api
    store_task(redis)

    response = call(client, method, OTHER)

    assert response.status_code == 404, response.text
    assert revoked == []


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_another_users_task_answers_like_a_missing_one(api, method):
    """The answer does not tell a caller that someone else's task id is live."""
    client, redis, _ = api
    store_task(redis)
    foreign = call(client, method, OTHER)

    redis.delete(f"task:{TASK_ID}:celery_id")
    missing = call(client, method, OTHER)

    assert foreign.status_code == missing.status_code == 404
    assert foreign.json().get("detail") == missing.json().get("detail")


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_an_unknown_task_is_not_found(api, method):
    client, _, revoked = api

    response = call(client, method, OWNER)

    assert response.status_code == 404, response.text
    assert revoked == []


def test_the_owner_cancels_their_task(api):
    client, redis, revoked = api
    store_task(redis)

    response = call(client, "DELETE", OWNER)

    assert response.status_code == 200, response.text
    assert revoked == [CELERY_ID]


def test_the_owner_reads_their_task(api):
    client, redis, _ = api
    store_task(redis)

    response = call(client, "GET", OWNER)

    assert response.status_code == 200, response.text
    assert response.json()["task_id"] == TASK_ID
    assert response.json()["status"] == "pending"


def test_the_owner_record_outlives_every_key_that_addresses_the_task(api):
    client, redis, _ = api

    response = client.post(
        "/v1/analyze",
        json={"ioc": {"type": "domain", "value": "example.com"}},
        headers=headers(OWNER),
    )
    assert response.status_code == 202, response.text
    task_id = response.json()["task_id"]

    owner_ttl = redis.ttl[f"task:{task_id}:user_id"]
    assert redis.store[f"task:{task_id}:user_id"] == OWNER["user_id"]
    assert owner_ttl > redis.ttl[f"task:{task_id}:celery_id"]
    assert owner_ttl > redis.ttl[f"task:{task_id}:metadata"]
