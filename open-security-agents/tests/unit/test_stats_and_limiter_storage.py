"""Counters that outlived, or did not outlive, what they counted (#652).

- ``completed_today`` and ``failed_today`` of ``GET /stats`` were two Redis
  keys the worker incremented and nothing reset: they counted since the
  Redis data was last cleared. Each UTC day now has its own key, which
  expires.
- The analysis limiter counted in the API process's memory, so a restart
  gave every user a new budget. It counts in the service's Redis; when that
  cannot be reached the submission is refused with 503, not accepted
  uncounted.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from limits.errors import StorageError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import main, rate_limit, stats, worker  # noqa: E402
from app.config import Settings  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import ValidationError  # noqa: E402

SECRET = "gateway-secret-for-tests"
CALLER = {
    "X-Wildbox-User-ID": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "X-Wildbox-Team-ID": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "X-Wildbox-Role": "member",
    "X-Gateway-Secret": SECRET,
}
DAY_1 = datetime(2026, 10, 5, 23, 59, 30, tzinfo=timezone.utc)
DAY_2 = DAY_1 + timedelta(minutes=1)


class FakeRedis:
    """redis-py as the counters use it, with expiry recorded."""

    def __init__(self):
        self.store = {}
        self.ttl = {}

    def get(self, key):
        value = self.store.get(key)
        return None if value is None else str(value).encode()

    def setex(self, key, ttl, value):
        self.store[key] = value
        self.ttl[key] = ttl

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1

    def expire(self, key, ttl):
        self.ttl[key] = ttl

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)

    def pipeline(self):
        return self

    def execute(self):
        return []


# --- The daily counters ------------------------------------------------------


def test_a_day_has_its_own_counter():
    redis = FakeRedis()
    for _ in range(3):
        stats.count_today(redis, stats.COMPLETED, DAY_1)
    stats.count_today(redis, stats.FAILED, DAY_1)

    assert stats.read_today(redis, stats.COMPLETED, DAY_1) == 3
    assert stats.read_today(redis, stats.FAILED, DAY_1) == 1
    # One minute later it is another UTC day: today's counters start at 0.
    assert stats.read_today(redis, stats.COMPLETED, DAY_2) == 0
    assert stats.read_today(redis, stats.FAILED, DAY_2) == 0

    stats.count_today(redis, stats.COMPLETED, DAY_2)
    assert stats.read_today(redis, stats.COMPLETED, DAY_2) == 1
    assert stats.read_today(redis, stats.COMPLETED, DAY_1) == 3


def test_the_day_is_the_utc_date_whatever_the_local_offset():
    local = datetime(2026, 10, 6, 1, 30, tzinfo=timezone(timedelta(hours=2)))
    assert stats.utc_day(local) == "2026-10-05"
    assert stats.daily_key(stats.COMPLETED, local) == "stats:completed:2026-10-05"


def test_a_daily_counter_expires():
    redis = FakeRedis()
    stats.count_today(redis, stats.COMPLETED, DAY_1)

    [key] = redis.store
    assert key == "stats:completed:2026-10-05"
    # Longer than the day it counts, and not forever.
    assert 24 * 3600 < redis.ttl[key] <= 7 * 24 * 3600


def test_the_worker_counts_a_completed_task_under_todays_key(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(worker, "redis_client", redis)
    monkeypatch.setattr(
        worker.run_threat_enrichment_task, "update_state", lambda *a, **k: None
    )

    class Agent:
        async def analyze_ioc(self, ioc):
            return {"verdict": "Benign"}

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", lambda: Agent())
    worker.run_threat_enrichment_task(
        task_id="task-1",
        ioc={"type": "domain", "value": "example.com"},
        caller={"user_id": "u", "team_id": "t", "role": "member"},
    )

    assert stats.read_today(redis, stats.COMPLETED) == 1
    assert stats.read_today(redis, stats.FAILED) == 0
    assert not set(stats.LEGACY_KEYS) & set(redis.store)


def test_the_worker_counts_a_failed_task_under_todays_key(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(worker, "redis_client", redis)
    monkeypatch.setattr(
        worker.run_threat_enrichment_task, "update_state", lambda *a, **k: None
    )

    class Agent:
        async def analyze_ioc(self, ioc):
            raise ValueError("bad tool output")

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", lambda: Agent())
    worker.run_threat_enrichment_task(
        task_id="task-1",
        ioc={"type": "domain", "value": "example.com"},
        caller={"user_id": "u", "team_id": "t", "role": "member"},
    )
    # And a task refused for having no caller.
    with pytest.raises(worker.CallerIdentityUnavailable):
        worker.run_threat_enrichment_task(
            task_id="task-2", ioc={"type": "domain", "value": "x.example"}
        )

    assert stats.read_today(redis, stats.FAILED) == 2
    assert stats.read_today(redis, stats.COMPLETED) == 0
    assert not set(stats.LEGACY_KEYS) & set(redis.store)


def test_stats_reports_todays_counters_not_the_ones_never_reset(monkeypatch):
    redis = FakeRedis()
    # What an upgraded deployment holds: months of the old counters.
    redis.store["stats:completed_today"] = 4821
    redis.store["stats:failed_today"] = 97
    redis.store["stats:total_analyses"] = 5000
    stats.count_today(redis, stats.COMPLETED)
    stats.count_today(redis, stats.COMPLETED)
    stats.count_today(redis, stats.FAILED)
    stats.count_today(
        redis, stats.COMPLETED, datetime.now(timezone.utc) - timedelta(days=1)
    )
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "redis_client", redis)
    inspect = SimpleNamespace(active=lambda: {}, scheduled=lambda: {})
    monkeypatch.setattr(main.celery_app.control, "inspect", lambda: inspect)

    response = TestClient(main.app).get("/stats", headers=CALLER)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["completed_today"] == 2
    assert body["failed_today"] == 1
    assert body["total_analyses"] == 5000


def test_the_api_deletes_the_old_counters_when_it_starts(monkeypatch):
    redis = FakeRedis()
    redis.ping = lambda: True
    redis.store.update(
        {
            "stats:completed_today": 4821,
            "stats:failed_today": 97,
            "stats:total_analyses": 5000,
        }
    )
    monkeypatch.setattr(main.redis, "from_url", lambda url: redis)
    inspect = SimpleNamespace(ping=lambda: {})
    monkeypatch.setattr(main.celery_app.control, "inspect", lambda: inspect)

    with TestClient(main.app):
        pass

    assert redis.store == {"stats:total_analyses": 5000}


# --- Where the limiter counts ------------------------------------------------


def test_the_limiter_counts_in_the_services_redis_by_default(monkeypatch):
    monkeypatch.delenv("ANALYZE_RATE_LIMIT_STORAGE_URI", raising=False)
    monkeypatch.setenv("REDIS_URL", "redis://:pw@wildbox-redis:6379/4")

    settings = Settings(_env_file=None)

    assert settings.analyze_rate_limit_storage_uri == ""
    assert settings.rate_limit_storage_uri() == "redis://:pw@wildbox-redis:6379/4"


def test_the_limiter_is_built_on_the_configured_storage():
    """The module-level limiter, the one the endpoint is decorated with."""
    assert (
        rate_limit.limiter._storage_uri == rate_limit.settings.rate_limit_storage_uri()
    )
    # No silent fall back to per-process counters, and no swallowed error.
    assert rate_limit.limiter._in_memory_fallback_enabled is False
    assert rate_limit.limiter._swallow_errors is False


def test_a_redis_storage_uri_gives_a_redis_backed_limiter():
    from limits.storage import RedisStorage, storage_from_string

    storage = storage_from_string("redis://:pw@wildbox-redis:6379/4")
    assert isinstance(storage, RedisStorage)


@pytest.mark.parametrize(
    "value", ["memory://", "redis://h:6379/1", "rediss://h:6380/1", ""]
)
def test_the_storage_settings_that_are_accepted(value):
    assert (
        Settings(
            _env_file=None, analyze_rate_limit_storage_uri=value
        ).analyze_rate_limit_storage_uri
        == value
    )


@pytest.mark.parametrize(
    "value", ["memcached://h:11211", "banana", "http://h", "memory"]
)
def test_another_storage_stops_the_service(value):
    with pytest.raises(ValidationError, match="ANALYZE_RATE_LIMIT_STORAGE_URI"):
        Settings(_env_file=None, analyze_rate_limit_storage_uri=value)


def test_a_submission_that_cannot_be_counted_is_refused_with_503(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    enqueued = []
    monkeypatch.setattr(
        main.run_threat_enrichment_task, "delay", lambda **kw: enqueued.append(kw)
    )
    monkeypatch.setattr(main, "redis_client", FakeRedis())
    monkeypatch.setattr(main.limiter, "enabled", True)

    def unreachable(*args, **kwargs):
        raise StorageError(
            ConnectionError("Error 111 connecting to wildbox-redis:6379")
        )

    monkeypatch.setattr(main.limiter._limiter, "hit", unreachable)

    response = TestClient(main.app, raise_server_exceptions=False).post(
        "/v1/analyze",
        json={"ioc": {"type": "domain", "value": "example.com"}},
        headers=CALLER,
    )

    assert response.status_code == 503, response.text
    assert (
        response.json()["error"]["message"] == "Rate limiting temporarily unavailable"
    )
    assert "wildbox-redis" not in response.text
    assert enqueued == [], "an uncounted submission was accepted"
