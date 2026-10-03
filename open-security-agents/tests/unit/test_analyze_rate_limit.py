"""The analysis rate limit belongs to the authenticated caller (#651).

The limiter was keyed by ``get_remote_address``. Behind the gateway the peer
address is the gateway's for every caller, so the whole platform shared one
bucket of five analyses a minute, and any user of any team could empty it
for all the others. The limit is now keyed by the user the gateway
authenticated, with an optional ceiling per team.
"""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import main, rate_limit  # noqa: E402
from app.config import Settings, settings  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import ValidationError  # noqa: E402

SECRET = "gateway-secret-for-tests"
TEAM_1 = "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b"
TEAM_2 = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
ALICE = {"user_id": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77", "team_id": TEAM_1}
BOB = {"user_id": "0b3f0e4c-8d1a-4c2e-9f5b-1a2b3c4d5e6f", "team_id": TEAM_2}
CAROL = {"user_id": "5e2d1c0b-9a8f-4e7d-8c6b-5a4f3e2d1c0b", "team_id": TEAM_1}


class FakeRedis:
    def __init__(self):
        self.store = {}

    def setex(self, key, ttl, value):
        self.store[key] = value

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)

    def pipeline(self):
        return self

    def execute(self):
        return []


@pytest.fixture
def api(monkeypatch):
    """The app with Redis and the queue replaced, and the limiter enabled."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "redis_client", FakeRedis())
    monkeypatch.setattr(main.limiter, "enabled", True)
    monkeypatch.setattr(settings, "analyze_rate_limit", "5/minute")
    monkeypatch.setattr(settings, "analyze_team_rate_limit", "")
    main.limiter.reset()

    enqueued = []

    def delay(**kwargs):
        enqueued.append(kwargs["caller"]["user_id"])
        return SimpleNamespace(id=f"celery-{len(enqueued)}")

    monkeypatch.setattr(main.run_threat_enrichment_task, "delay", delay)
    yield TestClient(main.app), enqueued
    main.limiter.reset()


def submit(client, caller, **extra_headers):
    headers = {"X-Gateway-Secret": SECRET, **extra_headers}
    if caller is not None:
        headers.update(
            {
                "X-Wildbox-User-ID": caller["user_id"],
                "X-Wildbox-Team-ID": caller["team_id"],
                "X-Wildbox-Role": "member",
            }
        )
    return client.post(
        "/v1/analyze",
        json={"ioc": {"type": "domain", "value": "example.com"}},
        headers=headers,
    )


def statuses(client, caller, count, **extra_headers):
    return [submit(client, caller, **extra_headers).status_code for _ in range(count)]


def test_two_users_of_different_teams_each_get_their_own_budget(api):
    client, enqueued = api

    assert statuses(client, ALICE, 5) == [202] * 5
    assert statuses(client, BOB, 5) == [202] * 5
    assert len(enqueued) == 10


def test_two_users_of_the_same_team_each_get_their_own_budget(api):
    client, _ = api

    assert statuses(client, ALICE, 5) == [202] * 5
    assert statuses(client, CAROL, 5) == [202] * 5


def test_the_same_user_is_limited(api):
    client, enqueued = api

    assert statuses(client, ALICE, 5) == [202] * 5
    response = submit(client, ALICE)

    assert response.status_code == 429
    assert "per user" in response.text
    assert len(enqueued) == 5
    # Another user is not affected by Alice's exhausted budget.
    assert submit(client, BOB).status_code == 202


def test_a_forwarded_for_header_does_not_change_the_bucket(api):
    client, _ = api

    for n in range(5):
        response = submit(client, ALICE, **{"X-Forwarded-For": f"203.0.113.{n}"})
        assert response.status_code == 202

    spoofed = submit(
        client,
        ALICE,
        **{"X-Forwarded-For": "198.51.100.7", "X-Real-IP": "198.51.100.7"},
    )
    assert spoofed.status_code == 429


def test_a_request_without_identity_is_refused_and_not_counted(api):
    client, enqueued = api

    refused = [submit(client, None).status_code for _ in range(6)]

    assert all(code in (401, 403) for code in refused), refused
    assert enqueued == []
    assert statuses(client, ALICE, 5) == [202] * 5


def test_a_request_with_a_wrong_secret_is_refused_before_the_limit(api):
    client, enqueued = api

    forged = [
        submit(client, ALICE, **{"X-Gateway-Secret": "wrong"}).status_code
        for _ in range(6)
    ]

    assert all(code in (401, 403) for code in forged), forged
    # Forged requests in Alice's name did not use her budget.
    assert statuses(client, ALICE, 5) == [202] * 5
    assert enqueued == [ALICE["user_id"]] * 5


def test_the_configured_limit_is_applied(api, monkeypatch):
    client, _ = api
    monkeypatch.setattr(settings, "analyze_rate_limit", "2/minute")

    assert statuses(client, ALICE, 3) == [202, 202, 429]


def test_the_team_ceiling_bounds_a_team_when_configured(api, monkeypatch):
    client, _ = api
    monkeypatch.setattr(settings, "analyze_team_rate_limit", "3/minute")

    assert statuses(client, ALICE, 2) == [202, 202]
    assert submit(client, CAROL).status_code == 202
    over = submit(client, CAROL)

    assert over.status_code == 429
    assert "per team" in over.text
    # The other team has its own ceiling.
    assert statuses(client, BOB, 3) == [202] * 3


def test_a_request_over_the_user_limit_does_not_use_the_team_ceiling(api, monkeypatch):
    client, _ = api
    monkeypatch.setattr(settings, "analyze_rate_limit", "2/minute")
    monkeypatch.setattr(settings, "analyze_team_rate_limit", "4/minute")

    assert statuses(client, ALICE, 4) == [202, 202, 429, 429]
    assert statuses(client, CAROL, 2) == [202, 202]


def test_the_key_functions_refuse_a_request_without_a_verified_caller():
    request = SimpleNamespace(state=SimpleNamespace())

    for key_func in (rate_limit.user_rate_limit_key, rate_limit.team_rate_limit_key):
        with pytest.raises(HTTPException) as refused:
            key_func(request)
        assert refused.value.status_code == 403


# --- Settings ---------------------------------------------------------------


def test_the_limits_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("ANALYZE_RATE_LIMIT", "10/minute;100/day")
    monkeypatch.setenv("ANALYZE_TEAM_RATE_LIMIT", "50/minute")

    configured = Settings(_env_file=None)

    assert configured.analyze_rate_limit == "10/minute;100/day"
    assert configured.analyze_team_rate_limit == "50/minute"


def test_the_defaults_are_five_per_minute_per_user_and_no_team_ceiling(monkeypatch):
    monkeypatch.delenv("ANALYZE_RATE_LIMIT", raising=False)
    monkeypatch.delenv("ANALYZE_TEAM_RATE_LIMIT", raising=False)

    configured = Settings(_env_file=None)

    assert configured.analyze_rate_limit == "5/minute"
    assert configured.analyze_team_rate_limit == ""


@pytest.mark.parametrize("value", ["", "  ", "banana", "5/fortnight", "0/minute"])
def test_an_invalid_user_limit_is_refused(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, analyze_rate_limit=value)


@pytest.mark.parametrize("value", ["banana", "0/minute"])
def test_an_invalid_team_ceiling_is_refused(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, analyze_team_rate_limit=value)
