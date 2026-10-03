"""Telemetry ingested through the gateway stays with the ingesting team (#641).

Two accounts, each the owner of the team registration gives it, talk to the
data service only through the gateway, with their own sessions. Team A posts
a valid batch to POST /api/v1/data/ingest; team B then sees none of it -- not
in the events, the sensors or the statistics, and not by asking for A's
sensor ID -- and a batch B posts under the same sensor ID, claiming A's team,
leaves A's sensor record as it was.

Before #641, telemetry and sensor records had no team: every team read every
team's events, and a sensor ID was unique across teams, so B's batch updated
A's record. Deterministic: one request per step, no retries, no waiting.
"""

import os
import secrets

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15

DATA_API = f"{GATEWAY_URL}/api/v1/data"


def bearer(token, **extra):
    return {"Authorization": f"Bearer {token}", **extra}


def account(label):
    """A new account and its team: (session, team id)."""
    address = f"telemetry-tenancy-{label}-{secrets.token_hex(6)}@example.com"
    password = f"Telemetry-Tenancy-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": address, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": address, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    token = login.json()["access_token"]
    probe = requests.get(f"{DATA_API}/health", headers=bearer(token), timeout=TIMEOUT)
    assert probe.status_code == 200, probe.text[:200]
    return token, probe.headers["X-Wildbox-Team-ID"]


def batch(sensor_id, host, count, claim=None):
    """A valid batch for /api/v1/ingest; ``claim`` names a team in the body."""
    events = []
    for i in range(count):
        event = {
            "sensor_id": sensor_id,
            "event_type": "process_event",
            "timestamp": f"2026-10-03T10:00:{i:02d}+00:00",
            "source_host": host,
            "event_data": {"pid": 4000 + i, "cmdline": f"/usr/bin/{host}"},
            "raw_data": f"raw line {i} from {host}",
            "severity": 3,
            "tags": ["process"],
        }
        if claim:
            event["team_id"] = claim
        events.append(event)
    body = {"batch_id": f"{sensor_id}-{host}", "events": events}
    if claim:
        body["team_id"] = claim
    return body


def ingest(token, body, **headers):
    response = requests.post(
        f"{DATA_API}/ingest",
        json=body,
        headers=bearer(token, **headers),
        timeout=TIMEOUT,
    )
    assert response.status_code == 200, response.text[:300]
    result = response.json()
    assert result["errors"] == [], result
    assert result["events_ingested"] == len(body["events"]), result
    return result


def get(token, path, expect=200, **params):
    response = requests.get(
        f"{DATA_API}{path}", params=params, headers=bearer(token), timeout=TIMEOUT
    )
    assert response.status_code == expect, f"{path}: {response.text[:300]}"
    return response.json()


@pytest.fixture(scope="module")
def teams():
    token_a, team_a = account("a")
    token_b, team_b = account("b")
    assert team_a != team_b
    sensor_id = f"s1-{secrets.token_hex(4)}"
    ingest(token_a, batch(sensor_id, "a-host", 3))
    return {
        "a": token_a,
        "b": token_b,
        "team_a": team_a,
        "team_b": team_b,
        "sensor": sensor_id,
    }


def test_team_a_reads_its_own_telemetry(teams):
    token, sensor = teams["a"], teams["sensor"]
    events = get(token, "/telemetry/events", sensor_id=sensor, limit=100)
    assert len(events) == 3
    assert {e["source_host"] for e in events} == {"a-host"}
    assert get(token, f"/sensors/{sensor}")["total_events"] == 3
    stats = get(token, "/telemetry/stats", sensor_id=sensor, hours=24 * 3650)
    assert stats["total_events"] == 3


def test_team_b_sees_none_of_team_a_telemetry(teams):
    token, sensor = teams["b"], teams["sensor"]

    assert get(token, "/telemetry/events", sensor_id=sensor, limit=1000) == []
    listed = get(token, "/telemetry/events", limit=1000)
    assert all(e["source_host"] != "a-host" for e in listed)

    for active_only in ("true", "false"):
        sensors = get(token, "/sensors", active_only=active_only)
        assert sensor not in {s["sensor_id"] for s in sensors}

    get(token, f"/sensors/{sensor}", expect=404)

    stats = get(token, "/telemetry/stats", sensor_id=sensor, hours=24 * 3650)
    assert stats["total_events"] == 0
    assert stats["events_by_type"] == {}


def test_team_b_cannot_overwrite_team_a_sensor(teams):
    sensor = teams["sensor"]
    before = get(teams["a"], f"/sensors/{sensor}")

    # Same sensor ID, A's team named in the body and in a forged gateway
    # header: the batch is stored for B, the authenticated caller.
    ingest(
        teams["b"],
        batch(sensor, "b-host", 2, claim=teams["team_a"]),
        **{"X-Wildbox-Team-ID": teams["team_a"]},
    )

    after = get(teams["a"], f"/sensors/{sensor}")
    assert after == before

    own = get(teams["b"], f"/sensors/{sensor}")
    assert own["id"] != before["id"]
    assert (own["total_events"], own["hostname"]) == (2, "b-host")

    a_events = get(teams["a"], "/telemetry/events", sensor_id=sensor, limit=100)
    b_events = get(teams["b"], "/telemetry/events", sensor_id=sensor, limit=100)
    assert {e["source_host"] for e in a_events} == {"a-host"} and len(a_events) == 3
    assert {e["source_host"] for e in b_events} == {"b-host"} and len(b_events) == 2
