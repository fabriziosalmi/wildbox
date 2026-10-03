"""Sensor telemetry reaches the data service, under the sensor's team (#628).

The sensor's forwarder posted to the data service's /api/v1/ingest directly,
with ``Authorization: Bearer <key>``. The data service accepts only requests
the gateway has authenticated, so every batch was refused and no telemetry was
ever stored. The sensor now sends through the gateway, with a personal API key
of a team member created for it, scoped to ``data:ingest``.

These tests run the forwarder's own code inside the running sensor container,
with the configuration docker-compose.yml gives it -- the gateway URL, the
gateway's certificate from the gateway_cert volume, the container's network
-- and only the key supplied by the test (over stdin, so it is in no process
list). What they assert happens through the gateway, as for any client:

  * a batch is accepted, and the data service lists its events for the key's
    team and not for another team;
  * the ingest-only key can do nothing but ingest;
  * a batch cannot be stored for another team by claiming it;
  * once the key is revoked, the next batch is refused with 401 (#593/#608).

Deterministic: one batch per step, no retries, no waiting.
"""

import json
import os
import secrets
import shutil
import subprocess
import uuid

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
SENSOR_CONTAINER = os.getenv("SENSOR_CONTAINER", "open-security-sensor")
TIMEOUT = 15

IDENTITY_API = f"{GATEWAY_URL}/api/v1/identity"
DATA_API = f"{GATEWAY_URL}/api/v1/data"

# Runs in the sensor container. Reads the key from stdin, loads the
# container's configuration, and flushes one batch of collector-shaped events
# through DataForwarder, exactly as the running sensor does.
FORWARD = r"""
import asyncio, json, os, sys

request = json.load(sys.stdin)
os.environ["SENSOR_DATA_LAKE_API_KEY"] = request["key"]

from sensor.core.config import load_config
from sensor.pipeline.data_forwarder import DataForwarder


async def main():
    config = load_config("/etc/security-sensor/config.yaml")
    config.data_lake.sensor_id = request["sensor_id"]
    config.data_lake.retry_attempts = 1
    forwarder = DataForwarder(config, asyncio.Queue())
    forwarder.min_request_interval = 0
    await forwarder._init_session()
    try:
        forwarder.batch_buffer.extend(request["events"])
        await forwarder._flush_batch()
    finally:
        await forwarder.session.close()
    print(json.dumps({
        "ingest_url": config.data_lake.ingest_url,
        "ca_bundle": config.data_lake.ca_bundle,
        "tls_verify": config.data_lake.tls_verify,
        "stats": forwarder.stats,
    }))


asyncio.run(main())
"""


def _email(label):
    return f"sensor-ingest-{label}-{secrets.token_hex(6)}@example.com"


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _account(label):
    """A new account, owner of the team registration gives it; its session."""
    address, password = _email(label), f"Sensor-Ingest-{secrets.token_hex(8)}!"
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
    return login.json()["access_token"]


def _ingest_key(token):
    created = requests.post(
        f"{IDENTITY_API}/api-keys",
        json={"name": f"sensor-{secrets.token_hex(4)}", "scopes": ["data:ingest"]},
        headers=_bearer(token),
        timeout=TIMEOUT,
    )
    assert created.status_code in (200, 201), created.text[:200]
    body = created.json()
    assert body["scopes"] == ["data:ingest"], body
    return body


def _events(marker):
    """Two events as the sensor's data processor emits them."""
    host = {"hostname": "ingest-test-host", "platform": "Linux"}
    return [
        {
            "id": f"{marker}-1",
            "timestamp": "2026-10-03T10:00:00+00:00",
            "source": "osquery",
            "type": "network.listening_ports",
            "data": [{"port": "22", "marker": marker}],
            "metadata": {},
            "host": host,
        },
        {
            "id": f"{marker}-2",
            "timestamp": "2026-10-03T10:00:01+00:00",
            "source": "file_monitor",
            "type": "file_modified",
            "data": {"path": "/etc/hosts", "marker": marker},
            "host": host,
        },
    ]


def _forward(key, sensor_id, events):
    """One batch through the real forwarder in the sensor container."""
    if shutil.which("docker") is None:
        _unavailable("docker is not available to reach the sensor container")
    result = subprocess.run(
        ["docker", "exec", "-i", SENSOR_CONTAINER, "python", "-c", FORWARD],
        input=json.dumps({"key": key, "sensor_id": sensor_id, "events": events}),
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0 and "No such container" in result.stderr:
        _unavailable(f"{SENSOR_CONTAINER} is not running")
    assert result.returncode == 0, result.stderr[-800:]
    # The key must not appear in anything the forwarder printed or logged.
    assert key not in result.stdout and key not in result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def _unavailable(reason):
    if os.getenv("REQUIRE_ALL_SERVICES", "") in ("1", "true", "yes"):
        pytest.fail(f"{reason}, and REQUIRE_ALL_SERVICES is set", pytrace=False)
    pytest.skip(reason)


def _listed(token, sensor_id):
    response = requests.get(
        f"{DATA_API}/telemetry/events",
        params={"sensor_id": sensor_id, "limit": 100},
        headers=_bearer(token),
        timeout=TIMEOUT,
    )
    assert response.status_code == 200, response.text[:200]
    return response.json()


@pytest.fixture(scope="module")
def teams():
    """Team A, whose sensor reports, and team B, which must see none of it."""
    token_a = _account("a")
    token_b = _account("b")
    return {"a": token_a, "b": token_b, "key": _ingest_key(token_a)}


def test_the_sensor_is_wired_to_the_gateway_with_tls_verified(teams):
    sensor_id = f"wiring-{uuid.uuid4().hex[:8]}"

    result = _forward(teams["key"]["key"], sensor_id, [])

    assert result["ingest_url"] == "https://open-security-gateway/api/v1/data/ingest"
    assert result["tls_verify"] is True
    assert result["ca_bundle"] == "/etc/ssl/wildbox/wildbox.crt"


def test_a_batch_is_stored_for_the_keys_team_and_not_for_another(teams):
    sensor_id = f"sensor-{uuid.uuid4().hex[:8]}"
    marker = uuid.uuid4().hex

    result = _forward(teams["key"]["key"], sensor_id, _events(marker))

    stats = result["stats"]
    assert stats["batches_sent"] == 1, stats
    assert stats["events_forwarded"] == 2, stats

    listed = _listed(teams["a"], sensor_id)
    assert len(listed) == 2, listed
    assert {event["event_type"] for event in listed} == {
        "network_connection",
        "file_change",
    }
    assert all(event["source_host"] == "ingest-test-host" for event in listed)
    assert marker in json.dumps([event["event_data"] for event in listed])

    assert _listed(teams["b"], sensor_id) == []

    sensors_a = requests.get(
        f"{DATA_API}/sensors/{sensor_id}", headers=_bearer(teams["a"]), timeout=TIMEOUT
    )
    assert sensors_a.status_code == 200, sensors_a.text[:200]
    sensors_b = requests.get(
        f"{DATA_API}/sensors/{sensor_id}", headers=_bearer(teams["b"]), timeout=TIMEOUT
    )
    assert sensors_b.status_code == 404, sensors_b.text[:200]


def test_the_ingest_key_can_do_nothing_but_ingest(teams):
    key = {"X-API-Key": teams["key"]["key"]}

    read = requests.get(f"{DATA_API}/telemetry/events", headers=key, timeout=TIMEOUT)
    assert read.status_code == 403, read.text[:200]
    assert read.json().get("error") == "insufficient_scope"

    write = requests.post(f"{DATA_API}/sources", json={}, headers=key, timeout=TIMEOUT)
    assert write.status_code == 403, write.text[:200]

    tools = requests.post(
        f"{GATEWAY_URL}/api/v1/tools/whois_lookup",
        json={},
        headers=key,
        timeout=TIMEOUT,
    )
    assert tools.status_code == 403, tools.text[:200]


def test_a_batch_cannot_be_stored_for_another_team(teams):
    sensor_id = f"forged-{uuid.uuid4().hex[:8]}"
    # Team B's ID, from a key of B's: an API key names its team.
    team_b = _ingest_key(teams["b"])["team_id"]
    assert team_b != teams["key"]["team_id"]
    event = {
        "sensor_id": sensor_id,
        "event_type": "security_event",
        "timestamp": "2026-10-03T10:00:00+00:00",
        "event_data": {"claim": "team B"},
        "team_id": team_b,
    }

    response = requests.post(
        f"{DATA_API}/ingest",
        json={"events": [event], "team_id": team_b},
        headers={"X-API-Key": teams["key"]["key"], "X-Wildbox-Team-ID": team_b},
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, response.text[:200]
    assert response.json()["events_ingested"] == 1
    assert _listed(teams["b"], sensor_id) == []
    assert len(_listed(teams["a"], sensor_id)) == 1


def test_a_revoked_key_is_refused_on_the_next_batch(teams):
    token = _account("revoked")
    created = _ingest_key(token)
    sensor_id = f"revoked-{uuid.uuid4().hex[:8]}"

    first = _forward(created["key"], sensor_id, _events(uuid.uuid4().hex))
    assert first["stats"]["batches_sent"] == 1, first["stats"]

    revoked = requests.delete(
        f"{IDENTITY_API}/api-keys/{created['prefix']}",
        headers=_bearer(token),
        timeout=TIMEOUT,
    )
    assert revoked.status_code == 200, revoked.text[:200]

    second = _forward(created["key"], sensor_id, _events(uuid.uuid4().hex))
    assert second["stats"]["batches_sent"] == 0, second["stats"]
    assert second["stats"]["last_error"] == "HTTP 401", second["stats"]
    assert len(_listed(token, sensor_id)) == 2
