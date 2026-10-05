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
  * once the key is revoked, the next batch is refused with 401 (#593/#608);
  * a line written to a file that ``log_sources`` names is read by the log
    forwarder and stored for the key's team, and a file it does not name is
    not read (#638);
  * a sensor that restarts goes on where the data service's last accepted
    line was: a line written while it was down is stored, and none twice
    (#725).

Deterministic: one batch per step, no retries, and no waiting except for the
log forwarder to look at its file and, in the restart test, for the gateway
to answer each line's batch; every wait has a bound.
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
    forwarder = DataForwarder(config, asyncio.Queue())
    forwarder.min_request_interval = 0
    await forwarder._init_session()
    try:
        for event in request["events"]:
            forwarder.accept(event)
        # One attempt: a batch the gateway does not take stays in the buffer.
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


# Runs in the sensor container (#638). Takes the container's configuration,
# adds one log source for a file in a temporary directory, and runs the real
# log forwarder on it: a line appended to the file is collected, processed and
# sent as the running sensor sends it. A second file in the same directory,
# which no source names, receives a line too.
FORWARD_LOG = r"""
import asyncio, json, os, shutil, sys, tempfile

request = json.load(sys.stdin)
os.environ["SENSOR_DATA_LAKE_API_KEY"] = request["key"]

import yaml

from sensor.collectors.log_forwarder import LogForwarder
from sensor.core.config import load_config
from sensor.pipeline.data_forwarder import DataForwarder
from sensor.pipeline.data_processor import DataProcessor
from sensor.pipeline.delivery import take_delivery


async def main():
    directory = tempfile.mkdtemp(prefix="log-source-")
    configured = os.path.join(directory, "access.log")
    unlisted = os.path.join(directory, "unlisted.log")
    for path in (configured, unlisted):
        open(path, "w").close()

    with open("/etc/security-sensor/config.yaml") as handle:
        settings = yaml.safe_load(handle)
    settings.setdefault("collection", {})["log_forwarding"] = True
    # Positions in memory: the container's data directory is the running
    # sensor's, and one directory keeps one sensor's positions.
    settings.pop("data_dir", None)
    settings["log_sources"] = [
        {
            "name": request["source"],
            "type": "file",
            "path": configured,
            "format": "nginx",
        }
    ]
    config_path = os.path.join(directory, "config.yaml")
    with open(config_path, "w") as handle:
        yaml.safe_dump(settings, handle)

    config = load_config(config_path)
    config.data_lake.sensor_id = request["sensor_id"]

    collected = asyncio.Queue()
    forwarder = LogForwarder(config, collected)
    forwarder.poll_interval = 0.05
    await forwarder.start()
    try:
        with open(unlisted, "a") as handle:
            handle.write(request["unlisted_line"] + "\n")
        with open(configured, "a") as handle:
            handle.write(request["line"] + "\n")
        events = [await asyncio.wait_for(collected.get(), timeout=30)]
        # Several more looks at the source: anything else it reads shows up.
        await asyncio.sleep(0.5)
        while not collected.empty():
            events.append(collected.get_nowait())
    finally:
        await forwarder.stop()
        shutil.rmtree(directory, ignore_errors=True)

    processor = DataProcessor(config, asyncio.Queue(), asyncio.Queue())
    sender = DataForwarder(config, asyncio.Queue())
    sender.min_request_interval = 0
    await sender._init_session()
    try:
        for event in events:
            # As the processor's loop does: the handle by which the log
            # forwarder learns what became of the line is not the event's.
            take_delivery(event)
            sender.accept(await processor._process_single_event(event))
        await sender._flush_batch()
    finally:
        await sender.session.close()
    print(json.dumps({
        "sources": [[source.name, source.path] for source in forwarder.log_sources],
        "configured": configured,
        "collected": len(events),
        "stats": sender.stats,
    }))


asyncio.run(main())
"""


# Runs in the sensor container (#725). The log forwarder, the processor and
# the sender, connected as the agent connects them, are run twice on one log
# file and one data directory: a first run, a line written while "the sensor
# is down", a second run. Each line is its own batch, and each run waits for
# the gateway to have accepted what it must before it stops.
FORWARD_LOG_RESTART = r"""
import asyncio, json, os, shutil, sys, tempfile

request = json.load(sys.stdin)
os.environ["SENSOR_DATA_LAKE_API_KEY"] = request["key"]

import yaml

from sensor.collectors.log_forwarder import LogForwarder
from sensor.core.config import load_config
from sensor.pipeline.data_forwarder import DataForwarder
from sensor.pipeline.data_processor import DataProcessor


async def until(condition, what):
    deadline = asyncio.get_running_loop().time() + 30
    while not condition():
        if asyncio.get_running_loop().time() > deadline:
            raise SystemExit("timed out waiting for " + what)
        await asyncio.sleep(0.05)


async def run(config_path, log, lines, expected):
    # One run of the sensor's log pipeline: write ``lines``, one at a time,
    # and stop when the gateway has accepted ``expected`` events.
    config = load_config(config_path)
    config.data_lake.sensor_id = request["sensor_id"]
    config.data_lake.batch_size = 1
    collected, processed = asyncio.Queue(100), asyncio.Queue(100)
    forwarder = LogForwarder(config, collected)
    forwarder.poll_interval = 0.05
    processor = DataProcessor(config, collected, processed)
    sender = DataForwarder(config, processed)
    sender.min_request_interval = 0
    await processor.start()
    await sender.start()
    await forwarder.start()
    try:
        for line in lines:
            with open(log, "a") as handle:
                handle.write(line + "\n")
        await until(
            lambda: sender.stats["events_forwarded"] >= expected,
            "the gateway to accept %d events" % expected,
        )
    finally:
        # As the agent stops: what collects, what carries, the positions.
        await forwarder.stop()
        await processor.stop()
        await sender.stop()
        forwarder.save_positions()
    return dict(sender.stats)


async def main():
    directory = tempfile.mkdtemp(prefix="log-restart-")
    data_dir = os.path.join(directory, "data")
    os.mkdir(data_dir)
    log = os.path.join(directory, "access.log")
    with open(log, "w") as handle:
        handle.write(request["lines"]["before"] + "\n")

    with open("/etc/security-sensor/config.yaml") as handle:
        settings = yaml.safe_load(handle)
    settings.setdefault("collection", {})["log_forwarding"] = True
    settings["data_dir"] = data_dir
    settings["log_sources"] = [
        {"name": request["source"], "path": log, "format": "raw"}
    ]
    config_path = os.path.join(directory, "config.yaml")
    with open(config_path, "w") as handle:
        yaml.safe_dump(settings, handle)

    try:
        first = await run(config_path, log, [request["lines"]["first_run"]], 1)
        with open(log, "a") as handle:
            handle.write(request["lines"]["while_down"] + "\n")
        second = await run(config_path, log, [request["lines"]["second_run"]], 2)
        with open(os.path.join(data_dir, "log-positions.json")) as handle:
            state = json.load(handle)
        size = os.path.getsize(log)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    print(json.dumps({
        "first": first,
        "second": second,
        "state": state,
        "size": size,
        "uid": os.geteuid(),
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
    return _in_sensor(FORWARD, key, sensor_id=sensor_id, events=events)


def _in_sensor(script, key, **request):
    """Run ``script`` in the sensor container; the JSON it prints last."""
    if shutil.which("docker") is None:
        _unavailable("docker is not available to reach the sensor container")
    result = subprocess.run(
        ["docker", "exec", "-i", SENSOR_CONTAINER, "python", "-c", script],
        input=json.dumps(dict(request, key=key)),
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


def test_a_line_written_to_a_configured_log_source_reaches_the_keys_team(teams):
    """The log forwarder reads the source the configuration names (#638).

    It used to ignore ``log_sources`` and read ``/var/log/syslog``,
    ``/var/log/auth.log`` and the journal, none of which exists in the
    container: a line written to the configured file went nowhere. This is
    the one test here that waits, for the forwarder to look at the file, up
    to a bound.
    """
    sensor_id = f"logs-{uuid.uuid4().hex[:8]}"
    source = f"access_{uuid.uuid4().hex[:6]}"
    marker = uuid.uuid4().hex
    unlisted_marker = uuid.uuid4().hex
    line = (
        f'203.0.113.9 - - [05/Oct/2026:10:00:00 +0000] "GET /search?q={marker} '
        f'HTTP/1.1" 200 512 "-" "sqlmap/1.7"'
    )

    result = _in_sensor(
        FORWARD_LOG,
        teams["key"]["key"],
        sensor_id=sensor_id,
        source=source,
        line=line,
        unlisted_line=f"a line in a file no source names {unlisted_marker}",
    )

    # Exactly the configured source: no default path beside it, and nothing
    # read from the file next to it.
    assert result["sources"] == [[source, result["configured"]]], result
    assert result["collected"] == 1, result
    assert result["stats"]["batches_sent"] == 1, result["stats"]
    assert result["stats"]["events_forwarded"] == 1, result["stats"]

    listed = _listed(teams["a"], sensor_id)
    assert len(listed) == 1, listed
    (event,) = listed
    assert event["event_type"] == "security_event"
    assert f"log.{source}" in event["tags"]
    collected = event["event_data"]
    assert collected["source"] == "log_forwarder"
    assert collected["type"] == f"log.{source}"
    assert collected["data"]["client_ip"] == "203.0.113.9"
    assert marker in collected["data"]["request"]
    assert collected["data"]["raw_message"] == line
    assert collected["metadata"]["log_file"] == result["configured"]
    assert unlisted_marker not in json.dumps(listed)

    assert _listed(teams["b"], sensor_id) == []


def test_a_restarted_sensor_goes_on_where_the_data_service_stopped(teams):
    """The read position outlives the sensor, and is the last line accepted (#725).

    Positions were kept in memory: with the default ``read_from: end`` a
    line written while the sensor was down was never sent. The file starts
    with a line written before the sensor ever ran, which ``read_from: end``
    leaves out; then one line per phase.
    """
    sensor_id = f"restart-{uuid.uuid4().hex[:8]}"
    source = f"app_{uuid.uuid4().hex[:6]}"
    lines = {
        phase: f"{phase} {uuid.uuid4().hex}"
        for phase in ("before", "first_run", "while_down", "second_run")
    }

    result = _in_sensor(
        FORWARD_LOG_RESTART,
        teams["key"]["key"],
        sensor_id=sensor_id,
        source=source,
        lines=lines,
    )

    # Run as the sensor's user, which owns its data directory.
    assert result["uid"] != 0, result
    assert result["first"]["events_forwarded"] == 1, result["first"]
    assert result["second"]["events_forwarded"] == 2, result["second"]
    for run in ("first", "second"):
        assert result[run]["events_dropped"] == 0, result[run]
        assert result[run]["events_returned_to_source"] == 0, result[run]
    # The saved offset is the end of the file: every line accepted.
    (saved,) = result["state"]["sources"][source]["files"]
    assert saved["offset"] == result["size"], result["state"]

    stored = [
        event["event_data"]["data"]["raw_message"]
        for event in _listed(teams["a"], sensor_id)
    ]
    # The line written while the sensor was down is there, and nothing is
    # there twice: the second run did not start over, nor from the end.
    assert sorted(stored) == sorted(
        [lines["first_run"], lines["while_down"], lines["second_run"]]
    ), stored
    assert _listed(teams["b"], sensor_id) == []


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
