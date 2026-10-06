"""The sensor's statistics are counted, not declared (#725).

``GET /api/v1/stats`` answered a dictionary the agent created with zeros and
that nothing ever incremented: events_collected, events_processed and
events_forwarded stayed 0 on a sensor that had forwarded for days, uptime was
a minute stale, and last_activity was the time of the last refresh.

The agent here is the real one, started with a log file as its only source;
the gateway is a stand-in at the sender's ``_send``.
"""

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.api.local_api import LocalAPI  # noqa: E402
from sensor.collectors import log_forwarder  # noqa: E402
from sensor.core.agent import CountingQueue, SecuritySensorAgent  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    FIMConfig,
    LogSourceConfig,
    NetworkConfig,
    SensorConfig,
)
from sensor.pipeline.data_forwarder import (  # noqa: E402
    REFUSED,
    RETRY,
    SENT,
    DataForwarder,
)

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class Gateway:
    """What the sender's requests are answered: SENT, RETRY or REFUSED."""

    def __init__(self):
        self.answer = SENT
        self.accepted = 0


@pytest.fixture
def gateway(monkeypatch):
    gateway = Gateway()

    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    async def send(self, body):
        if gateway.answer == SENT:
            gateway.accepted += len(json.loads(body)["events"])
        elif gateway.answer == RETRY:
            self.stats["network_errors"] += 1
        return gateway.answer

    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    monkeypatch.setattr(log_forwarder, "POLL_INTERVAL", 0.01)
    return gateway


def _agent(log, **data_lake):
    settings = {"api_key": API_KEY, "batch_size": 2, "retry_delay": 0}
    settings.update(data_lake)
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", **settings),
        collection=CollectionConfig(
            process_events=False,
            network_connections=False,
            file_monitoring=False,
            user_events=False,
            system_inventory=False,
            log_forwarding=True,
        ),
        fim=FIMConfig(enabled=False),
        network=NetworkConfig(enable_api=False, api_key="local-api-key"),
        log_sources=[LogSourceConfig(name="app", path=str(log), format="raw")],
    )
    return SecuritySensorAgent(config)


def _append(path, text):
    with open(path, "a") as handle:
        handle.write(text)


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


async def _answer(handler):
    response = await handler(None)
    assert response.status == 200, response.text
    return json.loads(response.text)


@pytest.mark.asyncio
async def test_the_counters_count_what_the_sensor_did(tmp_path, gateway):
    log = tmp_path / "app.log"
    log.write_text("")
    agent = _agent(log)
    before = datetime.now(timezone.utc)

    assert agent.get_stats()["events_collected"] == 0
    assert agent.get_stats()["last_activity"] is None
    assert agent.get_stats()["uptime_seconds"] == 0
    await agent.start()
    try:
        agent.data_forwarder.min_request_interval = 0.002
        _append(log, "one\ntwo\nthree\nfour\n")
        await _until(lambda: agent.get_stats()["events_forwarded"] == 4)
        stats = agent.get_stats()
        status = agent.get_status()
    finally:
        await agent.stop()

    # main: 0, 0 and 0, for as long as the sensor ran.
    assert stats["events_collected"] == 4
    assert stats["events_processed"] == 4
    assert stats["events_forwarded"] == 4 == gateway.accepted
    assert stats["events_filtered"] == 0
    assert stats["events_dropped"] == 0
    assert stats["events_in_pipeline"] == 0
    assert stats["errors"] == 0
    # When the last event was collected, not when the answer was made.
    assert before <= datetime.fromisoformat(stats["last_activity"])
    assert stats["last_activity"] == agent.event_queue.last_put.isoformat()
    assert status["stats"]["events_forwarded"] == 4


@pytest.mark.asyncio
async def test_what_waits_what_is_dropped_and_what_fails_are_counted(tmp_path, gateway):
    log = tmp_path / "app.log"
    log.write_text("")
    agent = _agent(log)

    await agent.start()
    try:
        agent.data_forwarder.min_request_interval = 0.002
        # The gateway takes nothing: the events wait, and the attempts fail.
        gateway.answer = RETRY
        _append(log, "one\ntwo\nthree\n")
        await _until(lambda: len(agent.data_forwarder.buffer) == 3)
        await _until(lambda: agent.data_forwarder.stats["send_failures"] >= 2)
        waiting = agent.get_stats()

        # It refuses the first batch, then accepts the rest.
        gateway.answer = REFUSED
        await _until(lambda: agent.get_stats()["events_dropped"] == 2)
        gateway.answer = SENT
        _append(log, "four\n")
        await _until(lambda: agent.get_stats()["events_forwarded"] == 2)
        done = agent.get_stats()
    finally:
        await agent.stop()

    assert waiting["events_collected"] == waiting["events_processed"] == 3
    assert waiting["events_forwarded"] == 0
    assert waiting["events_in_pipeline"] == 3
    assert waiting["errors"] >= 2
    assert done["events_collected"] == 4
    assert done["events_dropped"] == 2
    assert done["events_forwarded"] == 2
    assert done["events_in_pipeline"] == 0
    assert done["events_collected"] == (
        done["events_forwarded"] + done["events_dropped"] + done["events_filtered"]
    )


@pytest.mark.asyncio
async def test_a_filtered_event_is_collected_and_not_processed(tmp_path, gateway):
    log = tmp_path / "app.log"
    log.write_text("")
    agent = _agent(log)

    await agent.start()
    try:
        # As a collector would: an event with no data is filtered out.
        await agent.event_queue.put(
            {"type": "file_created", "source": "fim", "data": {}}
        )
        await _until(lambda: agent.get_stats()["events_filtered"] == 1)
        stats = agent.get_stats()
    finally:
        await agent.stop()

    assert stats["events_collected"] == 1
    assert stats["events_processed"] == 0
    assert stats["events_forwarded"] == 0


@pytest.mark.asyncio
async def test_the_stats_route_answers_the_counters(tmp_path, gateway):
    log = tmp_path / "app.log"
    log.write_text("")
    agent = _agent(log)
    api = LocalAPI(agent.config, agent)

    await agent.start()
    try:
        agent.data_forwarder.min_request_interval = 0.002
        _append(log, "one\ntwo\n")
        await _until(lambda: agent.get_stats()["events_forwarded"] == 2)
        # The resource monitor's first measurement.
        await _until(lambda: "memory_mb" in agent.get_stats())
        stats = await _answer(api._stats_handler)
        summary = await _answer(api._dashboard_metrics_handler)
    finally:
        await agent.stop()

    assert stats["events_collected"] == 2
    assert stats["events_processed"] == 2
    assert stats["events_forwarded"] == 2
    assert isinstance(stats["uptime_seconds"], int)
    assert stats["memory_mb"] > 0 and stats["over_limits"] in (True, False)
    assert "throttled" not in stats
    datetime.fromisoformat(stats["timestamp"])
    assert stats["last_activity"] != stats["timestamp"]

    # The summary says what the sensor measured, and nothing it did not:
    # it used to answer "unknown", zeros and the current time.
    details = summary["endpoint_details"]
    assert summary["online_endpoints"] == 1 and summary["alerts"] == 0
    assert summary["last_activity"] == stats["last_activity"]
    assert details["hostname"] == agent.data_processor.hostname != "unknown"
    assert details["os"] == agent.data_processor.platform_info["system"]
    assert details["events_collected"] == details["events_forwarded"] == 2
    assert details["memory_mb"] > 0
    for invented in ("disk_usage", "network_connections", "process_count"):
        assert invented not in details
    assert "trends_change" not in summary


@pytest.mark.asyncio
async def test_the_summary_counts_errors_as_something_to_look_at(tmp_path, gateway):
    log = tmp_path / "app.log"
    log.write_text("")
    agent = _agent(log)
    api = LocalAPI(agent.config, agent)

    await agent.start()
    try:
        agent.data_forwarder.min_request_interval = 0.002
        gateway.answer = RETRY
        _append(log, "one\ntwo\n")
        await _until(lambda: agent.get_stats()["errors"] >= 1)
        summary = await _answer(api._dashboard_metrics_handler)
    finally:
        await agent.stop()

    assert summary["alerts"] == 1


@pytest.mark.asyncio
async def test_the_summary_counts_a_sensor_over_its_thresholds(tmp_path, gateway):
    log = tmp_path / "app.log"
    log.write_text("")
    agent = _agent(log)
    # This process uses more than one megabyte.
    agent.config.performance.max_memory_mb = 1
    api = LocalAPI(agent.config, agent)

    await agent.start()
    try:
        await _until(lambda: "memory_mb" in agent.get_stats())
        stats = await _answer(api._stats_handler)
        summary = await _answer(api._dashboard_metrics_handler)
    finally:
        await agent.stop()

    assert stats["over_limits"] is True
    assert summary["alerts"] == 1


@pytest.mark.asyncio
async def test_a_sensor_that_delivers_nothing_says_so_where_it_is_looked_at(
    tmp_path, gateway
):
    # The local API answered "running" and zero errors for a sensor whose
    # key had been revoked for a week.
    log = tmp_path / "app.log"
    log.write_text("")
    agent = _agent(log)
    api = LocalAPI(agent.config, agent)

    await agent.start()
    try:
        agent.data_forwarder.min_request_interval = 0.002
        assert agent.get_stats()["delivery_state"] == "ok"
        agent.data_forwarder._note("unauthorized", "HTTP 401 invalid_token")
        stats = await _answer(api._stats_handler)
        summary = await _answer(api._dashboard_metrics_handler)
    finally:
        await agent.stop()

    assert stats["delivery_state"] == "unauthorized"
    assert stats["delivery_since"]
    assert summary["delivery_state"] == "unauthorized"
    assert summary["alerts"] == 1


@pytest.mark.asyncio
async def test_the_queue_counts_every_put_and_nothing_else():
    queue = CountingQueue(maxsize=2)

    assert (queue.total, queue.last_put) == (0, None)
    await queue.put("a")
    queue.put_nowait("b")
    with pytest.raises(asyncio.QueueFull):
        queue.put_nowait("c")  # not put: not counted
    assert queue.get_nowait() == "a"

    assert queue.total == 2
    assert queue.qsize() == 1
    assert isinstance(queue.last_put, datetime)
