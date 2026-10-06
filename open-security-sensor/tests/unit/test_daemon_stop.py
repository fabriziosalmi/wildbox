"""The process ends when the sensor has stopped, not when it is asked to (#725).

On SIGTERM the daemon set a flag and created a task to stop the agent; its
main coroutine saw the flag within a second and returned, the event loop
closed, and the task was cancelled wherever it had got to. An orderly
``docker stop`` therefore lost what stopping is for: the sender's last batches
and the log positions written after them. Found in the built image, where a
line the gateway had accepted was sent again after a restart.

The daemon here is the real one, started from a configuration file and
stopped by a real SIGTERM to this process; the gateway is a stand-in at the
sender's ``_send`` that takes its time to answer.
"""

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

import main as sensor_main  # noqa: E402
from sensor.collectors import log_forwarder  # noqa: E402
from sensor.collectors.position_store import STATE_FILE  # noqa: E402
from sensor.pipeline.data_forwarder import SENT, DataForwarder  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="signals are delivered differently on Windows"
)


@pytest.fixture
def sensor(tmp_path, monkeypatch):
    """A configuration with one log file, and a gateway that answers each
    batch after ``delay`` seconds."""
    log = tmp_path / "app.log"
    log.write_text("")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "data_lake": {
                    "endpoint": "https://gateway.example",
                    "api_key": API_KEY,
                    # Never due by itself: the events go when the sensor stops.
                    "batch_size": 100,
                    "flush_interval": 3600,
                },
                "collection": {
                    "process_events": False,
                    "network_connections": False,
                    "file_monitoring": False,
                    "user_events": False,
                    "system_inventory": False,
                    "log_forwarding": True,
                },
                "fim": {"enabled": False, "paths": ["/etc"]},
                "network": {"enable_api": False},
                "data_dir": str(data_dir),
                "log_sources": [{"name": "app", "path": str(log), "format": "raw"}],
            }
        )
    )

    class Gateway:
        delay = 1.5
        accepted = []

    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    async def send(self, body):
        await asyncio.sleep(Gateway.delay)
        Gateway.accepted += [
            event["event_data"]["data"]["raw_message"]
            for event in json.loads(body)["events"]
        ]
        return SENT

    Gateway.accepted = []
    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    monkeypatch.setattr(log_forwarder, "POLL_INTERVAL", 0.01)
    # The daemon configures the root logger and installs signal handlers:
    # both are put back.
    monkeypatch.setattr(sensor_main, "setup_logging", lambda settings: None)
    handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    yield sensor_main.SensorDaemon(str(config)), log, data_dir, Gateway
    # The loop the test ran on may already be closed and unset when this
    # runs (pytest-asyncio 1.4 does both before a synchronous fixture is
    # torn down): then there is no handler of the loop's left to remove, and
    # only the process-wide handlers are put back.
    try:
        loop = asyncio.get_event_loop_policy().get_event_loop()
    except RuntimeError:
        loop = None
    for signum, handler in handlers.items():
        if loop is not None:
            try:
                loop.remove_signal_handler(signum)
            except (NotImplementedError, RuntimeError, ValueError):
                pass
        signal.signal(signum, handler)


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


def _saved_offset(data_dir):
    state = json.loads((data_dir / STATE_FILE).read_text())
    (entry,) = state["sources"]["app"]["files"]
    return entry["offset"]


@pytest.mark.asyncio
async def test_sigterm_ends_the_daemon_after_the_last_batch_and_the_positions(sensor):
    daemon, log, data_dir, gateway = sensor
    running = asyncio.ensure_future(daemon.start())
    await _until(lambda: daemon.running)

    with open(log, "a") as handle:
        handle.write("one\ntwo\nthree\n")
    await _until(lambda: len(daemon.agent.data_forwarder.buffer) == 3)
    assert gateway.accepted == []

    os.kill(os.getpid(), signal.SIGTERM)
    code = await asyncio.wait_for(running, timeout=20)

    # At the moment start() returns, which is when the process ends: the
    # batch the gateway took a second and a half to answer was waited for,
    # and the positions written after it. main returned within a second,
    # with the batch in flight and the position at 0.
    assert code == 0
    assert gateway.accepted == ["one", "two", "three"]
    assert _saved_offset(data_dir) == len("one\ntwo\nthree\n")
    assert daemon.running is False
    assert daemon.agent.data_forwarder.session.closed is True
    assert daemon.agent.data_forwarder.stats["events_forwarded"] == 3


@pytest.mark.asyncio
async def test_a_signal_wakes_the_daemon_at_once(sensor):
    daemon, log, data_dir, gateway = sensor
    gateway.delay = 0
    running = asyncio.ensure_future(daemon.start())
    await _until(lambda: daemon.running)
    loop = asyncio.get_running_loop()

    started = loop.time()
    os.kill(os.getpid(), signal.SIGINT)
    assert await asyncio.wait_for(running, timeout=20) == 0

    # Not at the next tick of a one-second sleep.
    assert loop.time() - started < 0.9


@pytest.mark.asyncio
async def test_an_event_loop_without_signal_support_is_stopped_all_the_same(
    sensor, monkeypatch
):
    # As on Windows, where the loop cannot take a signal handler: the
    # handler is installed with the signal module and hands over to the loop.
    daemon, log, data_dir, gateway = sensor
    gateway.delay = 0

    def unsupported(*args):
        raise NotImplementedError

    monkeypatch.setattr(asyncio.get_running_loop(), "add_signal_handler", unsupported)
    running = asyncio.ensure_future(daemon.start())
    await _until(lambda: daemon.running)
    with open(log, "a") as handle:
        handle.write("one\n")
    await _until(lambda: len(daemon.agent.data_forwarder.buffer) == 1)

    os.kill(os.getpid(), signal.SIGTERM)

    assert await asyncio.wait_for(running, timeout=20) == 0
    assert gateway.accepted == ["one"]


@pytest.mark.asyncio
async def test_stop_asks_and_start_returns_when_the_sensor_has_stopped(sensor):
    daemon, log, data_dir, gateway = sensor
    gateway.delay = 0.3
    running = asyncio.ensure_future(daemon.start())
    await _until(lambda: daemon.running)
    with open(log, "a") as handle:
        handle.write("one\n")
    await _until(lambda: len(daemon.agent.data_forwarder.buffer) == 1)

    await daemon.stop()
    assert not running.done()  # asked, not done
    assert await asyncio.wait_for(running, timeout=20) == 0

    assert gateway.accepted == ["one"]
    assert _saved_offset(data_dir) == len("one\n")


@pytest.mark.asyncio
async def test_a_configuration_error_still_ends_with_its_own_status(tmp_path, capsys):
    config = tmp_path / "config.yaml"
    config.write_text('data_lake:\n  endpoint: "http://not-https"\n')

    assert await sensor_main.SensorDaemon(str(config)).start() == 2

    assert "Security Sensor not started" in capsys.readouterr().err


@pytest.mark.parametrize(
    "compose",
    [SERVICE_ROOT / "docker-compose.yml", SERVICE_ROOT.parent / "docker-compose.yml"],
)
def test_the_compose_files_give_the_sensor_the_time_its_stop_takes(compose):
    from sensor.pipeline.data_forwarder import STOP_FLUSH_SECONDS

    sensor = yaml.safe_load(compose.read_text())["services"]["sensor"]

    # Docker kills a container that has not stopped after 10 seconds unless
    # told otherwise, and the sender alone may spend that on its last batches.
    grace = sensor["stop_grace_period"]
    assert grace.endswith("s") and int(grace[:-1]) >= STOP_FLUSH_SECONDS + 15
