"""``main.py --status`` asks the running sensor (#745).

It printed "Security Sensor Status: Running" and exited 0 without looking:
on a host where no sensor ran, a sensor that was stopping, or one that had
delivered nothing for a day.

The sensor is the real local API over a stand-in for the agent, on a port
of its own; ``main.main()`` runs as the command does, in a thread.
"""

import asyncio
import socket
import sys
from pathlib import Path

import pytest
import pytest_asyncio
import yaml
from aiohttp import web

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

import main as sensor_main  # noqa: E402
from sensor.api import status_client  # noqa: E402
from sensor.api.local_api import LocalAPI  # noqa: E402
from sensor.core.config import load_config  # noqa: E402

LOCAL_KEY = "local-api-key-0123456789abcdef"

# aiohttp_cors keeps its state under a plain string key of the application,
# which aiohttp warns about; the local API's own start is not the subject.
pytestmark = pytest.mark.filterwarnings(
    "ignore:It is recommended to use web.AppKey instances for keys"
)


class Agent:
    """What the local API asks of the agent."""

    def __init__(self):
        self.running = True
        self.stats = {
            "events_collected": 120,
            "events_forwarded": 100,
            "events_dropped": 3,
            "events_in_pipeline": 17,
            "uptime_seconds": 86400,
            "delivery_state": "ok",
            "delivery_since": None,
        }

    def get_stats(self):
        return dict(self.stats)


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _write_config(tmp_path, port, **network):
    settings = {"bind_address": "127.0.0.1", "bind_port": port, "api_key": LOCAL_KEY}
    settings.update(network)
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "data_lake": {"endpoint": "https://gateway.example"},
                "network": {k: v for k, v in settings.items() if v is not None},
                "fim": {"enabled": False},
            }
        )
    )
    return str(path)


@pytest.fixture
def no_environment(monkeypatch):
    for name in (
        "SENSOR_API_KEY",
        "SENSOR_DATA_DIR",
        "SENSOR_DATA_LAKE_ENDPOINT",
        "SENSOR_DATA_LAKE_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest_asyncio.fixture
async def sensor(tmp_path, no_environment):
    """A running sensor's local API, its agent and its configuration file."""
    port = _free_port()
    path = _write_config(tmp_path, port)
    agent = Agent()
    api = LocalAPI(load_config(path), agent)
    await api.start()
    try:
        yield agent, path, port
    finally:
        await api.stop()


async def _status(monkeypatch, capsys, path):
    """The exit status and the output of ``main.py --config path --status``."""
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", path, "--status"])
    code = await asyncio.to_thread(sensor_main.main)
    return code, capsys.readouterr().out


@pytest.mark.asyncio
async def test_a_running_sensor_is_reported_with_what_it_counted(
    sensor, monkeypatch, capsys
):
    _, path, port = sensor

    code, out = await _status(monkeypatch, capsys, path)

    assert code == 0
    assert out.splitlines() == [
        f"✓ The sensor at http://127.0.0.1:{port} is running",
        "  Up 86400 s. Events: 120 collected, 100 delivered, 3 dropped, 17 waiting",
        "  Delivering to the data service",
    ]


@pytest.mark.asyncio
async def test_no_sensor_and_the_command_says_so(
    tmp_path, no_environment, monkeypatch, capsys
):
    port = _free_port()
    path = _write_config(tmp_path, port)

    code, out = await _status(monkeypatch, capsys, path)

    # main: "Security Sensor Status: Running", exit 0.
    assert code == 1
    assert out.startswith(f"✗ No sensor answers at http://127.0.0.1:{port}: ")
    assert "Running" not in out and "running" not in out


@pytest.mark.asyncio
async def test_a_sensor_that_is_stopping_is_not_running(sensor, monkeypatch, capsys):
    agent, path, port = sensor
    agent.running = False

    code, out = await _status(monkeypatch, capsys, path)

    assert code == 1
    assert out.strip() == (
        f"✗ The sensor at http://127.0.0.1:{port} is not running: it is "
        f"starting or stopping"
    )


@pytest.mark.asyncio
async def test_a_sensor_that_delivers_nothing_is_said_to(sensor, monkeypatch, capsys):
    agent, path, _ = sensor
    agent.stats.update(
        delivery_state="unauthorized", delivery_since="2026-10-05T19:41:57+00:00"
    )

    code, out = await _status(monkeypatch, capsys, path)

    # It is running, which is what the exit status answers.
    assert code == 0
    assert out.splitlines()[2] == (
        "  NOT delivering to the data service: unauthorized since "
        "2026-10-05T19:41:57+00:00. See data_forwarder in GET /api/v1/components"
    )


@pytest.mark.asyncio
async def test_another_key_than_the_sensors_and_its_counters_are_not_read(
    sensor, tmp_path, monkeypatch, capsys
):
    _, _, port = sensor
    path = _write_config(tmp_path, port, api_key="another-key-0123456789abcdef")

    code, out = await _status(monkeypatch, capsys, path)

    assert code == 0
    assert out.splitlines() == [
        f"✓ The sensor at http://127.0.0.1:{port} is running",
        "  Its counters could not be read: HTTP 403: the configured "
        "network.api_key is not the running sensor's",
    ]
    assert "another-key" not in out


@pytest.mark.asyncio
async def test_without_a_key_the_sensor_is_still_found(
    sensor, tmp_path, monkeypatch, capsys
):
    _, _, port = sensor
    path = _write_config(tmp_path, port, api_key=None)

    code, out = await _status(monkeypatch, capsys, path)

    assert code == 0
    assert out.splitlines() == [
        f"✓ The sensor at http://127.0.0.1:{port} is running",
        "  Its counters need the local API's key (network.api_key, or "
        "SENSOR_API_KEY), which is not set",
    ]


@pytest.mark.asyncio
async def test_the_key_is_never_printed(sensor, monkeypatch, capsys):
    agent, path, _ = sensor

    for state in ("ok", "forbidden"):
        agent.stats["delivery_state"] = state
        _, out = await _status(monkeypatch, capsys, path)
        assert LOCAL_KEY not in out


@pytest.mark.asyncio
async def test_a_sensor_bound_to_every_address_is_asked_on_this_host(
    tmp_path, no_environment, monkeypatch, capsys
):
    port = _free_port()
    path = _write_config(tmp_path, port, bind_address="0.0.0.0")
    api = LocalAPI(load_config(path), Agent())
    await api.start()
    try:
        code, out = await _status(monkeypatch, capsys, path)
    finally:
        await api.stop()

    assert code == 0
    assert out.startswith(f"✓ The sensor at http://127.0.0.1:{port} is running")


@pytest.mark.asyncio
async def test_with_the_local_api_off_it_cannot_be_told(
    tmp_path, no_environment, monkeypatch, capsys
):
    path = _write_config(tmp_path, _free_port(), enable_api=False)

    code, out = await _status(monkeypatch, capsys, path)

    assert code == 2
    assert out.startswith("? The local API is off (network.enable_api: false)")


@pytest.mark.asyncio
async def test_a_configuration_that_does_not_load_is_an_error(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "config.yaml"
    path.write_text("data_lake: [")

    code, out = await _status(monkeypatch, capsys, str(path))

    assert code == 1
    assert out.startswith("✗ Configuration error: ")


async def _serve(handler):
    """Something that is not a sensor, on a port of its own."""
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    port = _free_port()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    return runner, port


@pytest.mark.asyncio
async def test_what_answers_and_is_not_a_sensor_is_not_called_one(
    tmp_path, no_environment, monkeypatch, capsys
):
    async def page(request):
        return web.Response(text="<html>It works!</html>", content_type="text/html")

    runner, port = await _serve(page)
    try:
        code, out = await _status(monkeypatch, capsys, _write_config(tmp_path, port))
    finally:
        await runner.cleanup()

    assert code == 2
    assert out.strip() == (
        f"? What answers at http://127.0.0.1:{port}/health (HTTP 200) is not a sensor"
    )


@pytest.mark.asyncio
async def test_the_key_does_not_follow_a_redirect(
    tmp_path, no_environment, monkeypatch, capsys
):
    seen = []

    async def elsewhere(request):
        seen.append(dict(request.headers))
        return web.json_response({"events_collected": 1})

    other, other_port = await _serve(elsewhere)

    asked = {}

    async def redirecting(request):
        asked[request.path] = request.headers.get("X-API-Key")
        if request.path == "/health":
            return web.json_response({"status": "healthy"})
        raise web.HTTPFound(f"http://127.0.0.1:{other_port}/api/v1/stats")

    runner, port = await _serve(redirecting)
    try:
        code, out = await _status(monkeypatch, capsys, _write_config(tmp_path, port))
    finally:
        await runner.cleanup()
        await other.cleanup()

    assert seen == []
    assert code == 0
    assert out.splitlines()[1] == "  Its counters could not be read: HTTP 302"
    # The key goes with the one request that needs it.
    assert asked == {"/health": None, "/api/v1/stats": LOCAL_KEY}


@pytest.mark.asyncio
async def test_something_that_accepts_and_never_answers_is_not_waited_for(
    tmp_path, no_environment, monkeypatch, capsys
):
    monkeypatch.setattr(status_client, "TIMEOUT", 0.5)
    held = []

    async def silent(reader, writer):
        held.append(writer)
        await asyncio.sleep(30)

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    started = asyncio.get_running_loop().time()
    try:
        code, out = await _status(monkeypatch, capsys, _write_config(tmp_path, port))
    finally:
        for writer in held:
            writer.close()
        server.close()
    took = asyncio.get_running_loop().time() - started

    assert code == 1
    assert out.startswith(f"✗ No sensor answers at http://127.0.0.1:{port}: ")
    assert took < 10


@pytest.mark.asyncio
async def test_no_proxy_of_the_environment_is_asked(sensor, monkeypatch, capsys):
    # A proxy would be handed the request, and the local API's key with it.
    _, path, _ = sensor
    seen = []

    async def proxy(request):
        seen.append(dict(request.headers))
        return web.json_response({"status": "healthy"})

    runner, proxy_port = await _serve(proxy)
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{proxy_port}")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    try:
        code, out = await _status(monkeypatch, capsys, path)
    finally:
        await runner.cleanup()

    assert seen == []
    assert code == 0
    assert "100 delivered" in out


@pytest.mark.asyncio
async def test_what_the_sensor_did_not_count_is_not_made_up(
    sensor, monkeypatch, capsys
):
    agent, path, _ = sensor
    agent.stats = {
        "events_collected": "many",
        "events_forwarded": True,
        "delivery_state": "\x1b[31mok",
    }

    code, out = await _status(monkeypatch, capsys, path)

    assert code == 0
    assert out.splitlines()[1] == (
        "  Up ? s. Events: ? collected, ? delivered, ? dropped, ? waiting"
    )
    # Nothing of an answer is printed but numbers and the states the
    # sensor has.
    assert len(out.splitlines()) == 2
    assert "\x1b" not in out

    agent.stats = {"delivery_state": "forbidden", "delivery_since": "\x1b[2Jyesterday"}
    _, out = await _status(monkeypatch, capsys, path)
    assert out.splitlines()[2] == (
        "  NOT delivering to the data service: forbidden. See data_forwarder "
        "in GET /api/v1/components"
    )


def test_an_address_as_a_client_reaches_it(tmp_path, no_environment):
    for bind, asked in (
        ("127.0.0.1", "http://127.0.0.1:8004"),
        ("0.0.0.0", "http://127.0.0.1:8004"),
        ("::", "http://[::1]:8004"),
        ("::1", "http://[::1]:8004"),
        ("192.0.2.7", "http://192.0.2.7:8004"),
    ):
        config = load_config(_write_config(tmp_path, 8004, bind_address=bind))
        assert status_client._address(config) == asked
