"""The local API says nothing about origins (#765, #777).

It had a CORS layer that allowed one origin: the API's own bind address and
port, ``http://127.0.0.1:8004``, or ``http://0.0.0.0:8004`` in the container,
where it binds every address. A page the API serves itself has that origin
and needs no permission to call it. Any other page with that origin is served
by whatever else answers on that address of the browser's own machine, and it
was given the API's answers, with credentials: the only thing the layer ever
allowed is the thing it should not have. It is gone, and ``aiohttp-cors``
with it.

What a browser needs in order to let a page of another origin read an answer
is an ``Access-Control-Allow-Origin`` header naming it, and for a request
with the API key in a header a preflight answered with one. The API sends
neither now, for any origin, on any address the sensor's configurations bind.
The requests themselves are answered as they were: CORS never kept a request
from the server, it only told the browser who may read the answer.

The API is the real one, on a port of its own, asked over HTTP.
"""

import socket
import sys
import warnings
from pathlib import Path

import aiohttp
import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.api.local_api import LocalAPI  # noqa: E402
from sensor.core.config import DataLakeConfig, NetworkConfig, SensorConfig  # noqa: E402

LOCAL_KEY = "local-api-key-0123456789abcdef"
# The configurations the sensor ships with.
CONFIGURATIONS = ("config.yaml", "config.docker.yaml", "config.yaml.example")


def _bind_addresses():
    """Every address the sensor's configurations bind the API to, and the
    one it binds without a configuration."""
    addresses = {NetworkConfig().bind_address}
    for name in CONFIGURATIONS:
        settings = yaml.safe_load((SERVICE_ROOT / name).read_text())
        addresses.add(settings["network"]["bind_address"])
    return sorted(addresses)


class Agent:
    """What /health and /api/v1/status ask of the agent."""

    running = True

    def get_status(self):
        return {"running": True}


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _api(port, bind_address="127.0.0.1"):
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        network=NetworkConfig(
            enable_api=True,
            bind_address=bind_address,
            bind_port=port,
            api_key=LOCAL_KEY,
        ),
    )
    return LocalAPI(config, agent=Agent())


def _about_origins(response):
    return {
        name: value
        for name, value in response.headers.items()
        if name.lower().startswith("access-control-")
    }


@pytest.mark.asyncio
async def test_the_local_api_starts_without_a_warning():
    api = _api(_free_port())

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await api.start()
    try:
        # #765: "It is recommended to use web.AppKey instances for keys."
        assert [str(warning.message) for warning in caught] == []
        assert api.running is True
    finally:
        await api.stop()


def test_the_addresses_tested_are_the_ones_the_configurations_bind():
    addresses = _bind_addresses()

    # The loopback address, and every address (the container's): if a
    # configuration begins to bind another, it is tested below without
    # being named here.
    assert len(addresses) == 2
    assert NetworkConfig().bind_address in addresses


@pytest.mark.parametrize("bind_address", _bind_addresses())
@pytest.mark.asyncio
async def test_no_origin_is_told_it_may_read_an_answer(bind_address):
    port = _free_port()
    api = _api(port, bind_address)
    url = f"http://127.0.0.1:{port}"
    origins = [
        # The one main allowed: the API's own bind address and port.
        f"http://{bind_address}:{port}",
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
        "http://elsewhere.example",
        "null",
    ]
    answers = {}

    await api.start()
    try:
        async with aiohttp.ClientSession() as session:
            for origin in origins:
                for path, key in (
                    ("/health", None),
                    ("/api/v1/status", None),
                    ("/api/v1/status", LOCAL_KEY),
                ):
                    headers = {"Origin": origin}
                    if key:
                        headers["X-API-Key"] = key
                    async with session.get(url + path, headers=headers) as response:
                        answers[origin, path, bool(key)] = (
                            response.status,
                            _about_origins(response),
                        )
    finally:
        await api.stop()

    for origin in origins:
        # Answered as it always was, with or without an Origin...
        assert answers[origin, "/health", False][0] == 200
        assert answers[origin, "/api/v1/status", False][0] == 401
        assert answers[origin, "/api/v1/status", True][0] == 200
    # ... and no browser is told that a page may read the answer. main:
    # the first origin got Access-Control-Allow-Origin with its own name
    # and Access-Control-Allow-Credentials: true.
    assert {key: about for key, (_, about) in answers.items() if about} == {}


@pytest.mark.parametrize("bind_address", _bind_addresses())
@pytest.mark.asyncio
async def test_no_preflight_is_granted(bind_address):
    # A page of another origin cannot send the API key without asking
    # first: a request with X-API-Key or Authorization is preflighted, and a
    # preflight that is not granted ends it in the browser.
    port = _free_port()
    api = _api(port, bind_address)
    origins = [
        f"http://{bind_address}:{port}",
        f"http://127.0.0.1:{port}",
        "http://elsewhere.example",
    ]
    answers = {}

    await api.start()
    try:
        async with aiohttp.ClientSession() as session:
            for origin in origins:
                for path, method in (("/api/v1/status", "GET"), ("/api/v1/query", "POST")):
                    async with session.options(
                        f"http://127.0.0.1:{port}{path}",
                        headers={
                            "Origin": origin,
                            "Access-Control-Request-Method": method,
                            "Access-Control-Request-Headers": "x-api-key",
                        },
                    ) as response:
                        answers[origin, path] = (
                            response.status,
                            _about_origins(response),
                        )
    finally:
        await api.stop()

    # main: 200 for the first origin, with Access-Control-Allow-Origin,
    # -Credentials, -Methods and -Headers; 403 for the others. Now the API
    # has no OPTIONS route at all.
    assert len(answers) == 2 * len(set(origins))
    assert [answer for answer in answers.values() if answer != (405, {})] == []


def test_nothing_of_the_sensor_imports_the_cors_package():
    # That it is no longer required is in test_packaging.py.
    sources = [SERVICE_ROOT / "main.py", *(SERVICE_ROOT / "sensor").rglob("*.py")]

    assert len(sources) > 10
    assert [str(path) for path in sources if "aiohttp_cors" in path.read_text()] == []
