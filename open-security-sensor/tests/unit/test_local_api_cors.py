"""The local API starts without a warning, and its CORS answers are as they
were (#765).

``aiohttp_cors.setup()`` keeps the CORS configuration in the application
under the name ``"aiohttp_cors"``, and aiohttp warns about every name that
is not a ``web.AppKey``: one NotAppKeyWarning at every start of the sensor.
Nothing in the sensor reads that entry. The API builds the same
configuration without storing it.

The API is the real one, on a port of its own, asked over HTTP.
"""

import socket
import sys
import warnings
from pathlib import Path

import aiohttp
import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.api.local_api import LocalAPI  # noqa: E402
from sensor.core.config import DataLakeConfig, NetworkConfig, SensorConfig  # noqa: E402


class Agent:
    """What /health asks of the agent."""

    running = True


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _api(port):
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        network=NetworkConfig(
            enable_api=True,
            bind_address="127.0.0.1",
            bind_port=port,
            api_key="local-api-key-0123456789abcdef",
        ),
    )
    return LocalAPI(config, agent=Agent())


@pytest.mark.asyncio
async def test_the_local_api_starts_without_a_warning():
    api = _api(_free_port())

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await api.start()
    try:
        # main: "It is recommended to use web.AppKey instances for keys."
        assert [str(warning.message) for warning in caught] == []
        assert api.running is True
    finally:
        await api.stop()


@pytest.mark.asyncio
async def test_the_api_still_answers_its_own_origin_and_no_other():
    port = _free_port()
    api = _api(port)
    own = f"http://127.0.0.1:{port}"

    await api.start()
    try:
        async with aiohttp.ClientSession() as session:

            async def allowed(origin):
                async with session.get(
                    f"{own}/health", headers={"Origin": origin}
                ) as response:
                    assert response.status == 200
                    return response.headers.get("Access-Control-Allow-Origin")

            assert await allowed(own) == own
            assert await allowed("http://elsewhere.example") is None
    finally:
        await api.stop()
