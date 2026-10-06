"""The sensor's start-up line says what it runs on, and nothing of who runs
it (#777).

The line was ``Platform: {...}``, the whole of ``get_platform_info()`` at
INFO: the system and the Python version, and with them the user's name, the
home directory and the first entries of ``PATH``; on Linux every field of
``/etc/os-release`` too. A sensor's log is shipped, attached to tickets and
read by people who have no business with the account it runs under.

``tests/scripts/test_no_request_values_in_logs.py`` guards the log lines of
the request handlers; it does not read this one. Here the line is the real
one: the daemon is started, with a stop already asked for so that it starts
nothing, and what it logged is read.
"""

import asyncio
import logging
import os
import platform
import signal
import sys
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

import main as sensor_main  # noqa: E402
from sensor.utils.platform import describe_platform, get_platform_info  # noqa: E402

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the daemon's signal handlers are the loop's"
)

# What the account and the environment are made to be: values no log line
# can hold by chance.
ACCOUNT = {
    "USER": "canary-user-5d1c",
    "USERNAME": "canary-username-5d1c",
    "LOGNAME": "canary-logname-5d1c",
    "HOME": "/canary-home-5d1c",
    "USERPROFILE": "C:\\canary-profile-5d1c",
}
PATH_ENTRY = "/canary-path-5d1c/bin"


@pytest.fixture
def handlers():
    """The process's signal handlers as they were, after the test."""
    before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    yield
    for signum, handler in before.items():
        signal.signal(signum, handler)


@pytest.fixture
def account(monkeypatch):
    for name, value in ACCOUNT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("PATH", f"{PATH_ENTRY}{os.pathsep}{os.environ['PATH']}")
    return [*ACCOUNT.values(), PATH_ENTRY]


async def _started(tmp_path, monkeypatch, caplog):
    """What a daemon logs when it starts, with a stop already asked for."""
    monkeypatch.setattr(sensor_main, "setup_logging", lambda settings: None)
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "data_lake": {"endpoint": "https://gateway.example"},
                "fim": {"enabled": False},
                "network": {"enable_api": False},
            }
        )
    )
    asked = sensor_main.StopAsked()
    load = sensor_main.load_config

    def loading(path):
        # As a SIGTERM during the reading of the configuration.
        asked._note(signal.SIGTERM, None)
        return load(path)

    monkeypatch.setattr(sensor_main, "load_config", loading)
    daemon = sensor_main.SensorDaemon(str(config), stop_asked=asked)
    with caplog.at_level(logging.DEBUG):
        assert await asyncio.wait_for(daemon.start(), timeout=10) == 0
    return [record.getMessage() for record in caplog.records]


@pytest.mark.asyncio
async def test_the_platform_line_says_what_an_operator_needs(
    handlers, account, tmp_path, monkeypatch, caplog
):
    said = await _started(tmp_path, monkeypatch, caplog)

    (line,) = [message for message in said if message.startswith("Platform:")]
    assert line == (
        f"Platform: {platform.system()} {platform.release()} "
        f"({platform.machine()}), Python {platform.python_version()}"
    )
    assert said[0].startswith("Starting Open Security Sensor v")


@pytest.mark.asyncio
async def test_no_line_of_the_start_names_the_account_or_the_environment(
    handlers, account, tmp_path, monkeypatch, caplog
):
    said = await _started(tmp_path, monkeypatch, caplog)

    assert len(said) >= 3
    # main: the user's name, the home directory and PATH were in the
    # platform line.
    leaked = [
        (value, message) for message in said for value in account if value in message
    ]
    assert leaked == []


def test_the_description_is_one_short_line(account):
    described = describe_platform()

    assert "\n" not in described and len(described) < 200
    assert not [value for value in account if value in described]


def test_what_the_sensor_keeps_about_its_platform_holds_nothing_of_the_account(
    account,
):
    # What the processor reads its `host` fields from. It held the user's
    # name, the home directory and PATH under "environment", which nothing
    # read but the log line.
    info = get_platform_info()

    assert "environment" not in info
    assert not [value for value in account if value in repr(info)]
    # What the events and the local API read is still there.
    assert info["system"] == platform.system()
    assert info["architecture"][0]
