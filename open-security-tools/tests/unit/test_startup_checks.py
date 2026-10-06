"""The start-up check on the API key is fatal everywhere but in development.

At start-up the service looks at its API key again and refuses one that is
missing or that contains ``test``, ``demo`` or ``default``. The refusal was
fatal when ``ENVIRONMENT`` was exactly ``production``; in ``staging``, or with
no ``ENVIRONMENT`` at all, the error was logged and the service started
(#736). The rule is the one every service shares
(``open_security_shared.environment``): only an environment that says
``development`` is a development one.
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.main as main  # noqa: E402
from app.config import Settings  # noqa: E402

WEAK = "x9f2-default-7c1e4b8a6d3f5a9c2e7b1d4f"


def start(monkeypatch, environment, key):
    """Enter the lifespan with this environment and key; return what it raises."""
    monkeypatch.setattr(main.settings, "environment", environment)
    monkeypatch.setattr(type(main.settings), "get_api_key", lambda self: key)

    async def run():
        async with main.lifespan(main.app):
            pass

    try:
        asyncio.run(run())
    except ValueError as raised:
        return raised
    return None


@pytest.mark.parametrize("environment", ["production", "staging", ""])
def test_a_weak_key_stops_the_service_outside_development(monkeypatch, environment):
    raised = start(monkeypatch, environment, WEAK)
    assert raised is not None
    assert "Insecure API key" in str(raised)
    assert WEAK not in str(raised)


@pytest.mark.parametrize("environment", ["production", "staging", ""])
def test_a_missing_key_stops_the_service_outside_development(monkeypatch, environment):
    raised = start(monkeypatch, environment, "")
    assert raised is not None and "API key is required" in str(raised)


def test_development_logs_the_problem_and_starts(monkeypatch):
    assert start(monkeypatch, "development", WEAK) is None


@pytest.mark.parametrize("environment", ["production", "staging", "", "development"])
def test_a_good_key_starts_in_any_environment(monkeypatch, environment):
    assert start(monkeypatch, environment, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") is None


@pytest.mark.parametrize(
    "environment, applies",
    [
        ("production", True),
        ("staging", True),
        (None, True),
        ("development", False),
        ("Development", False),
    ],
)
def test_the_settings_follow_the_shared_rule(monkeypatch, environment, applies):
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    if environment is not None:
        monkeypatch.setenv("ENVIRONMENT", environment)
    settings = Settings(_env_file=None)
    assert settings.production_checks_apply() is applies
    assert settings.is_development() is (not applies)
    assert not hasattr(settings, "is_production")
