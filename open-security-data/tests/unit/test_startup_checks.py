"""The data service's start-up checks apply everywhere but in development.

``AppConfig`` refuses to start without ``SECRET_KEY`` and ``DATABASE_URL``,
or with ``DEBUG`` on. It did so when ``ENVIRONMENT`` was exactly
``production``: a deployment called ``staging``, one whose ``.env`` said
``Production``, or one that set no ``ENVIRONMENT`` at all started without
them (#736). The rule is the one every service shares
(``open_security_shared.environment``): only an environment that says
``development`` is a development one.

The configuration is built when ``app.config`` is imported, from the
environment of that moment, so each case imports it in a fresh interpreter.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]

COMPLETE = {
    "SECRET_KEY": "x" * 40,
    "DATABASE_URL": "postgresql://test:test@localhost:5432/test",
    "DEBUG": "false",
}
SETTINGS = ("ENVIRONMENT", "SECRET_KEY", "DATABASE_URL", "DEBUG")

# Everything that is not the word "development".
NOT_DEVELOPMENT = ["production", "Production", "staging", "prod", "dev", "", None]


def start(environment, tmp_path, **settings):
    """Import app.config under ``environment``; return the finished process.

    ``None`` leaves ENVIRONMENT out, as a bare `docker run` does.
    """
    env = {key: value for key, value in os.environ.items() if key not in SETTINGS}
    env.update(settings)
    if environment is not None:
        env["ENVIRONMENT"] = environment
    return subprocess.run(
        [sys.executable, "-c", "import app.config"],
        cwd=SERVICE_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.mark.parametrize("environment", NOT_DEVELOPMENT)
def test_no_secret_key_is_refused_outside_development(environment, tmp_path):
    settings = {k: v for k, v in COMPLETE.items() if k != "SECRET_KEY"}
    result = start(environment, tmp_path, **settings)
    assert result.returncode != 0
    assert "SECRET_KEY must be set unless ENVIRONMENT=development" in result.stderr


@pytest.mark.parametrize("environment", NOT_DEVELOPMENT)
def test_no_database_url_is_refused_outside_development(environment, tmp_path):
    settings = {k: v for k, v in COMPLETE.items() if k != "DATABASE_URL"}
    result = start(environment, tmp_path, **settings)
    assert result.returncode != 0
    assert "DATABASE_URL must be set unless ENVIRONMENT=development" in result.stderr


@pytest.mark.parametrize("environment", NOT_DEVELOPMENT)
def test_debug_is_refused_outside_development(environment, tmp_path):
    result = start(environment, tmp_path, **{**COMPLETE, "DEBUG": "true"})
    assert result.returncode != 0
    assert "DEBUG must be False unless ENVIRONMENT=development" in result.stderr


@pytest.mark.parametrize("environment", NOT_DEVELOPMENT)
def test_a_complete_configuration_starts_in_any_environment(environment, tmp_path):
    result = start(environment, tmp_path, **COMPLETE)
    assert result.returncode == 0, result.stderr[-2000:]


@pytest.mark.parametrize("environment", ["development", "Development", " development "])
def test_development_may_start_without_them_and_with_debug(environment, tmp_path):
    result = start(environment, tmp_path, DEBUG="true")
    assert result.returncode == 0, result.stderr[-2000:]
