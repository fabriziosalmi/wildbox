"""The standalone Compose files give the service no API key it refuses (#665).

``docker-compose.yml`` and ``docker-compose.dev.yml`` in this directory set
``API_KEY`` to a placeholder when the variable was not set:
``your-secure-api-key-here-change-this`` and ``dev-api-key-change-this``. The
settings refuse both (a weak pattern; fewer than 32 characters), so
``docker compose up`` built the image and the API exited at once.

The variable is required now. Whatever a file gives the service when the
operator sets nothing has to be a key the service accepts, or no key at all,
with Compose saying that one is needed.
"""

import os
import re
import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.config import Settings  # noqa: E402

SERVICE_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.dev.yml")

_REQUIRED = re.compile(r"^\$\{API_KEY:?\?.*\}$")
_DEFAULTED = re.compile(r"^\$\{API_KEY:?-(.*)\}$")


def api_keys(compose_file):
    """(service, the value its ``API_KEY`` is given) for each service that gets one."""
    compose = yaml.safe_load((SERVICE_ROOT / compose_file).read_text(encoding="utf-8"))
    found = []
    for name, service in compose["services"].items():
        environment = service.get("environment") or []
        if isinstance(environment, dict):
            environment = [f"{key}={value}" for key, value in environment.items()]
        for entry in environment:
            key, _, value = str(entry).partition("=")
            if key == "API_KEY":
                found.append((name, value))
    return found


def refused(value):
    """Why the settings refuse ``value`` as the API key, or None."""
    try:
        Settings(_env_file=None, api_key=value)
    except ValidationError as error:
        return str(error)
    return None


def test_the_settings_refuse_the_placeholders_the_files_used_to_default_to():
    assert "weak pattern" in refused("your-secure-api-key-here-change-this")
    assert "at least 32 characters" in refused("dev-api-key-change-this")
    assert refused("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") is None


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_the_file_requires_a_key_or_defaults_to_one_the_service_accepts(compose_file):
    keys = api_keys(compose_file)
    assert keys, f"{compose_file} passes no API_KEY: this test reads nothing"
    for service, value in keys:
        if _REQUIRED.match(value):
            continue
        defaulted = _DEFAULTED.match(value)
        literal = defaulted.group(1) if defaulted else value
        assert refused(literal) is None, (
            f"{compose_file}: {service} starts with an API_KEY the service "
            "refuses when the operator sets none. Require the variable "
            "(${API_KEY:?...}) instead of defaulting it."
        )
