"""The service URLs default to where docker-compose.yml runs the services.

Guardian's default was http://localhost:8003, a port Guardian does not
listen on, and every default named localhost, which inside the responder's
container is the responder. The defaults are now the services' addresses
in docker-compose.yml, and these tests keep the two equal.
"""

import os
import re
import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

SERVICE_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = SERVICE_ROOT.parent / "docker-compose.yml"
sys.path.insert(0, str(SERVICE_ROOT))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

from app.config import Settings  # noqa: E402

URL_VARIABLES = (
    "WILDBOX_API_URL",
    "WILDBOX_DATA_URL",
    "WILDBOX_GUARDIAN_URL",
    "WILDBOX_AGENTS_URL",
)
# Compose service -> the address its URL names.
SERVICES = {
    "WILDBOX_API_URL": "api",
    "WILDBOX_DATA_URL": "data",
    "WILDBOX_GUARDIAN_URL": "guardian",
    "WILDBOX_AGENTS_URL": "agents",
}


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())["services"]


def responder_default(compose, variable):
    """The default docker-compose.yml gives ``variable`` for the responder."""
    for entry in compose["responder"]["environment"]:
        name, _, value = entry.partition("=")
        if name == variable:
            match = re.fullmatch(r"\$\{[A-Z_]+:-([^}]+)\}", value)
            assert match, f"{variable} in docker-compose.yml has no default: {value}"
            return match.group(1)
    raise AssertionError(f"docker-compose.yml sets no {variable} for the responder")


@pytest.fixture
def no_url_overrides(monkeypatch):
    for variable in URL_VARIABLES:
        monkeypatch.delenv(variable, raising=False)


@pytest.mark.parametrize("variable", URL_VARIABLES)
def test_the_default_is_the_compose_address(compose, no_url_overrides, variable):
    settings = Settings(_env_file=None)
    assert getattr(settings, variable.lower()) == responder_default(compose, variable)


@pytest.mark.parametrize("variable", URL_VARIABLES)
def test_the_compose_address_names_the_service_and_its_port(compose, variable):
    url = responder_default(compose, variable)
    host, port = re.fullmatch(r"http://([a-z-]+):(\d+)", url).groups()
    service = compose[SERVICES[variable]]
    names = {service.get("container_name")}
    networks = service.get("networks")
    if isinstance(networks, dict):
        for config in networks.values():
            names |= set((config or {}).get("aliases") or [])
    assert host in names, f"{host} is not an address of {SERVICES[variable]}"
    published = [p.rsplit(":", 1)[-1] for p in service.get("ports", [])]
    assert port in published, f"{SERVICES[variable]} listens on {published}"


@pytest.mark.parametrize(
    "value",
    [
        "open-security-tools:8000",
        "ftp://open-security-tools",
        "http://",
        "http://h/?a=1",
    ],
)
def test_a_url_that_is_not_one_stops_the_service(monkeypatch, value):
    monkeypatch.setenv("WILDBOX_API_URL", value)
    with pytest.raises(ValidationError, match="WILDBOX_API_URL"):
        Settings(_env_file=None)


def test_a_trailing_slash_is_dropped(monkeypatch):
    monkeypatch.setenv("WILDBOX_GUARDIAN_URL", "http://guardian.internal:8013/")
    settings = Settings(_env_file=None)
    assert settings.wildbox_guardian_url == "http://guardian.internal:8013"
