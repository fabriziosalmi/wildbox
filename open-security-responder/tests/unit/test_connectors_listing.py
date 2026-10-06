"""GET /v1/connectors lists names and actions, not internal addresses (#654).

Any member of any team can call it. It answered each connector's
``config``: the WILDBOX_*_URL addresses of the other services on the
internal network, which the caller cannot reach and which describe how the
deployment is laid out.
"""

import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

import app.main as main_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.connectors import connector_registry  # noqa: E402

SERVICE_URL_SETTINGS = (
    "wildbox_api_url",
    "wildbox_data_url",
    "wildbox_guardian_url",
    "wildbox_agents_url",
    "redis_url",
)


def listing(role):
    response = TestClient(main_module.app).get(
        "/v1/connectors",
        headers={
            "X-Wildbox-User-ID": str(uuid.uuid4()),
            "X-Wildbox-Team-ID": str(uuid.uuid4()),
            "X-Wildbox-Role": role,
            "X-Gateway-Secret": os.environ["GATEWAY_INTERNAL_SECRET"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_the_registry_holds_the_addresses_this_test_looks_for():
    """Otherwise the tests below would pass with nothing to leak."""
    held = json.dumps(
        {
            name: connector_registry.get_connector(name).config
            for name in ("wildbox", "data", "api")
        }
    )
    for name in ("wildbox_api_url", "wildbox_data_url", "wildbox_guardian_url"):
        assert getattr(settings, name) in held


@pytest.mark.parametrize("role", ["viewer", "member", "admin", "owner"])
def test_the_listing_carries_no_service_address(role):
    text = json.dumps(listing(role))
    for name in SERVICE_URL_SETTINGS:
        assert getattr(settings, name) not in text, f"{name} is in the listing"
    assert "http://" not in text and "https://" not in text
    assert "open-security-" not in text


@pytest.mark.parametrize("role", ["viewer", "member", "admin", "owner"])
def test_each_connector_is_its_name_and_its_actions(role):
    body = listing(role)
    assert set(body["connectors"]) == {"system", "wildbox", "data", "api"}
    assert body["total"] == 4
    for name, connector in body["connectors"].items():
        assert set(connector) == {"name", "actions"}
        assert connector["name"] == name
        assert connector["actions"] == (
            connector_registry.get_connector(name).get_available_actions()
        )


def test_the_listing_requires_a_gateway_caller():
    response = TestClient(main_module.app).get("/v1/connectors")
    assert response.status_code == 403, response.text
