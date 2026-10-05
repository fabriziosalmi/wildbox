"""The responder's answers name nothing a client cannot reach (#654).

On the running stack, through the gateway:

- the ``status_url`` of a started run, appended to the address the client
  called, is the run. It was the responder's own ``/v1/runs/{id}``, which the
  gateway routes to the dashboard;
- the connector listing has the connectors' names and actions and none of
  the internal service addresses it used to print for any member.

simple_notification only logs, so nothing here depends on another service.
"""

import os
import secrets

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
RESPONDER = f"{GATEWAY_URL}/api/v1/responder"
TIMEOUT = 15


def new_token():
    email = f"responder-urls-{secrets.token_hex(6)}@example.com"
    password = f"Responder-Urls-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    return login.json()["access_token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_status_url_leads_to_the_run_through_the_gateway():
    token = new_token()
    started = requests.post(
        f"{RESPONDER}/playbooks/simple_notification/execute",
        json={"trigger_data": {"message": "status_url"}},
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert started.status_code == 202, started.text[:300]
    body = started.json()
    status_url = body["status_url"]
    assert status_url == f"/api/v1/responder/runs/{body['run_id']}"

    # The client follows it against the address it called, and nothing else.
    run = requests.get(
        f"{GATEWAY_URL}{status_url}",
        headers=bearer(token),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    assert run.status_code == 200, run.text[:300]
    assert run.headers["content-type"].startswith("application/json")
    assert run.json()["run_id"] == body["run_id"]
    assert run.json()["playbook_id"] == "simple_notification"

    # Somebody else following the same URL is told the run does not exist.
    other = requests.get(
        f"{GATEWAY_URL}{status_url}", headers=bearer(new_token()), timeout=TIMEOUT
    )
    assert other.status_code == 404, other.text[:300]


def test_the_connector_listing_names_no_internal_address():
    listed = requests.get(
        f"{RESPONDER}/connectors", headers=bearer(new_token()), timeout=TIMEOUT
    )
    assert listed.status_code == 200, listed.text[:300]
    connectors = listed.json()["connectors"]
    assert {"system", "wildbox", "data", "api"} <= set(connectors)
    for name, connector in connectors.items():
        assert set(connector) == {"name", "actions"}, name
        assert connector["actions"], name
    assert "http://" not in listed.text
    assert "open-security-" not in listed.text
