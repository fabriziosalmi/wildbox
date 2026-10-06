"""A playbook's Guardian actions get Guardian's answer, on the running stack (#707).

Every playbook action that calls Guardian was answered ``301 Moved
Permanently``: the responder's connectors call Guardian over plain HTTP on
the internal network, without the ``X-Forwarded-Proto: https`` the gateway
sends, and Guardian (DEBUG off) redirects such a request to ``https://`` on
a port where nothing speaks TLS. The unit tests' stand-in did not model the
redirect, and no integration test ran a Guardian action, so nothing failed.

This test does: a newly registered owner stores an asset and a vulnerability
on it in Guardian through the gateway, then starts the shipped
``asset_vulnerabilities`` playbook through the gateway with that asset's id.
The run must complete, and its steps must hold what Guardian holds: the
asset by its name, and the vulnerability by its title. A user of another
team who runs the playbook for the same asset is told by Guardian that it
does not exist, and the run fails without listing anything.

The playbook reaches Guardian only, so nothing here depends on the runner's
egress. Each request is sent once; only the run's status is polled.
"""

import os
import secrets
import time
import uuid

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
RESPONDER = f"{GATEWAY_URL}/api/v1/responder"
GUARDIAN_API = f"{GATEWAY_URL}/api/v1/guardian"
ASSETS = f"{GUARDIAN_API}/assets/assets/"
VULNERABILITIES = f"{GUARDIAN_API}/vulnerabilities/"
TIMEOUT = 15
# Long enough for a worker that is busy with other tests' work.
FINISH_WITHIN = 120


def new_owner():
    """Bearer headers of a newly registered account: the owner of its team."""
    email = f"responder-guardian-{secrets.token_hex(6)}@example.com"
    password = f"Responder-Guardian-{secrets.token_hex(8)}!"
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
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


@pytest.fixture
def owners():
    return new_owner(), new_owner()


@pytest.fixture
def team_a_asset(owners):
    """An asset and a vulnerability on it, both team A's; removed afterwards."""
    a, _ = owners
    marker = f"it-responder-{uuid.uuid4().hex[:12]}"
    asset = requests.post(
        ASSETS,
        json={
            "name": marker,
            "asset_type": "server",
            "hostname": "it-responder.invalid",
        },
        headers=a,
        timeout=TIMEOUT,
    )
    assert asset.status_code == 201, asset.text[:300]
    asset_id = asset.json()["id"]
    title = f"{marker} OpenSSH regreSSHion"
    created = requests.post(
        VULNERABILITIES,
        json={
            "title": title,
            "description": "playbook probe",
            "asset": asset_id,
            "severity": "high",
            # cve_id and port complete the unique (asset, cve_id, port) key.
            "cve_id": "CVE-2024-6387",
            "port": 22,
        },
        headers=a,
        timeout=TIMEOUT,
    )
    assert created.status_code == 201, created.text[:300]
    yield asset_id, marker, title
    listed = requests.get(
        VULNERABILITIES, params={"search": marker}, headers=a, timeout=TIMEOUT
    )
    for row in listed.json().get("results", []):
        requests.delete(f"{VULNERABILITIES}{row['id']}/", headers=a, timeout=TIMEOUT)
    requests.delete(f"{ASSETS}{asset_id}/", headers=a, timeout=TIMEOUT)


def run_playbook(headers, asset_id):
    """Start asset_vulnerabilities through the gateway; return the ended run."""
    started = requests.post(
        f"{RESPONDER}/playbooks/asset_vulnerabilities/execute",
        json={"trigger_data": {"asset_id": asset_id}},
        headers=headers,
        timeout=TIMEOUT,
    )
    assert started.status_code == 202, started.text[:300]
    run_id = started.json()["run_id"]
    deadline = time.monotonic() + FINISH_WITHIN
    while True:
        response = requests.get(
            f"{RESPONDER}/runs/{run_id}", headers=headers, timeout=TIMEOUT
        )
        assert response.status_code == 200, response.text[:300]
        run = response.json()
        if run["status"] in ("completed", "failed", "cancelled"):
            return run
        assert time.monotonic() < deadline, f"still unfinished: {run['status']}"
        time.sleep(1)


def test_a_playbooks_guardian_actions_return_what_guardian_holds(owners, team_a_asset):
    a, _ = owners
    asset_id, marker, title = team_a_asset

    run = run_playbook(a, asset_id)

    # Not a redirect, not an error: Guardian's own records, in the steps.
    assert run["status"] == "completed", (run.get("error"), run.get("logs"))
    assert "301" not in str(run.get("error"))
    read_asset, listed, report = run["step_results"]
    assert read_asset["status"] == "completed", read_asset
    assert read_asset["output"]["id"] == asset_id
    assert read_asset["output"]["name"] == marker
    assert listed["status"] == "completed", listed
    assert listed["output"]["count"] == 1
    [vulnerability] = listed["output"]["results"]
    assert vulnerability["title"] == title
    assert vulnerability["cve_id"] == "CVE-2024-6387"
    assert report["output"]["data"]["asset_name"] == marker
    assert report["output"]["data"]["titles"] == title

    # Which is what the same user gets from Guardian through the gateway.
    direct = requests.get(
        VULNERABILITIES, params={"asset_id": asset_id}, headers=a, timeout=TIMEOUT
    )
    assert direct.status_code == 200, direct.text[:300]
    assert [row["title"] for row in direct.json()["results"]] == [title]


def test_another_teams_run_gets_guardians_refusal_not_the_asset(owners, team_a_asset):
    """The run acts for the user who started it: Guardian answers that user,
    for whom the asset does not exist. A 404 from Guardian, not a 301."""
    _, b = owners
    asset_id, marker, title = team_a_asset

    run = run_playbook(b, asset_id)

    assert run["status"] == "failed", run
    # The status where the connector writes it ("GET <path> answered 404:
    # ..."), not anywhere in the text: the message names the asset twice by
    # its id, a random UUID, in which "301" or "404" can appear. Once in a
    # few hundred runs one did, and `"301" not in run["error"]` failed on a
    # correct answer (#766).
    assert "answered 404" in run["error"], run["error"]
    assert "answered 301" not in run["error"], run["error"]
    assert marker not in str(run) and title not in str(run)
    assert [step["step_name"] for step in run["step_results"]] == ["read_asset"]
