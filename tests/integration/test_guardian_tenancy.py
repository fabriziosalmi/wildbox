"""Guardian keeps each team to its own data, through the gateway (#642).

Guardian stored no team: any team owner -- anyone who registers gets a team
of their own -- read, changed and deleted every other team's assets and
vulnerabilities. Two accounts are registered here, each the owner of its own
team. A stores an asset and a vulnerability on it; B does not find them in
its lists, and reading, changing or deleting them by id answers 404, as for
ids that do not exist. B cannot file a vulnerability under A's asset either.

Each test registers its own accounts directly at identity, as
test_tools_async_tasks.py does, and makes every other request through the
gateway.
"""

import os
import secrets
import uuid

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
TIMEOUT = 15

# /api/v1/guardian/<x> on the gateway is /api/v1/<x> on guardian.
GUARDIAN_API = f"{GATEWAY_URL}/api/v1/guardian"
ASSETS = f"{GUARDIAN_API}/assets/assets/"
VULNERABILITIES = f"{GUARDIAN_API}/vulnerabilities/"


def _new_owner():
    """Bearer headers of a newly registered account: the owner of its team."""
    email = f"guardian-tenancy-{secrets.token_hex(6)}@example.com"
    password = f"Guardian-Tenancy-{secrets.token_hex(8)}!"
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


def _ids(response):
    assert response.status_code == 200, response.text[:300]
    return {row["id"] for row in response.json()["results"]}


@pytest.fixture
def owners():
    return _new_owner(), _new_owner()


@pytest.fixture
def team_a_rows(owners):
    """An asset and a vulnerability on it, both team A's; removed afterwards."""
    a, _ = owners
    asset = requests.post(
        ASSETS,
        json={
            "name": f"it-tenancy-{uuid.uuid4().hex[:12]}",
            "asset_type": "server",
            "hostname": "it-tenancy.invalid",
        },
        headers=a,
        timeout=TIMEOUT,
    )
    assert asset.status_code == 201, asset.text[:300]
    asset = asset.json()
    vulnerability = requests.post(
        VULNERABILITIES,
        json={
            "title": f"it-tenancy-{uuid.uuid4().hex[:12]}",
            "description": "cross-team probe",
            "asset": asset["id"],
            "severity": "high",
            # cve_id and port complete the unique (asset, cve_id, port) key,
            # which the API requires.
            "cve_id": "CVE-2024-3094",
            "port": 22,
        },
        headers=a,
        timeout=TIMEOUT,
    )
    assert vulnerability.status_code == 201, vulnerability.text[:300]
    # The create serializer does not return the id; the list does.
    listed = requests.get(
        VULNERABILITIES,
        params={"search": vulnerability.json()["title"]},
        headers=a,
        timeout=TIMEOUT,
    )
    (vulnerability_id,) = _ids(listed)
    yield asset["id"], vulnerability_id
    requests.delete(f"{VULNERABILITIES}{vulnerability_id}/", headers=a, timeout=TIMEOUT)
    requests.delete(f"{ASSETS}{asset['id']}/", headers=a, timeout=TIMEOUT)


def test_another_team_does_not_see_or_change_the_rows(owners, team_a_rows):
    a, b = owners
    asset_id, vulnerability_id = team_a_rows

    # The owner has them.
    assert asset_id in _ids(requests.get(ASSETS, headers=a, timeout=TIMEOUT))
    assert vulnerability_id in _ids(
        requests.get(VULNERABILITIES, headers=a, timeout=TIMEOUT)
    )

    # B's lists leave them out.
    assert asset_id not in _ids(requests.get(ASSETS, headers=b, timeout=TIMEOUT))
    assert vulnerability_id not in _ids(
        requests.get(VULNERABILITIES, headers=b, timeout=TIMEOUT)
    )

    for url in (f"{ASSETS}{asset_id}/", f"{VULNERABILITIES}{vulnerability_id}/"):
        assert requests.get(url, headers=b, timeout=TIMEOUT).status_code == 404, url
        changed = requests.patch(
            url, json={"description": "b was here"}, headers=b, timeout=TIMEOUT
        )
        assert changed.status_code == 404, (url, changed.text[:200])
        assert requests.delete(url, headers=b, timeout=TIMEOUT).status_code == 404, url
        # Still there, unchanged, for A.
        mine = requests.get(url, headers=a, timeout=TIMEOUT)
        assert mine.status_code == 200, (url, mine.text[:200])
        assert mine.json()["description"] != "b was here", url


def test_another_teams_asset_cannot_be_referenced(owners, team_a_rows):
    _, b = owners
    asset_id, _ = team_a_rows

    response = requests.post(
        VULNERABILITIES,
        json={
            "title": f"it-tenancy-{uuid.uuid4().hex[:12]}",
            "description": "filed under another team's asset",
            "cve_id": "CVE-2024-3094",
            "port": 22,
            "asset": asset_id,
        },
        headers=b,
        timeout=TIMEOUT,
    )

    assert response.status_code == 400, response.text[:300]
    assert "does not exist" in str(response.json()["asset"]), response.json()
