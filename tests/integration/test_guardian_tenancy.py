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


# --- a member who left the team (#676) ---------------------------------------------

IDENTITY_API = f"{GATEWAY_URL}/api/v1/identity"
GROUPS = f"{GUARDIAN_API}/assets/groups/"


def _team_of(headers):
    """The team the gateway resolves for a session."""
    response = requests.get(ASSETS, headers=headers, timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:200]
    return response.headers["X-Wildbox-Team-ID"]


def _new_admin_member(owner, team_id):
    """An account the owner creates in the team, past its first password
    change: (identity user id, bearer headers)."""
    email = f"guardian-tenancy-member-{secrets.token_hex(6)}@example.com"
    initial = f"Guardian-Member-{secrets.token_hex(8)}!"
    created = requests.post(
        f"{IDENTITY_API}/admin/teams/{team_id}/members",
        json={"email": email, "password": initial, "role": "admin"},
        headers=owner,
        timeout=TIMEOUT,
    )
    assert created.status_code == 201, created.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": initial},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    changed = requests.post(
        f"{IDENTITY_API}/admin/me/change-password",
        json={
            "current_password": initial,
            "new_password": f"Guardian-Member-{secrets.token_hex(8)}!",
        },
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        timeout=TIMEOUT,
    )
    assert changed.status_code == 200, changed.text[:200]
    return created.json()["user_id"], {
        "Authorization": f"Bearer {changed.json()['access_token']}"
    }


def _assign(owner, vulnerability_id, guardian_user_id):
    return requests.post(
        f"{VULNERABILITIES}{vulnerability_id}/assign/",
        json={"assigned_to": guardian_user_id},
        headers=owner,
        timeout=TIMEOUT,
    )


def _assignee(owner, vulnerability_id):
    response = requests.get(
        f"{VULNERABILITIES}{vulnerability_id}/", headers=owner, timeout=TIMEOUT
    )
    assert response.status_code == 200, response.text[:300]
    return response.json()["assigned_to"]


def test_a_member_removed_from_the_team_is_no_longer_one_of_its_users(
    owners, team_a_rows
):
    """identity removes a member; guardian, told by identity, refuses them.

    guardian recorded a member the first time they acted in a team and
    never forgot them: the team could go on assigning vulnerabilities to a
    member identity had removed, and its data went on naming them.
    """
    owner, _ = owners
    _, vulnerability_id = team_a_rows
    team_id = _team_of(owner)
    member_id, member = _new_admin_member(owner, team_id)

    # The member acts in the team: guardian now knows them. What they create
    # carries their guardian user id, which is what an assignment names.
    group = requests.post(
        GROUPS,
        json={"name": f"it-tenancy-{uuid.uuid4().hex[:12]}"},
        headers=member,
        timeout=TIMEOUT,
    )
    assert group.status_code == 201, group.text[:300]
    group = group.json()
    assert group["created_by_username"] == member_id
    guardian_user_id = group["created_by"]

    try:
        # While a member: accepted, and named.
        assigned = _assign(owner, vulnerability_id, guardian_user_id)
        assert assigned.status_code == 200, assigned.text[:300]
        assert _assignee(owner, vulnerability_id) == guardian_user_id

        removed = requests.delete(
            f"{IDENTITY_API}/admin/teams/{team_id}/members/{member_id}",
            headers=owner,
            timeout=TIMEOUT,
        )
        assert removed.status_code == 200, removed.text[:200]

        # At once, with no wait: identity told guardian before it answered.
        # The team's data no longer names them...
        assert _assignee(owner, vulnerability_id) is None
        # ...and they are refused as an assignee, as an id nobody has is.
        refused = _assign(owner, vulnerability_id, guardian_user_id)
        assert refused.status_code == 400, refused.text[:300]
        unknown = _assign(owner, vulnerability_id, 2**31 - 1)
        assert unknown.status_code == 400, unknown.text[:300]
        assert refused.json() == unknown.json()
        patched = requests.patch(
            f"{VULNERABILITIES}{vulnerability_id}/",
            json={"assigned_to": guardian_user_id},
            headers=owner,
            timeout=TIMEOUT,
        )
        assert patched.status_code == 400, patched.text[:300]
        assert "does not exist" in str(patched.json()["assigned_to"]), patched.json()
        assert _assignee(owner, vulnerability_id) is None

        # What they did stays on record: the group is still theirs by name.
        kept = requests.get(f"{GROUPS}{group['id']}/", headers=owner, timeout=TIMEOUT)
        assert kept.status_code == 200, kept.text[:300]
        assert kept.json()["created_by"] == guardian_user_id
    finally:
        requests.delete(f"{GROUPS}{group['id']}/", headers=owner, timeout=TIMEOUT)
