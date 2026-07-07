"""Cross-tenant isolation for the responder run history (#180).

Responder stores run state in Redis (not SQL). Each run is owned by the team
that triggered it; another team must not be able to read or cancel it. These
tests execute a real bundled playbook as "team A" and assert "team B" gets 404
for the same run id.
"""

import os
import uuid
from typing import Dict

import pytest
import requests


def _gateway_headers(team_id: str, secret: str, role: str = "member") -> Dict[str, str]:
    return {
        "X-Wildbox-User-ID": str(uuid.uuid4()),
        "X-Wildbox-Team-ID": team_id,
        "X-Wildbox-Role": role,
        "X-Gateway-Secret": secret,
    }


def _require_secret() -> str:
    secret = os.environ.get("GATEWAY_INTERNAL_SECRET", "")
    if not secret:
        pytest.skip("GATEWAY_INTERNAL_SECRET not set (e.g. fork PR without secrets)")
    return secret


def test_responder_runs_reject_unauthenticated(service_urls):
    """Reading a run without gateway auth must not succeed."""
    try:
        resp = requests.get(
            f"{service_urls['responder']}/v1/runs/{uuid.uuid4()}", timeout=10
        )
    except requests.exceptions.RequestException:
        pytest.fail("Responder service is not available. Ensure it's running in CI.")
    assert resp.status_code in (401, 403, 503)


def test_responder_run_not_readable_by_other_team(service_urls):
    """A run created by team A returns 404 to team B (no cross-tenant leak)."""
    secret = _require_secret()
    base = service_urls["responder"]
    team_a = str(uuid.uuid4())
    team_b = str(uuid.uuid4())

    # Pick any bundled playbook to execute.
    pb_resp = requests.get(
        f"{base}/v1/playbooks", headers=_gateway_headers(team_a, secret), timeout=10
    )
    assert pb_resp.status_code == 200, pb_resp.text
    playbooks = pb_resp.json().get("playbooks", [])
    if not playbooks:
        pytest.skip("No bundled playbooks available to execute")
    playbook_id = playbooks[0].get("playbook_id") or playbooks[0].get("id")
    assert playbook_id, f"Could not determine a playbook id from {playbooks[0]}"

    # Team A starts a run.
    exec_resp = requests.post(
        f"{base}/v1/playbooks/{playbook_id}/execute",
        headers=_gateway_headers(team_a, secret),
        json={},
        timeout=10,
    )
    assert exec_resp.status_code == 202, exec_resp.text
    run_id = exec_resp.json()["run_id"]

    # Team A can read its own run (state is persisted synchronously as QUEUED).
    a_resp = requests.get(
        f"{base}/v1/runs/{run_id}", headers=_gateway_headers(team_a, secret), timeout=10
    )
    assert a_resp.status_code == 200, a_resp.text

    # Team B must NOT see it — 404, indistinguishable from "not found".
    b_resp = requests.get(
        f"{base}/v1/runs/{run_id}", headers=_gateway_headers(team_b, secret), timeout=10
    )
    assert b_resp.status_code == 404, b_resp.text

    # Team B must NOT be able to cancel it either.
    b_del = requests.delete(
        f"{base}/v1/runs/{run_id}", headers=_gateway_headers(team_b, secret), timeout=10
    )
    assert b_del.status_code == 404, b_del.text


def test_responder_reload_requires_admin_role(service_urls):
    """#182 policy: configuration mutations require owner/admin. Reloading
    playbook definitions from disk is config, so a member is denied (403) and an
    admin is allowed (200). Operational mutations (execute/cancel) stay member-
    allowed and are covered by the tenancy tests above."""
    secret = _require_secret()
    base = service_urls["responder"]
    team = str(uuid.uuid4())

    member = requests.post(
        f"{base}/v1/playbooks/reload",
        headers=_gateway_headers(team, secret, role="member"),
        timeout=10,
    )
    assert member.status_code == 403, member.text

    admin = requests.post(
        f"{base}/v1/playbooks/reload",
        headers=_gateway_headers(team, secret, role="admin"),
        timeout=10,
    )
    assert admin.status_code == 200, admin.text
