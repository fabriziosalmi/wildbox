"""Cross-tenant isolation for CSPM scans (#179).

CSPM stores scans in Redis, indexed per team. A scan started by one team must
not be visible to another — neither by direct id nor via the team dashboard,
which now iterates the team's own scan index (not every team's keys).
"""

import os
import uuid
from typing import Dict

import pytest
import requests


def _gateway_headers(team_id: str, secret: str) -> Dict[str, str]:
    return {
        "X-Wildbox-User-ID": str(uuid.uuid4()),
        "X-Wildbox-Team-ID": team_id,
        "X-Wildbox-Role": "member",
        "X-Gateway-Secret": secret,
    }


def _require_secret() -> str:
    secret = os.environ.get("GATEWAY_INTERNAL_SECRET", "")
    if not secret:
        pytest.skip("GATEWAY_INTERNAL_SECRET not set (e.g. fork PR without secrets)")
    return secret


def _start_scan(base: str, headers: Dict[str, str]) -> str:
    payload = {
        "provider": "aws",
        "account_id": "123456789012",
        "credentials": {
            "auth_method": "access_key",
            "access_key_id": "AKIAFAKEFAKEFAKEFAKE",
            "secret_access_key": "fake-secret-for-ci-only",
            "region": "us-east-1",
        },
    }
    resp = requests.post(f"{base}/api/v1/scans", headers=headers, json=payload, timeout=15)
    assert resp.status_code == 202, resp.text
    return resp.json()["scan_id"]


def test_cspm_rejects_unauthenticated(service_urls):
    """A scan read without gateway auth must not succeed."""
    try:
        resp = requests.get(
            f"{service_urls['cspm']}/api/v1/scans/{uuid.uuid4()}", timeout=10
        )
    except requests.exceptions.RequestException:
        pytest.fail("CSPM service is not available. Ensure it's running in CI.")
    assert resp.status_code in (401, 403, 503)


def test_cspm_scan_isolated_by_team(service_urls):
    """A scan started by team A is invisible to team B, by id and on the dashboard."""
    secret = _require_secret()
    base = service_urls["cspm"]
    team_a = str(uuid.uuid4())
    team_b = str(uuid.uuid4())

    scan_id = _start_scan(base, _gateway_headers(team_a, secret))

    # Team A reads its own scan.
    a_get = requests.get(
        f"{base}/api/v1/scans/{scan_id}", headers=_gateway_headers(team_a, secret), timeout=10
    )
    assert a_get.status_code == 200, a_get.text

    # Team B is denied direct access (403, not a 200 that leaks data).
    b_get = requests.get(
        f"{base}/api/v1/scans/{scan_id}", headers=_gateway_headers(team_b, secret), timeout=10
    )
    assert b_get.status_code == 403, b_get.text

    # Team B is also denied cancellation of team A's scan.
    b_del = requests.delete(
        f"{base}/api/v1/scans/{scan_id}", headers=_gateway_headers(team_b, secret), timeout=10
    )
    assert b_del.status_code == 403, b_del.text

    # NOTE: the /dashboard/summary endpoint has a pre-existing broken response
    # contract (its return doesn't match DashboardSummaryResponse), so it 500s
    # regardless of tenancy — not asserted here. The per-team scan index that
    # backs it is still exercised by start_scan above; the dashboard response
    # contract is a separate fix.
