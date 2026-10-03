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


# AWS, with an access key id AWS could never issue: cspm-worker runs every
# scan (#601), and its session factory refuses this key before creating any
# boto3 session, so these fail at once without calling AWS (#612). With
# well-formed fake keys the worker would send each scan's checks to AWS from
# CI and stay busy for the other tests. GCP, used before, is now refused at
# submit time.
CREDENTIALS = {
    "auth_method": "access_key",
    "access_key_id": "not-an-aws-key",
    "secret_access_key": "not-a-secret",
}


def _start_scan(base: str, headers: Dict[str, str]) -> str:
    payload = {
        "provider": "aws",
        "account_id": "wildbox-ci-account",
        "credentials": CREDENTIALS,
    }
    resp = requests.post(
        f"{base}/api/v1/scans", headers=headers, json=payload, timeout=15
    )
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
        f"{base}/api/v1/scans/{scan_id}",
        headers=_gateway_headers(team_a, secret),
        timeout=10,
    )
    assert a_get.status_code == 200, a_get.text

    # Team B is denied direct access (403, not a 200 that leaks data).
    b_get = requests.get(
        f"{base}/api/v1/scans/{scan_id}",
        headers=_gateway_headers(team_b, secret),
        timeout=10,
    )
    assert b_get.status_code == 403, b_get.text

    # Team B is also denied cancellation of team A's scan.
    b_del = requests.delete(
        f"{base}/api/v1/scans/{scan_id}",
        headers=_gateway_headers(team_b, secret),
        timeout=10,
    )
    assert b_del.status_code == 403, b_del.text

    # Team A's dashboard counts the scan; team B's does not (per-team index).
    a_dash = requests.get(
        f"{base}/api/v1/dashboard/summary",
        headers=_gateway_headers(team_a, secret),
        timeout=10,
    )
    assert a_dash.status_code == 200, a_dash.text
    assert a_dash.json()["total_scans"] >= 1

    b_dash = requests.get(
        f"{base}/api/v1/dashboard/summary",
        headers=_gateway_headers(team_b, secret),
        timeout=10,
    )
    assert b_dash.status_code == 200, b_dash.text
    assert b_dash.json()["total_scans"] == 0


def test_cspm_batch_scans_are_recorded_for_their_team(service_urls):
    """Batch scans count for the team that started them, and only for it (#591).

    The batch path wrote no scan metadata, so its scans were "not found" by
    id and never counted on the dashboard. Each scan of a batch now goes
    through the single-scan path. A team id in a scan's request metadata
    does not move the scan to that team.
    """
    secret = _require_secret()
    base = service_urls["cspm"]
    team_a = str(uuid.uuid4())
    team_b = str(uuid.uuid4())

    scans = [
        {
            "provider": "aws",
            "account_id": account_id,
            "metadata": metadata,
            "credentials": CREDENTIALS,
        }
        for account_id, metadata in (
            ("ci-account-1", {}),
            ("ci-account-2", {"team_id": team_b}),
        )
    ]
    resp = requests.post(
        f"{base}/api/v1/batch/scans",
        headers=_gateway_headers(team_a, secret),
        json={"scans": scans},
        timeout=15,
    )
    assert resp.status_code == 200, resp.text
    scan_ids = [scan["scan_id"] for scan in resp.json()["scans"]]
    assert len(scan_ids) == 2

    for scan_id in scan_ids:
        a_get = requests.get(
            f"{base}/api/v1/scans/{scan_id}",
            headers=_gateway_headers(team_a, secret),
            timeout=10,
        )
        assert a_get.status_code == 200, a_get.text
        b_get = requests.get(
            f"{base}/api/v1/scans/{scan_id}",
            headers=_gateway_headers(team_b, secret),
            timeout=10,
        )
        assert b_get.status_code == 403, b_get.text

    a_dash = requests.get(
        f"{base}/api/v1/dashboard/summary",
        headers=_gateway_headers(team_a, secret),
        timeout=10,
    )
    assert a_dash.status_code == 200, a_dash.text
    assert a_dash.json()["total_scans"] == 2

    b_dash = requests.get(
        f"{base}/api/v1/dashboard/summary",
        headers=_gateway_headers(team_b, secret),
        timeout=10,
    )
    assert b_dash.status_code == 200, b_dash.text
    assert b_dash.json()["total_scans"] == 0


def test_cspm_refuses_providers_it_cannot_scan(service_urls):
    """GCP and Azure are refused at submit time and leave no scan (#612).

    A batch naming one is refused whole: its AWS scan is not started either.
    """
    secret = _require_secret()
    base = service_urls["cspm"]
    headers = _gateway_headers(str(uuid.uuid4()), secret)
    aws = {"provider": "aws", "account_id": "ci-account", "credentials": CREDENTIALS}
    gcp = {
        "provider": "gcp",
        "account_id": "ci-project",
        "credentials": {"auth_method": "service_account", "project_id": "ci-project"},
    }
    azure = {
        "provider": "azure",
        "account_id": "ci-subscription",
        "credentials": {
            "auth_method": "client_secret",
            "tenant_id": "ci-tenant",
            "client_id": "ci-client",
            "subscription_id": "ci-subscription",
        },
    }

    for scan in (gcp, azure):
        single = requests.post(
            f"{base}/api/v1/scans", headers=headers, json=scan, timeout=15
        )
        assert single.status_code == 400, single.text
        assert "Supported providers: aws" in single.text, single.text
        batch = requests.post(
            f"{base}/api/v1/batch/scans",
            headers=headers,
            json={"scans": [aws, scan]},
            timeout=15,
        )
        assert batch.status_code == 400, batch.text

    dash = requests.get(f"{base}/api/v1/dashboard/summary", headers=headers, timeout=10)
    assert dash.status_code == 200, dash.text
    assert dash.json()["total_scans"] == 0

    listed = requests.get(f"{base}/api/v1/providers", headers=headers, timeout=10)
    assert listed.status_code == 200, listed.text
    assert [p["provider"] for p in listed.json()["providers"]] == ["aws"]
