"""Integration checks for the data service's team-scoped, gateway-authenticated
read path (#178).

These exercise the auth + tenancy code path end-to-end against the running
service. They do NOT prove cross-tenant isolation by seeding two teams' data —
that fuller test (DB seeding) is tracked in #183.
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


def test_data_search_rejects_unauthenticated(service_urls):
    """Without gateway headers the data search must not return data."""
    try:
        resp = requests.get(
            f"{service_urls['data']}/api/v1/indicators/search", timeout=10
        )
    except requests.exceptions.RequestException:
        pytest.fail("Data service is not available. Ensure it's running in CI.")
    # 401 (no identity headers), 403 (missing/invalid gateway secret) or
    # 503 (secret not configured) — never 200.
    assert resp.status_code in (401, 403, 503)


def test_data_search_team_scoped_ok(service_urls):
    """With valid gateway headers + secret the team-scoped query runs (200)."""
    secret = os.environ.get("GATEWAY_INTERNAL_SECRET", "")
    if not secret:
        pytest.skip("GATEWAY_INTERNAL_SECRET not set (e.g. fork PR without secrets)")

    resp = requests.get(
        f"{service_urls['data']}/api/v1/indicators/search",
        params={"q": "zzz-no-such-indicator"},
        headers=_gateway_headers(str(uuid.uuid4()), secret),
        timeout=10,
    )
    # The scoped query (team rows + global NULL rows) executes; a fresh CI DB
    # has no matches, so this is an empty-but-200 response, proving the
    # team_or_global_filter path doesn't error against a real database.
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, dict)
