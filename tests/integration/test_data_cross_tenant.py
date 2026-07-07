"""True two-team cross-tenant isolation for the data service (#183, completing
#178). The data service has no create API, so seed Source/Indicator rows
directly in its database, then assert team B cannot read team A's data via the
API while global (team_id NULL) data is visible to both.
"""
import os
import uuid
from datetime import datetime, timezone
from typing import Dict

import pytest
import requests

psycopg2 = pytest.importorskip("psycopg2")
from psycopg2.extras import Json  # noqa: E402


def _gateway_headers(team_id: str, secret: str) -> Dict[str, str]:
    return {
        "X-Wildbox-User-ID": str(uuid.uuid4()),
        "X-Wildbox-Team-ID": team_id,
        "X-Wildbox-Role": "member",
        "X-Gateway-Secret": secret,
    }


def _seed(conn, *, team_id, value):
    """Insert a Source + Indicator (active) owned by team_id (NULL = global).
    Returns (source_id, indicator_id)."""
    now = datetime.now(timezone.utc)
    source_id = uuid.uuid4()
    indicator_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO sources (id, team_id, name, source_type, enabled) "
            "VALUES (%s, %s, %s, %s, %s)",
            (str(source_id), team_id, f"test-src-{source_id}", "feed", True),
        )
        cur.execute(
            "INSERT INTO indicators "
            "(id, source_id, team_id, indicator_type, value, normalized_value, "
            " threat_types, confidence, severity, tags, "
            " first_seen, last_seen, collection_date, active) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            # threat_types/confidence/severity/tags are NOT NULL in the response
            # schema (pydantic defaults don't apply to a NULL read from the ORM).
            (str(indicator_id), str(source_id), team_id, "ipv4", value, value,
             Json([]), "medium", 5, Json([]),
             now, now, now, True),
        )
    conn.commit()
    return source_id, indicator_id


def _search_values(service_urls, team_id, secret, query):
    resp = requests.get(
        f"{service_urls['data']}/api/v1/indicators/search",
        params={"q": query},
        headers=_gateway_headers(team_id, secret),
        timeout=10,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    items = body.get("indicators") or body.get("results") or []
    return {i.get("value") for i in items}


def test_data_team_cannot_read_other_teams_indicator(service_urls):
    secret = os.environ.get("GATEWAY_INTERNAL_SECRET", "")
    dsn = os.environ.get("DATA_DB_DSN", "")
    if not secret or not dsn:
        pytest.skip("GATEWAY_INTERNAL_SECRET / DATA_DB_DSN not set")

    team_a = str(uuid.uuid4())
    team_b = str(uuid.uuid4())
    val_a = f"10.0.0.{uuid.uuid4().hex[:6]}"        # team A private
    val_global = f"10.1.1.{uuid.uuid4().hex[:6]}"   # shared/global feed

    conn = psycopg2.connect(dsn)
    seeded = []
    try:
        seeded.append(_seed(conn, team_id=team_a, value=val_a))
        seeded.append(_seed(conn, team_id=None, value=val_global))

        # Team A sees its own private indicator; team B does not.
        assert val_a in _search_values(service_urls, team_a, secret, val_a)
        assert val_a not in _search_values(service_urls, team_b, secret, val_a)

        # Global (team_id NULL) indicator is visible to both teams.
        assert val_global in _search_values(service_urls, team_a, secret, val_global)
        assert val_global in _search_values(service_urls, team_b, secret, val_global)
    finally:
        with conn.cursor() as cur:
            for source_id, indicator_id in seeded:
                cur.execute("DELETE FROM indicators WHERE id = %s", (str(indicator_id),))
                cur.execute("DELETE FROM sources WHERE id = %s", (str(source_id),))
        conn.commit()
        conn.close()
