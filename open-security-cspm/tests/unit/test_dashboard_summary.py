"""GET /api/v1/dashboard/summary reports the team's stored scan reports (#578).

The endpoint read ``scan:{id}:results``, a key nothing writes, so findings
and the compliance score were 0 even after a real scan; the severity
buckets were hard-coded to 0; and every scan counted as active, because the
stored scan status was never updated after the scan started. It now reads
the reports GET /api/v1/compliance/summary reads (the newest completed scan
of each of the team's accounts, as the worker stored it, #591), takes each
failed check's severity from the check catalog, and reports no scan status
counts at all.

The endpoint is called directly with a fake Redis (tests/unit/conftest.py),
so these tests need no service running.
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# app.main builds Settings() at import time, which requires these; the same
# test-only values test_check_discovery.py uses.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-at-least-32-chars-long")
os.environ.setdefault(
    "CSPM_CREDENTIAL_KEY", "dGVzdC1vbmx5LWtleS1ub3QtdXNlZC1mb3ItY3J5cHRvISE="
)

from app import main, scan_store, schemas  # noqa: E402

CATALOG = [
    {"check_id": "S3_PUBLIC", "severity": "critical", "title": "S3 bucket is public"},
    {"check_id": "IAM_MFA", "severity": "high", "title": "Root account has no MFA"},
    {"check_id": "EC2_TAGS", "severity": "low", "title": "Instance is untagged"},
    {"check_id": "LOGGING", "severity": "info", "title": "Access logging is off"},
]

TEAM_A = "team-a"
TEAM_B = "team-b"


def _check(check_id, resource_id, status):
    return {
        "check_id": check_id,
        "resource_id": resource_id,
        "resource_type": "S3 Bucket",
        "region": "eu-west-1",
        "status": status,
        "message": "msg",
        "remediation": "fix it",
        "compliance_frameworks": ["CIS"],
        "timestamp": "2026-10-01T10:00:00",
    }


@pytest.fixture
def store(monkeypatch, fake_redis):
    monkeypatch.setattr(main, "redis_client", fake_redis)
    monkeypatch.setattr(main.check_runner, "get_available_checks", lambda: CATALOG)

    counter = {"n": 0}

    def add_scan(team_id, account_id, *, hours_ago, status="SUCCESS", results=None):
        counter["n"] += 1
        scan_id = f"00000000-0000-0000-0000-{counter['n']:012d}"
        started = datetime.utcnow() - timedelta(hours=hours_ago)
        scan_store.save_metadata(
            fake_redis,
            {
                "scan_id": scan_id,
                "provider": "aws",
                "account_id": account_id,
                "status": "started",
                "started_at": started.isoformat(),
                "team_id": team_id,
            },
        )
        if status == "SUCCESS":
            completed_at = (started + timedelta(minutes=5)).isoformat()
            report = {
                "scan_id": scan_id,
                "account_id": account_id,
                "started_at": started.isoformat(),
                "completed_at": completed_at,
                "results": results or [],
            }
            scan_store.complete_scan(fake_redis, scan_id, report, completed_at)
        return started

    return add_scan


def _summary(team_id, days=30):
    response = asyncio.run(
        main.get_dashboard_summary(days=days, current_user={"team_id": team_id})
    )
    return schemas.DashboardSummaryResponse.model_validate(response).model_dump()


def test_a_team_without_scans_has_nothing_assessed_not_zero_percent(store):
    summary = _summary(TEAM_A)

    assert summary["total_scans"] == 0
    assert summary["last_scan_at"] is None
    assert summary["accounts_assessed"] == 0
    assert summary["compliance_score"] is None
    assert summary["total_findings"] == 0
    assert summary["summary_period_days"] == 30


def test_figures_come_from_the_newest_completed_report_of_each_account(store):
    # Superseded by the newer scan of the same account: must not count.
    store(
        TEAM_A,
        "acct-1",
        hours_ago=10,
        results=[_check("S3_PUBLIC", "old", "failed")] * 3,
    )
    store(
        TEAM_A,
        "acct-1",
        hours_ago=5,
        results=[
            _check("S3_PUBLIC", "bucket-1", "failed"),
            _check("IAM_MFA", "root", "failed"),
            _check("EC2_TAGS", "i-1", "passed"),
            _check("EC2_TAGS", "i-2", "error"),  # no verdict: counts nowhere
        ],
    )
    store(
        TEAM_A,
        "acct-2",
        hours_ago=3,
        results=[
            _check("LOGGING", "trail", "failed"),
            _check("RETIRED_CHECK", "x", "failed"),  # not in the catalog
            _check("EC2_TAGS", "i-3", "passed"),
        ],
    )
    # Started, not finished: a scan, but no report.
    newest = store(TEAM_A, "acct-3", hours_ago=1, status="PENDING")

    summary = _summary(TEAM_A)

    assert summary["total_scans"] == 4
    assert summary["last_scan_at"] == newest
    assert summary["accounts_assessed"] == 2
    assert summary["total_findings"] == 4
    assert summary["critical_findings"] == 1
    assert summary["high_findings"] == 1
    assert summary["medium_findings"] == 0
    assert summary["low_findings"] == 0
    assert summary["info_findings"] == 1
    assert summary["unknown_severity_findings"] == 1
    # 2 passed out of 6 verdicts.
    assert summary["compliance_score"] == 33.3
    for gone in ("active_scans", "completed_scans", "failed_scans"):
        assert gone not in summary


def test_the_figures_match_the_compliance_summary(store):
    store(
        TEAM_A,
        "acct-1",
        hours_ago=2,
        results=[_check("S3_PUBLIC", "b", "failed"), _check("IAM_MFA", "r", "passed")],
    )

    dashboard = _summary(TEAM_A)
    compliance = asyncio.run(
        main.get_compliance_summary(
            days=30, provider=None, current_user={"team_id": TEAM_A}
        )
    )

    assert dashboard["compliance_score"] == compliance["overall_score"] == 50.0
    assert dashboard["accounts_assessed"] == compliance["scans_considered"] == 1


def test_reports_older_than_the_period_are_left_out(store):
    store(
        TEAM_A,
        "acct-1",
        hours_ago=24 * 10,
        results=[_check("S3_PUBLIC", "b", "failed")],
    )

    summary = _summary(TEAM_A, days=7)

    assert summary["total_scans"] == 1
    assert summary["accounts_assessed"] == 0
    assert summary["total_findings"] == 0
    assert summary["compliance_score"] is None
    assert summary["summary_period_days"] == 7


def test_a_team_sees_only_its_own_accounts(store):
    store(TEAM_A, "acct-a", hours_ago=2, results=[_check("EC2_TAGS", "i-1", "passed")])
    store(
        TEAM_B,
        "acct-b",
        hours_ago=1,
        results=[
            _check("S3_PUBLIC", "b-1", "failed"),
            _check("S3_PUBLIC", "b-2", "failed"),
        ],
    )

    team_a = _summary(TEAM_A)
    team_b = _summary(TEAM_B)

    assert (team_a["total_scans"], team_a["accounts_assessed"]) == (1, 1)
    assert team_a["total_findings"] == 0
    assert team_a["critical_findings"] == 0
    assert team_a["compliance_score"] == 100.0

    assert (team_b["total_scans"], team_b["accounts_assessed"]) == (1, 1)
    assert team_b["critical_findings"] == 2
    assert team_b["compliance_score"] == 0.0

    # A team with no scans of its own sees none of the others'.
    assert _summary("team-c")["total_scans"] == 0
    assert _summary("team-c")["accounts_assessed"] == 0
