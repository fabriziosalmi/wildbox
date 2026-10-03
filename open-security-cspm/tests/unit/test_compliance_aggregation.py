"""Compliance summary and findings come from scan reports, and only from them.

GET /api/v1/compliance/summary and /findings used to return one invented
account (1547 resources, 86.7%, CIS/NIST/PCI) to every team (#572). These
tests pin the aggregation that replaced it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import schemas  # noqa: E402
from app.utils import _compliance_findings, _summarize_compliance  # noqa: E402


def _result(check_id, resource_id, status, frameworks=(), message="msg"):
    return {
        "check_id": check_id,
        "resource_id": resource_id,
        "resource_type": "S3 Bucket",
        "region": "eu-west-1",
        "status": status,
        "message": message,
        "remediation": "fix it",
        "compliance_frameworks": list(frameworks),
        "timestamp": "2026-10-01T10:00:00",
    }


def _report(scan_id, completed_at, results, account_id="111122223333"):
    return {
        "scan_id": scan_id,
        "account_id": account_id,
        "started_at": "2026-10-01T09:00:00",
        "completed_at": completed_at,
        "results": results,
    }


def test_no_reports_means_nothing_assessed_not_zero_percent():
    summary = _summarize_compliance([])

    assert summary == {
        "total_resources": 0,
        "compliant_resources": 0,
        "non_compliant_resources": 0,
        "overall_score": None,
        "frameworks": [],
        "scans_considered": 0,
        "last_updated": None,
    }
    schemas.ComplianceSummaryResponse(**summary, summary_period_days=30)


def test_summary_counts_resources_and_frameworks_from_verdicts():
    reports = [
        _report(
            "scan-a",
            "2026-10-01T10:05:00",
            [
                _result("aws_s3_1", "bucket-1", "passed", ["CIS"]),
                _result("aws_s3_2", "bucket-1", "failed", ["CIS", "PCI"]),
                _result("aws_s3_1", "bucket-2", "passed", ["CIS"]),
                # No verdict: neither compliant nor not.
                _result("aws_s3_3", "bucket-3", "error", ["CIS"]),
                _result("aws_s3_4", "bucket-3", "not_implemented", ["CIS"]),
            ],
        )
    ]

    summary = _summarize_compliance(reports)

    assert summary["total_resources"] == 2
    assert summary["non_compliant_resources"] == 1
    assert summary["compliant_resources"] == 1
    assert summary["overall_score"] == 66.7
    assert summary["scans_considered"] == 1
    assert summary["last_updated"] == "2026-10-01T10:05:00"
    assert summary["frameworks"] == [
        {
            "name": "CIS",
            "passed_checks": 2,
            "failed_checks": 1,
            "total_checks": 3,
            "compliance_percentage": 66.7,
            "last_assessment": "2026-10-01T10:05:00",
        },
        {
            "name": "PCI",
            "passed_checks": 0,
            "failed_checks": 1,
            "total_checks": 1,
            "compliance_percentage": 0.0,
            "last_assessment": "2026-10-01T10:05:00",
        },
    ]
    schemas.ComplianceSummaryResponse(**summary, summary_period_days=30)


def test_same_resource_id_in_two_accounts_is_two_resources():
    reports = [
        _report("a", "2026-10-01T10:00:00", [_result("c", "r", "passed")], "acct-1"),
        _report("b", "2026-10-02T10:00:00", [_result("c", "r", "failed")], "acct-2"),
    ]

    summary = _summarize_compliance(reports)

    assert summary["total_resources"] == 2
    assert summary["non_compliant_resources"] == 1
    assert summary["last_updated"] == "2026-10-02T10:00:00"


def test_findings_take_title_and_severity_from_the_check_catalog():
    reports = [
        _report(
            "old", "2026-10-01T10:00:00", [_result("known", "r1", "failed", ["CIS"])]
        ),
        _report(
            "new",
            "2026-10-02T10:00:00",
            [
                _result("unknown", "r2", "passed"),
                _result("known", "r3", "skipped"),
            ],
        ),
    ]
    catalog = {"known": {"title": "Buckets block public access", "severity": "high"}}

    findings = _compliance_findings(reports, catalog)

    # Newest scan first; the skipped result is not a finding.
    assert [f["finding_id"] for f in findings] == ["new:0", "old:0"]
    unknown, known = findings
    assert unknown["title"] == "unknown"
    assert unknown["severity"] is None
    assert known["title"] == "Buckets block public access"
    assert known["severity"] == "high"
    assert known["frameworks"] == ["CIS"]
    assert known["status"] == "failed"
    for finding in findings:
        schemas.ComplianceFinding(**finding)
