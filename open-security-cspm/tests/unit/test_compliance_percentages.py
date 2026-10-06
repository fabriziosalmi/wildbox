"""A scan's compliance percentages are over the results with a verdict (#778).

``GET /api/v1/scans/{id}/compliance`` and ``summary.compliance_frameworks``
in the report divided the passed results by every result tagged with the
framework. A check that was skipped, or that failed to run, has no verdict,
and it lowered the percentage exactly as a failed one does: a scan with one
result passed, two failed and one in error read 25% for its framework where
its own ``compliance_score`` read 33.3%.

What is left as it was, for a release that may change what clients read:
``total_checks`` counts every result, and the percentages are ``0``, not
null, when nothing was assessed.
"""

import copy

import pytest
from app import scan_store
from app.checks.framework import CheckResult, CheckStatus, CloudProvider, ScanReport
from route_probes import HEADERS

FRAMEWORK = "CIS AWS Foundations"
OTHER = "PCI DSS"


def _compliance(world, scan_id, **params):
    response = world.client.get(
        f"/api/v1/scans/{scan_id}/compliance", headers=HEADERS, params=params
    )
    assert response.status_code == 200, response.text
    return response.json()


def _report(world, scan_id):
    response = world.client.get(f"/api/v1/scans/{scan_id}/report", headers=HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def _complete_with(world, statuses):
    """Complete the world's queued scan with one result per status given, as
    (status, frameworks) pairs; return its id."""
    scan_id = world.scans.queued
    report = ScanReport(
        scan_id=scan_id,
        provider=CloudProvider.AWS,
        account_id="444444444444",
        regions=["eu-west-1"],
    )
    for number, (status, frameworks) in enumerate(statuses):
        report.add_result(
            CheckResult(
                check_id="AWS_TEST_001",
                resource_id=f"res-{number}",
                resource_type="Resource",
                status=status,
                message=status.value,
                compliance_frameworks=frameworks,
            )
        )
    report.finalize()
    assert scan_store.complete_scan(
        world.redis, scan_id, report.model_dump(mode="json"), "2026-10-06T12:00:00"
    )
    return scan_id


def test_the_scan_of_the_other_tests_has_results_without_a_verdict(world):
    """So that the figures below are not those of the old division too."""
    report = _report(world, world.scans.completed)

    assert (report["passed_checks"], report["failed_checks"]) == (1, 2)
    assert report["skipped_checks"] + report["error_checks"] == 2
    assert report["compliance_score"] == pytest.approx(100 / 3)


def test_a_result_without_a_verdict_does_not_lower_a_frameworks_percentage(world):
    passed, failed, skipped, error = (
        CheckStatus.PASSED,
        CheckStatus.FAILED,
        CheckStatus.SKIPPED,
        CheckStatus.ERROR,
    )
    scan_id = _complete_with(
        world,
        [
            (passed, [FRAMEWORK, OTHER]),
            (failed, [FRAMEWORK]),
            (skipped, [FRAMEWORK]),
            (error, [FRAMEWORK, OTHER]),
            (CheckStatus.NOT_IMPLEMENTED, [FRAMEWORK]),
        ],
    )

    body = _compliance(world, scan_id)

    rows = {row["framework"]: row for row in body["frameworks"]}
    # One passed of two verdicts; it was one of five results, 20%.
    assert rows[FRAMEWORK] == {
        "framework": FRAMEWORK,
        "total_checks": 5,
        "passed_checks": 1,
        "failed_checks": 1,
        "compliance_percentage": 50.0,
    }
    # One passed, and one that did not run: 100% of what was assessed, not 50.
    assert rows[OTHER] == {
        "framework": OTHER,
        "total_checks": 2,
        "passed_checks": 1,
        "failed_checks": 0,
        "compliance_percentage": 100.0,
    }
    # Two passed of three verdicts over the two frameworks; it was 2 of 7.
    assert body["overall_score"] == pytest.approx(200 / 3)


def test_the_report_and_the_compliance_route_give_one_percentage(world):
    scan_id = _complete_with(
        world,
        [
            (CheckStatus.PASSED, [FRAMEWORK]),
            (CheckStatus.FAILED, [FRAMEWORK]),
            (CheckStatus.FAILED, [FRAMEWORK]),
            (CheckStatus.ERROR, [FRAMEWORK]),
        ],
    )

    report = _report(world, scan_id)
    body = _compliance(world, scan_id)

    in_summary = report["summary"]["compliance_frameworks"][FRAMEWORK]
    assert in_summary == {
        "total": 4,
        "passed": 1,
        "failed": 2,
        "compliance_percentage": pytest.approx(100 / 3),
    }
    (row,) = body["frameworks"]
    assert row["compliance_percentage"] == pytest.approx(100 / 3)
    # The scan's three percentages agree: it has one framework.
    assert report["compliance_score"] == pytest.approx(100 / 3)
    assert body["overall_score"] == pytest.approx(100 / 3)


def test_every_framework_of_the_worlds_scan(world):
    """The same, on the scan the worker's own task completed."""
    report = _report(world, world.scans.completed)
    body = _compliance(world, world.scans.completed)

    assert any(
        row["total_checks"] > row["passed_checks"] + row["failed_checks"]
        for row in body["frameworks"]
    )
    for row in body["frameworks"]:
        verdicts = row["passed_checks"] + row["failed_checks"]
        assert verdicts > 0
        assert row["compliance_percentage"] == pytest.approx(
            row["passed_checks"] / verdicts * 100
        )
        assert row["compliance_percentage"] == pytest.approx(
            report["summary"]["compliance_frameworks"][row["framework"]][
                "compliance_percentage"
            ]
        )


# --- What is left as it was --------------------------------------------------------


def test_a_framework_with_no_verdict_still_reads_zero_and_counts_its_results(world):
    scan_id = _complete_with(
        world,
        [(CheckStatus.SKIPPED, [FRAMEWORK]), (CheckStatus.ERROR, [FRAMEWORK])],
    )

    report = _report(world, scan_id)
    body = _compliance(world, scan_id)

    assert body["frameworks"] == [
        {
            "framework": FRAMEWORK,
            "total_checks": 2,
            "passed_checks": 0,
            "failed_checks": 0,
            "compliance_percentage": 0,
        }
    ]
    assert body["overall_score"] == 0
    assert report["compliance_score"] == 0
    assert report["summary"]["compliance_frameworks"][FRAMEWORK] == {
        "total": 2,
        "passed": 0,
        "failed": 0,
        "compliance_percentage": 0,
    }


def test_a_report_stored_before_keeps_its_summary_and_the_route_recomputes(world):
    """Reports are stored whole: one written by an earlier release carries
    the percentage over ``total`` in its summary, and is served as stored."""
    scan_id = world.scans.completed
    stored = copy.deepcopy(scan_store.load_report(world.redis, scan_id))
    for figures in stored["summary"]["compliance_frameworks"].values():
        figures["compliance_percentage"] = figures["passed"] / figures["total"] * 100
    world.redis.setex(
        scan_store.report_key(scan_id),
        scan_store.retention_seconds(),
        scan_store.encode_report(stored),
    )

    report = _report(world, scan_id)
    body = _compliance(world, scan_id)

    for row in body["frameworks"]:
        in_summary = report["summary"]["compliance_frameworks"][row["framework"]]
        assert in_summary["compliance_percentage"] == pytest.approx(
            row["passed_checks"] / row["total_checks"] * 100
        )
        assert row["compliance_percentage"] == pytest.approx(
            row["passed_checks"] / (row["passed_checks"] + row["failed_checks"]) * 100
        )
