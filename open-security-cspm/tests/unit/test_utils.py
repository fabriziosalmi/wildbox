"""Unit tests for pure-logic CSPM scoring/summary helpers in app/utils.py.

Pure-logic, no cloud credentials/DB/Redis needed. Locks in the compliance
scoring and remediation-roadmap math so a refactor can't silently change
what counts as "compliant" or how findings get prioritized.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.utils import (  # noqa: E402
    _calculate_compliance_score,
    _estimate_scan_duration,
    _generate_remediation_roadmap,
    _get_resource_inventory_summary,
)


def test_calculate_compliance_score_empty_results_is_zero():
    assert _calculate_compliance_score({"results": []}) == 0.0
    assert _calculate_compliance_score({}) == 0.0


def test_calculate_compliance_score_all_passed_is_100():
    results = {"results": [{"status": "passed"}, {"status": "passed"}]}
    assert _calculate_compliance_score(results) == 100.0


def test_calculate_compliance_score_mixed_pass_fail():
    results = {"results": [{"status": "passed"}, {"status": "failed"}, {"status": "passed"}]}
    assert _calculate_compliance_score(results) == pytest.approx(66.67, abs=0.01)


def test_calculate_compliance_score_excludes_unevaluated_statuses():
    # skipped/errored/not-implemented checks should not count toward or
    # against the score - only "passed"/"failed" verdicts are evaluated.
    results = {
        "results": [
            {"status": "passed"},
            {"status": "failed"},
            {"status": "skipped"},
            {"status": "error"},
            {"status": "not_implemented"},
        ]
    }
    assert _calculate_compliance_score(results) == 50.0


def test_calculate_compliance_score_only_unevaluated_is_zero():
    results = {"results": [{"status": "skipped"}, {"status": "error"}]}
    assert _calculate_compliance_score(results) == 0.0


@pytest.mark.parametrize("provider,expected", [
    ("aws", 15),
    ("AWS", 15),
    ("gcp", 10),
    ("azure", 12),
    ("unknown", 15),
])
def test_estimate_scan_duration_base_by_provider(provider, expected):
    assert _estimate_scan_duration(provider) == expected


def test_estimate_scan_duration_scales_with_extra_regions():
    base = _estimate_scan_duration("aws")
    with_regions = _estimate_scan_duration("aws", regions=["us-east-1", "us-west-1", "eu-west-1", "ap-south-1"])
    assert with_regions == base + 2  # one region beyond the 3 included


def test_estimate_scan_duration_halves_for_specific_checks():
    duration = _estimate_scan_duration("aws", check_ids=["AWS_S3_001"])
    assert duration == max(5, 15 // 2)


def test_estimate_scan_duration_floor_is_five_minutes():
    duration = _estimate_scan_duration("gcp", check_ids=["GCP_CHECK_001"])
    assert duration >= 5


def test_resource_inventory_summary_empty():
    summary = _get_resource_inventory_summary({"results": []})
    assert summary["total_resources"] == 0
    assert summary["resources_by_type"] == {}


def test_resource_inventory_summary_counts_unique_resources_and_extracts_service():
    scan_results = {
        "results": [
            {"resource_id": "bucket-1", "resource_type": "S3Bucket", "region": "us-east-1", "check_id": "AWS_S3_001"},
            {"resource_id": "bucket-1", "resource_type": "S3Bucket", "region": "us-east-1", "check_id": "AWS_S3_002"},
            {"resource_id": "vm-1", "resource_type": "EC2Instance", "region": "us-west-1", "check_id": "AWS_EC2_001"},
        ]
    }
    summary = _get_resource_inventory_summary(scan_results)

    assert summary["total_resources"] == 2  # bucket-1 counted once
    assert summary["total_findings"] == 3
    assert summary["resources_by_type"]["S3Bucket"] == 2
    assert summary["resources_by_service"]["S3"] == 2
    assert summary["resources_by_service"]["EC2"] == 1


def test_remediation_roadmap_empty_results():
    assert _generate_remediation_roadmap({"results": []}) == []


def test_remediation_roadmap_groups_by_remediation_and_ranks_by_impact():
    scan_results = {
        "results": [
            {
                "status": "failed",
                "remediation": "Enable encryption",
                "resource_id": "bucket-1",
                "resource_type": "S3Bucket",
                "region": "us-east-1",
                "check_id": "AWS_S3_001",
                "compliance_frameworks": ["CIS"],
            },
            {
                "status": "failed",
                "remediation": "Enable encryption",
                "resource_id": "bucket-2",
                "resource_type": "S3Bucket",
                "region": "us-east-1",
                "check_id": "AWS_S3_001",
                "compliance_frameworks": ["CIS", "NIST"],
            },
            {
                "status": "failed",
                "remediation": "Restrict security group",
                "resource_id": "vm-1",
                "resource_type": "EC2Instance",
                "region": "us-west-1",
                "check_id": "AWS_EC2_001",
                "compliance_frameworks": [],
            },
            {
                # passed findings should be excluded entirely
                "status": "passed",
                "remediation": "Enable encryption",
                "resource_id": "bucket-3",
                "resource_type": "S3Bucket",
                "region": "us-east-1",
                "check_id": "AWS_S3_001",
            },
        ]
    }

    roadmap = _generate_remediation_roadmap(scan_results)

    assert len(roadmap) == 2
    # The item affecting more resources (2 buckets) should be ranked first.
    assert roadmap[0]["remediation"] == "Enable encryption"
    assert len(roadmap[0]["affected_resources"]) == 2
    assert set(roadmap[0]["compliance_impact"]) == {"CIS", "NIST"}
    assert roadmap[0]["order"] == 1

    assert roadmap[1]["remediation"] == "Restrict security group"
    assert len(roadmap[1]["affected_resources"]) == 1
