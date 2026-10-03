"""Unit tests for pure-logic CSPM scoring/summary helpers in app/utils.py.

Pure-logic, no cloud credentials/DB/Redis needed. Locks in the scan
duration estimate and the resource inventory summary. (The compliance
score and the remediation roadmap helpers went with the endpoints that
read scan:{id}:results, a key nothing writes; see #578.)
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.utils import (  # noqa: E402
    _estimate_scan_duration,
    _get_resource_inventory_summary,
)


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
