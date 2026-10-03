"""
Enhanced API endpoints for comprehensive CSMP functionality
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json
import logging

from fastapi import HTTPException, status
from . import schemas

logger = logging.getLogger(__name__)


def _estimate_scan_duration(
    provider: str, 
    regions: Optional[List[str]] = None, 
    check_ids: Optional[List[str]] = None
) -> int:
    """
    Estimate scan duration in minutes based on provider, regions, and checks.
    """
    base_duration = {
        "aws": 15,      # AWS scans typically take 15 minutes
        "gcp": 10,      # GCP scans typically take 10 minutes  
        "azure": 12     # Azure scans typically take 12 minutes
    }
    
    duration = base_duration.get(provider.lower(), 15)
    
    # Adjust for regions
    if regions:
        region_count = len(regions)
        if region_count > 3:
            duration += (region_count - 3) * 2  # +2 minutes per additional region
    
    # Adjust for specific checks
    if check_ids:
        # If specific checks are selected, it's usually faster
        duration = max(5, duration // 2)
    
    return duration


def _get_resource_inventory_summary(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate resource inventory summary from scan results.
    """
    if not scan_results.get('results'):
        return {
            "total_resources": 0,
            "resources_by_type": {},
            "resources_by_region": {},
            "resources_by_service": {}
        }
    
    results = scan_results['results']
    
    resources_by_type = {}
    resources_by_region = {}
    resources_by_service = {}
    unique_resources = set()
    
    for result in results:
        resource_id = result.get('resource_id', 'unknown')
        resource_type = result.get('resource_type', 'Unknown')
        region = result.get('region', 'Unknown')
        
        # Extract service from check_id (e.g., AWS_S3_001 -> S3)
        check_id = result.get('check_id', '')
        service = check_id.split('_')[1] if '_' in check_id else 'Unknown'
        
        unique_resources.add(resource_id)
        
        # Count by type
        resources_by_type[resource_type] = resources_by_type.get(resource_type, 0) + 1
        
        # Count by region
        resources_by_region[region] = resources_by_region.get(region, 0) + 1
        
        # Count by service
        resources_by_service[service] = resources_by_service.get(service, 0) + 1
    
    return {
        "total_resources": len(unique_resources),
        "total_findings": len(results),
        "resources_by_type": dict(sorted(resources_by_type.items(), key=lambda x: x[1], reverse=True)),
        "resources_by_region": dict(sorted(resources_by_region.items(), key=lambda x: x[1], reverse=True)),
        "resources_by_service": dict(sorted(resources_by_service.items(), key=lambda x: x[1], reverse=True))
    }


# --- Compliance aggregation over stored scan reports -------------------------
# GET /api/v1/compliance/summary and /findings used to return a hard-coded
# account (1547 resources, 86.7%, CIS/NIST/PCI with invented control counts
# and five invented findings) whatever the team had scanned. These helpers
# build both answers from the reports of the team's completed scans, and
# from nothing else.

_VERDICTS = ("passed", "failed")


def _plain(value: Any) -> Any:
    """The JSON value of an enum or datetime that a report may still carry."""
    if isinstance(value, datetime):
        return value.isoformat()
    return getattr(value, "value", value)


def _report_time(report: Dict[str, Any]) -> Optional[str]:
    value = _plain(report.get("completed_at") or report.get("started_at"))
    return value if isinstance(value, str) else None


def _latest(current: Optional[str], candidate: Optional[str]) -> Optional[str]:
    # ISO-8601 timestamps written by one service, in UTC, sort as strings.
    if candidate is None:
        return current
    return candidate if current is None or candidate > current else current


def _summarize_compliance(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Resource, framework and overall figures from completed scan reports.

    Only verdicts count: a check that errored, was skipped or is not
    implemented says nothing about compliance either way.
    """
    resource_statuses: Dict[tuple, set] = {}
    frameworks: Dict[str, Dict[str, Any]] = {}
    passed = failed = 0
    last_updated: Optional[str] = None

    for report in reports:
        assessed = _report_time(report)
        last_updated = _latest(last_updated, assessed)
        account = report.get("account_id")
        for result in report.get("results") or []:
            verdict = _plain(result.get("status"))
            if verdict not in _VERDICTS:
                continue
            resource_statuses.setdefault((account, result.get("resource_id")), set()).add(verdict)
            if verdict == "passed":
                passed += 1
            else:
                failed += 1
            for name in result.get("compliance_frameworks") or []:
                entry = frameworks.setdefault(
                    name,
                    {"name": name, "passed_checks": 0, "failed_checks": 0, "last_assessment": None},
                )
                entry[f"{verdict}_checks"] += 1
                entry["last_assessment"] = _latest(entry["last_assessment"], assessed)

    framework_rows = []
    for entry in sorted(frameworks.values(), key=lambda e: e["name"]):
        total = entry["passed_checks"] + entry["failed_checks"]
        framework_rows.append({
            **entry,
            "total_checks": total,
            "compliance_percentage": round(entry["passed_checks"] / total * 100, 1),
        })

    non_compliant = sum(1 for statuses in resource_statuses.values() if "failed" in statuses)
    verdicts = passed + failed
    return {
        "total_resources": len(resource_statuses),
        "compliant_resources": len(resource_statuses) - non_compliant,
        "non_compliant_resources": non_compliant,
        "overall_score": round(passed / verdicts * 100, 1) if verdicts else None,
        "frameworks": framework_rows,
        "scans_considered": len(reports),
        "last_updated": last_updated,
    }


def _compliance_findings(
    reports: List[Dict[str, Any]], check_catalog: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """One finding per check verdict in the reports, newest scan first.

    Title and severity come from the check's own metadata (``check_catalog``,
    keyed by check id). A result whose check is not in the catalog keeps its
    id as the title and has no severity, rather than a guessed one.
    """
    findings = []
    for report in sorted(reports, key=lambda r: _report_time(r) or "", reverse=True):
        scan_id = str(report.get("scan_id"))
        for index, result in enumerate(report.get("results") or []):
            verdict = _plain(result.get("status"))
            if verdict not in _VERDICTS:
                continue
            check_id = str(result.get("check_id"))
            check = check_catalog.get(check_id, {})
            findings.append({
                "finding_id": f"{scan_id}:{index}",
                "scan_id": scan_id,
                "check_id": check_id,
                "title": check.get("title") or check_id,
                "frameworks": list(result.get("compliance_frameworks") or []),
                "resource_id": str(result.get("resource_id")),
                "resource_type": str(result.get("resource_type")),
                "region": result.get("region"),
                "status": verdict,
                "severity": _plain(check.get("severity")),
                "description": str(result.get("message") or ""),
                "remediation": result.get("remediation"),
                "last_checked": _plain(result.get("timestamp")),
            })
    return findings


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _count_failed_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Failed checks among ``findings``, by the severity their check declares.

    ``findings`` is what _compliance_findings returns. A failed check whose
    severity is unknown (the check is no longer in the catalog) is counted
    under ``unknown_severity_findings`` rather than given a severity, so the
    buckets always add up to ``total_findings``.
    """
    counts = {f"{severity}_findings": 0 for severity in _SEVERITIES}
    counts["unknown_severity_findings"] = 0
    total = 0
    for finding in findings:
        if finding.get("status") != "failed":
            continue
        total += 1
        severity = finding.get("severity")
        key = f"{severity}_findings" if severity in _SEVERITIES else "unknown_severity_findings"
        counts[key] += 1
    return {"total_findings": total, **counts}
