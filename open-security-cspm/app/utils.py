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


def _calculate_compliance_score(scan_results: Dict[str, Any]) -> float:
    """
    Calculate overall compliance score from scan results.
    """
    if not scan_results.get('results'):
        return 0.0

    results = scan_results['results']
    # Score over checks that produced a real verdict only. Not-implemented /
    # skipped / errored checks are excluded so an unrun check never counts as
    # (or against) compliance.
    passed_checks = sum(1 for result in results if result.get('status') == 'passed')
    failed_checks = sum(1 for result in results if result.get('status') == 'failed')
    evaluated_checks = passed_checks + failed_checks

    if evaluated_checks == 0:
        return 0.0

    return round((passed_checks / evaluated_checks) * 100, 2)


def _severity_for_check(check_id):
    """Severity declared by the check that produced a finding, or None.

    A CheckResult carries no severity of its own -- severity lives in the
    check's metadata -- so it has to be looked up in the registry the runner
    populated at start-up.
    """
    if not check_id:
        return None
    try:
        from .checks.framework import check_registry
    except ImportError:  # pragma: no cover - registry unavailable
        return None
    check = check_registry.get_check(check_id)
    if check is None:
        return None
    severity = getattr(check.metadata, "severity", None)
    return getattr(severity, "value", severity)


def _generate_executive_summary(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate executive summary from scan results.
    """
    if not scan_results.get('results'):
        return {
            "total_resources_scanned": 0,
            "security_score": 0.0,
            "critical_findings": 0,
            "high_findings": 0,
            "recommendations_count": 0,
            "compliance_frameworks": {}
        }
    
    results = scan_results['results']
    
    # Count findings by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        # Findings whose check is not registered. Kept separate so they are
        # never silently folded into a real severity bucket.
        "unknown": 0,
    }
    
    # Count compliance framework coverage
    framework_stats = {}
    
    unique_resources = set()
    
    for result in results:
        # Count unique resources
        resource_id = result.get('resource_id', 'unknown')
        unique_resources.add(resource_id)
        
        # Count by status and severity.
        #
        # The severity comes from the check that produced the finding. It used
        # to come from random.choice(['critical','high','medium','low']) -- the
        # executive dashboard's "critical findings" figure, the headline number
        # of a cloud security product, was a die roll that changed on every
        # request. A finding whose check is not in the registry is counted as
        # unknown rather than assigned a severity nobody determined.
        if result.get('status') == 'failed':
            severity = _severity_for_check(result.get('check_id'))
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["unknown"] += 1
        
        # Track compliance frameworks
        frameworks = result.get('compliance_frameworks', [])
        for framework in frameworks:
            if framework not in framework_stats:
                framework_stats[framework] = {"total": 0, "passed": 0, "failed": 0}
            
            framework_stats[framework]["total"] += 1
            if result.get('status') == 'passed':
                framework_stats[framework]["passed"] += 1
            else:
                framework_stats[framework]["failed"] += 1
    
    # Calculate compliance percentages
    for framework in framework_stats:
        total = framework_stats[framework]["total"]
        passed = framework_stats[framework]["passed"]
        framework_stats[framework]["compliance_percentage"] = round(
            (passed / total * 100) if total > 0 else 0, 1
        )
    
    # Calculate security score (based on failed checks)
    total_failed = sum(severity_counts.values())
    total_checks = len(results)
    security_score = round(((total_checks - total_failed) / total_checks * 100) if total_checks > 0 else 0, 1)
    
    return {
        "total_resources_scanned": len(unique_resources),
        "total_checks_performed": total_checks,
        "security_score": security_score,
        "critical_findings": severity_counts["critical"],
        "high_findings": severity_counts["high"],
        "medium_findings": severity_counts["medium"],
        "low_findings": severity_counts["low"],
        "info_findings": severity_counts["info"],
        "unknown_severity_findings": severity_counts["unknown"],
        "compliance_frameworks": framework_stats,
        "recommendations_count": severity_counts["critical"] + severity_counts["high"] + severity_counts["medium"]
    }


def _get_trending_metrics(recent_scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-day security metrics computed from the scans that actually ran.

    This used to invent them:

        # In a real implementation, this would query historical scan data
        # For now, we'll simulate trending data
        base_score = 65 + (i * 0.5)          # Gradual improvement
        score = min(95, base_score + (i % 7))  # Weekly variations

    -- a curve that always improved, on an account that had never been scanned,
    presented to the reader as their security posture over time. An empty
    history now yields an empty list, which the dashboard can render as "no
    data" rather than as reassuring progress.

    ``recent_scans`` is what the executive-summary endpoint has already
    gathered: ``{"metadata": {...}, "results": {...}}`` per scan.
    """
    by_date: Dict[str, Dict[str, int]] = {}

    for scan in recent_scans:
        started = (scan.get("metadata") or {}).get("started_at") or ""
        day = started[:10]
        if not day:
            continue
        bucket = by_date.setdefault(
            day, {"critical": 0, "high": 0, "failed": 0, "passed": 0, "evaluated": 0}
        )
        for result in (scan.get("results") or {}).get("results", []):
            status = result.get("status")
            if status not in ("passed", "failed"):
                # not_implemented / skipped / error say nothing about posture
                continue
            bucket["evaluated"] += 1
            if status == "passed":
                bucket["passed"] += 1
                continue
            bucket["failed"] += 1
            severity = _severity_for_check(result.get("check_id"))
            if severity == "critical":
                bucket["critical"] += 1
            elif severity == "high":
                bucket["high"] += 1

    trending = []
    for day in sorted(by_date):
        bucket = by_date[day]
        evaluated = bucket["evaluated"]
        trending.append(
            {
                "date": day,
                "security_score": (
                    round(bucket["passed"] / evaluated * 100, 1) if evaluated else 0.0
                ),
                "critical_findings": bucket["critical"],
                "high_findings": bucket["high"],
                "total_findings": bucket["failed"],
            }
        )
    return trending


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


def _generate_remediation_roadmap(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate a prioritized remediation roadmap.
    """
    if not scan_results.get('results'):
        return []
    
    results = scan_results['results']
    failed_results = [r for r in results if r.get('status') == 'failed']
    
    # Group by remediation steps
    remediation_groups = {}
    
    for result in failed_results:
        remediation = result.get('remediation', 'No specific remediation provided')
        
        if remediation not in remediation_groups:
            remediation_groups[remediation] = {
                "remediation": remediation,
                "affected_resources": [],
                "estimated_effort": "Medium",  # This would be calculated based on resource types
                "priority": "High",  # This would be calculated based on severity
                "compliance_impact": []
            }
        
        remediation_groups[remediation]["affected_resources"].append({
            "resource_id": result.get('resource_id'),
            "resource_type": result.get('resource_type'),
            "region": result.get('region'),
            "check_id": result.get('check_id')
        })
        
        # Add compliance frameworks
        frameworks = result.get('compliance_frameworks', [])
        for framework in frameworks:
            if framework not in remediation_groups[remediation]["compliance_impact"]:
                remediation_groups[remediation]["compliance_impact"].append(framework)
    
    # Convert to list and sort by number of affected resources
    roadmap = list(remediation_groups.values())
    roadmap.sort(key=lambda x: len(x["affected_resources"]), reverse=True)
    
    # Add priority scoring
    for i, item in enumerate(roadmap):
        item["priority_score"] = len(item["affected_resources"]) * 10 + len(item["compliance_impact"]) * 5
        item["order"] = i + 1

    return roadmap[:10]  # Return top 10 prioritized items


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
