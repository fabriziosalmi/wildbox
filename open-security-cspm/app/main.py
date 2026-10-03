"""
FastAPI main application for Open Security CSPM
"""

import asyncio
import hmac
import logging
import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import uuid
import redis
import json

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status, Request, Path, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .config import settings
from .credential_crypto import encrypt_credentials
from open_security_shared.gateway_auth import get_user_from_gateway_headers
from .worker import celery_app, run_cspm_scan_task, get_available_checks_task, health_check_task
from .checks.runner import check_runner
from .checks.framework import CloudProvider
from . import schemas
from .utils import (
    _estimate_scan_duration, _summarize_compliance, _compliance_findings,
    _count_failed_by_severity,
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format=settings.log_format
)
logger = logging.getLogger(__name__)

# Conditionally expose API docs (disabled in production)
_docs_url = "/docs" if settings.debug else None
_redoc_url = "/redoc" if settings.debug else None
_openapi_url = "/openapi.json" if settings.debug else None

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Cloud Security Posture Management for Wildbox Security Suite",
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url
)

# Canonical error contract + correlation id + Prometheus metrics.
# One shape for every Wildbox service (see open_security_shared.errors).
from open_security_shared.errors import install_error_handlers as _install_error_handlers
from open_security_shared.observability import install_observability as _install_observability

_install_error_handlers(app)
_install_observability(app, service_name="cspm", service_version=settings.app_version)


# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

# Redis client for caching
redis_client = redis.from_url(settings.redis_url, decode_responses=True)


# --- Per-team scan index (tenancy) -------------------------------------------
# Scans are stored under flat keys (scan:{id}:metadata). To scope reads by team
# WITHOUT scanning every team's keys, each team keeps a Redis SET of its scan
# ids. Dashboards iterate the caller's set instead of `scan:*:metadata`.
# Scan retention. NOTE: must be an int — redis SETEX rejects a float TTL with
# "value is not an integer or out of range".
_SCAN_TTL_SECONDS = int(timedelta(days=30).total_seconds())


def _team_scans_key(team_id: str) -> str:
    return f"cspm:team:{team_id}:scans"


def _index_team_scan(team_id: str, scan_id: str) -> None:
    """Record that ``scan_id`` belongs to ``team_id``."""
    key = _team_scans_key(team_id)
    redis_client.sadd(key, scan_id)
    # Keep the index alive at least as long as scan metadata.
    redis_client.expire(key, _SCAN_TTL_SECONDS)


def _iter_team_scan_metadata(team_id: str):
    """Yield metadata dicts for the team's scans via its index set, skipping
    any whose metadata has expired or fails to parse."""
    for scan_id in redis_client.smembers(_team_scans_key(team_id)):
        raw = redis_client.get(f"scan:{scan_id}:metadata")
        if not raw:
            continue
        try:
            yield json.loads(raw)
        except (ValueError, TypeError):
            continue

# Application state
app_start_time = datetime.utcnow()

# UUID regex for path parameter validation
_UUID_REGEX = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# Gateway authentication.
#
# This used to be a hand-rolled copy of the shared dependency: it repeated the
# secret comparison, the fail-closed branch and the header extraction, and
# returned a plain dict where the shared one returns a GatewayUser -- so the two
# had to be changed in lockstep and their call sites were not interchangeable
# (WILDBO-QUAL-04). CSPM was the only service of five not using the shared code.
#
# A thin adapter keeps the dict shape this module's handlers expect.
async def get_current_user(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
    x_gateway_secret: Optional[str] = Header(None, alias="X-Gateway-Secret"),
) -> Dict[str, str]:
    """Authenticate via gateway-injected headers (shared implementation)."""
    user = await get_user_from_gateway_headers(
        x_wildbox_user_id=x_wildbox_user_id,
        x_wildbox_team_id=x_wildbox_team_id,
        x_wildbox_role=x_wildbox_role,
        x_gateway_secret=x_gateway_secret,
    )
    return {
        "user_id": str(user.user_id),
        "team_id": str(user.team_id),
        "role": getattr(user, "role", "member"),
    }


@app.get("/health/live")
async def liveness():
    """Liveness probe: the HTTP process is up. Unlike /health (readiness) it
    does NOT require Redis or an active Celery worker, so orchestration can
    distinguish "process alive" from "dependencies ready"."""
    return {"status": "alive"}


@app.get("/health", response_model=schemas.HealthCheckResponse)
async def health_check():
    """Health check endpoint."""
    try:
        # Check Redis connectivity
        redis_status = "healthy" if redis_client.ping() else "unhealthy"
        
        # Check Celery worker status
        celery_inspect = celery_app.control.inspect()
        active_workers = celery_inspect.active()
        celery_status = "healthy" if active_workers else "unhealthy"
        
        # Calculate uptime
        uptime = (datetime.utcnow() - app_start_time).total_seconds()
        
        overall_status = "healthy" if all([
            redis_status == "healthy",
            celery_status == "healthy"
        ]) else "degraded"
        
        return schemas.HealthCheckResponse(
            status=overall_status,
            timestamp=datetime.utcnow(),
            version=settings.app_version,
            uptime_seconds=uptime,
            checks={
                "redis": redis_status,
                "celery": celery_status,
                "api": "healthy"
            }
        )
    except (ConnectionError, TimeoutError) as e:
        logger.error(f"Health check connection error: {e}")
        return schemas.HealthCheckResponse(
            status="degraded",
            timestamp=datetime.utcnow(),
            version=settings.app_version,
            checks={
                "api": "degraded",
                "error": "Service connection issue"
            }
        )
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Health check unexpected error: {type(e).__name__}: {e}")
        return schemas.HealthCheckResponse(
            status="unhealthy",
            timestamp=datetime.utcnow(),
            version=settings.app_version,
            checks={
                "api": "unhealthy",
                "error": str(type(e).__name__)
            }
        )


# #182 policy: starting/cancelling a scan is an operational action, member-
# allowed (gated by gateway auth + per-team scan ownership, not by role).
# CSPM has no configuration-mutation endpoint that would require owner/admin.
@app.post(
    "/api/v1/scans",
    response_model=schemas.ScanResponse,
    status_code=status.HTTP_202_ACCEPTED
)
async def start_scan(
    scan_request: schemas.ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Start a new CSPM scan.
    
    This endpoint accepts scan configuration and starts an asynchronous scan job.
    The scan will be executed by Celery workers in the background.
    """
    try:
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Store credentials encrypted, with a short TTL.
        #
        # Keeping them out of the Celery task args was the right instinct, but
        # the replacement wrote the same plaintext to the same Redis -- which
        # runs with --appendonly yes, so an AWS secret access key, an Azure
        # client secret or a GCP service-account JSON landed in the AOF on the
        # wildbox_redis_data volume and stayed there until a rewrite, outliving
        # the 5-minute TTL and the worker's explicit delete (WILDBO-SEC-02).
        #
        # The models mark these fields repr=False, which protects tracebacks and
        # logs; model_dump() ignores repr, so serialisation needed its own
        # protection. Encryption is envelope-style with a service-held key: an
        # attacker with the Redis volume gets ciphertext.
        cred_key = f"scan:{scan_id}:creds"
        redis_client.setex(
            cred_key,
            300,  # 5 minute TTL
            encrypt_credentials(scan_request.credentials.model_dump())
        )

        # Prepare scan configuration for worker (NO credentials in task args)
        scan_config = {
            "provider": scan_request.provider.value,
            "credential_ref": cred_key,
            "account_id": scan_request.account_id,
            "account_name": scan_request.account_name,
            "regions": scan_request.regions,
            "check_ids": scan_request.check_ids,
            "metadata": {
                **scan_request.metadata,
                "requested_by": current_user["user_id"],
                "team_id": current_user["team_id"]
            }
        }

        # Start Celery task
        task = run_cspm_scan_task.apply_async(
            args=[scan_config],
            task_id=scan_id
        )
        
        # Cache scan metadata
        scan_metadata = {
            "scan_id": scan_id,
            "provider": scan_request.provider.value,
            "account_id": scan_request.account_id,
            "account_name": scan_request.account_name,
            "status": "started",
            "started_at": datetime.utcnow().isoformat(),
            "requested_by": current_user["user_id"],
            "team_id": current_user["team_id"]
        }
        
        redis_client.setex(
            f"scan:{scan_id}:metadata",
            _SCAN_TTL_SECONDS,
            json.dumps(scan_metadata)
        )
        # Namespace the scan under its team so reads never scan other teams' keys.
        _index_team_scan(current_user["team_id"], scan_id)

        logger.info(f"Started CSPM scan {scan_id} for {scan_request.provider} account {scan_request.account_id}")
        
        return schemas.ScanResponse(
            scan_id=scan_id,
            status="started",
            provider=scan_request.provider.value,
            account_id=scan_request.account_id,
            started_at=datetime.utcnow(),
            estimated_duration_minutes=_estimate_scan_duration(
                scan_request.provider,
                scan_request.regions,
                scan_request.check_ids
            )
        )
        
    except (ConnectionError, TimeoutError) as e:
        logger.error(f"Task queue connection error starting scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Task queue temporarily unavailable"
        )
    except ValueError as e:
        logger.error(f"Invalid scan configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan configuration"
        )


@app.get("/api/v1/scans/{scan_id}", response_model=schemas.ScanStatusResponse)
async def get_scan_status(
    scan_id: str = Path(..., pattern=_UUID_REGEX),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get the status of a running or completed scan."""
    try:
        # Get task result
        task_result = celery_app.AsyncResult(scan_id)
        
        # Get cached metadata
        metadata_json = redis_client.get(f"scan:{scan_id}:metadata")
        if not metadata_json:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        metadata = json.loads(metadata_json)
        
        # Check authorization (user can only see their own scans)
        if metadata.get("team_id") != current_user["team_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get task status and result
        task_status = task_result.status
        task_info = task_result.info or {}
        
        # Map Celery status to our status
        status_mapping = {
            "PENDING": "queued",
            "PROGRESS": "running",
            "SUCCESS": "completed",
            "FAILURE": "failed",
            "REVOKED": "cancelled"
        }
        
        scan_status = status_mapping.get(task_status, "unknown")
        
        response = schemas.ScanStatusResponse(
            scan_id=scan_id,
            status=scan_status,
            provider=metadata["provider"],
            account_id=metadata["account_id"],
            started_at=datetime.fromisoformat(metadata["started_at"])
        )
        
        # Add completion time if available
        if scan_status == "completed" and isinstance(task_info, dict):
            response.completed_at = datetime.fromisoformat(task_info.get("completed_at", metadata["started_at"]))
        
        # Add progress information if available
        if scan_status == "running" and isinstance(task_info, dict):
            response.progress = {
                "current_status": task_info.get("status", "running"),
                "total_checks": task_info.get("total_checks"),
                "completed_checks": task_info.get("completed_checks"),
                "current_region": task_info.get("current_region")
            }
        
        return response
        
    except HTTPException:
        raise
    except (ConnectionError, KeyError) as e:
        logger.error(f"Failed to get scan status for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    except ValueError as e:
        logger.error(f"Invalid scan data for {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan data integrity error"
        )


@app.get("/api/v1/scans/{scan_id}/report", response_model=schemas.ScanReportSchema)
async def get_scan_report(
    scan_id: str = Path(..., pattern=_UUID_REGEX),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get the complete report for a completed scan."""
    try:
        # Get task result
        task_result = celery_app.AsyncResult(scan_id)
        
        # Check if scan is completed
        if task_result.status != "SUCCESS":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan is not completed"
            )
        
        # Get cached metadata for authorization check
        metadata_json = redis_client.get(f"scan:{scan_id}:metadata")
        if not metadata_json:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        metadata = json.loads(metadata_json)
        
        # Check authorization
        if metadata.get("team_id") != current_user["team_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get scan results
        result = task_result.result
        if not result or "report" not in result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Scan report not available"
            )
        
        # Convert to response schema
        report_data = result["report"]
        report_schema = schemas.ScanReportSchema(**report_data)
        
        return report_schema
        
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to get scan report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scan report"
        )


@app.get("/api/v1/checks", response_model=schemas.ChecksListResponse)
async def list_checks(
    provider: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List available security checks."""
    try:
        # Get available checks
        provider_enum = CloudProvider(provider) if provider else None
        checks = check_runner.get_available_checks(provider_enum)
        
        # Apply filters
        if category:
            checks = [c for c in checks if c["category"].lower() == category.lower()]
        
        if severity:
            checks = [c for c in checks if c["severity"].lower() == severity.lower()]
        
        # Get unique values for metadata
        providers = list(set(c["provider"] for c in checks))
        categories = list(set(c["category"] for c in checks))
        
        return schemas.ChecksListResponse(
            total_checks=len(checks),
            checks=[schemas.CheckMetadataSchema(**check) for check in checks],
            providers=providers,
            categories=categories
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to list checks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list checks"
        )


@app.get("/api/v1/scans/{scan_id}/compliance", response_model=schemas.ComplianceReportResponse)
async def get_compliance_report(
    scan_id: str = Path(..., pattern=_UUID_REGEX),
    framework: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get compliance-focused report for a scan."""
    try:
        # Get scan report first
        scan_report = await get_scan_report(scan_id, current_user)
        
        # Generate compliance report
        frameworks_summary = []
        
        # Group results by compliance framework
        framework_results = {}
        for result in scan_report.results:
            for fw in result.compliance_frameworks:
                if framework and fw != framework:
                    continue
                    
                if fw not in framework_results:
                    framework_results[fw] = {"total": 0, "passed": 0, "failed": 0}
                
                framework_results[fw]["total"] += 1
                if result.status == "passed":
                    framework_results[fw]["passed"] += 1
                elif result.status == "failed":
                    framework_results[fw]["failed"] += 1
        
        # Create framework summaries
        for fw, stats in framework_results.items():
            compliance_percentage = (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0
            frameworks_summary.append(
                schemas.ComplianceReportFrameworkSummary(
                    framework=fw,
                    total_checks=stats["total"],
                    passed_checks=stats["passed"],
                    failed_checks=stats["failed"],
                    compliance_percentage=compliance_percentage
                )
            )
        
        # Calculate overall score
        total_framework_checks = sum(fw.total_checks for fw in frameworks_summary)
        total_passed = sum(fw.passed_checks for fw in frameworks_summary)
        overall_score = (total_passed / total_framework_checks * 100) if total_framework_checks > 0 else 0
        
        return schemas.ComplianceReportResponse(
            scan_id=scan_id,
            account_id=scan_report.account_id,
            generated_at=datetime.utcnow(),
            frameworks=frameworks_summary,
            overall_score=overall_score,
            recommendations=scan_report.summary.get("recommendations", [])
        )
        
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to generate compliance report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate compliance report"
        )


@app.delete("/api/v1/scans/{scan_id}")
async def cancel_scan(
    scan_id: str = Path(..., pattern=_UUID_REGEX),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Cancel a running scan."""
    try:
        # Check if scan exists and user has access
        metadata_json = redis_client.get(f"scan:{scan_id}:metadata")
        if not metadata_json:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        metadata = json.loads(metadata_json)
        
        # Check authorization
        if metadata.get("team_id") != current_user["team_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Revoke the Celery task
        celery_app.control.revoke(scan_id, terminate=True)
        
        # Update metadata
        metadata["status"] = "cancelled"
        metadata["cancelled_at"] = datetime.utcnow().isoformat()
        redis_client.setex(
            f"scan:{scan_id}:metadata",
            _SCAN_TTL_SECONDS,
            json.dumps(metadata)
        )
        
        logger.info(f"Cancelled scan {scan_id}")
        
        return {"message": "Scan cancelled successfully"}
        
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to cancel scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel scan"
        )


# Dashboard and metrics endpoints

@app.get("/api/v1/dashboard/summary", response_model=schemas.DashboardSummaryResponse)
async def get_dashboard_summary(
    days: int = Query(30, ge=1, le=365),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Scan count and the figures of the team's newest completed scans.

    Findings, severities and the compliance score come from the same reports
    as GET /api/v1/compliance/summary: the newest completed scan of each of
    the team's accounts in the period. Severity is the one the check declares
    in its metadata. This endpoint used to read ``scan:{id}:results``, which
    nothing writes, so every figure was 0 even after a real scan, and it
    counted every scan as active because the stored scan status is never
    updated after the scan starts.
    """
    team_id = current_user["team_id"]
    try:
        # Get the team's scans via its index set (no cross-team key scanning).
        started_times = []
        total_scans = 0
        for metadata in _iter_team_scan_metadata(team_id):
            total_scans += 1
            try:
                started_times.append(datetime.fromisoformat(metadata["started_at"]))
            except (KeyError, ValueError, TypeError):
                continue

        reports = _team_compliance_reports(team_id, days, None)
        catalog = {check["check_id"]: check for check in check_runner.get_available_checks()}
        compliance = _summarize_compliance(reports)

        return schemas.DashboardSummaryResponse(
            total_scans=total_scans,
            last_scan_at=max(started_times) if started_times else None,
            summary_period_days=days,
            accounts_assessed=len(reports),
            compliance_score=compliance["overall_score"],
            **_count_failed_by_severity(_compliance_findings(reports, catalog)),
        )

    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to get dashboard summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get dashboard summary"
        )


@app.post("/api/v1/batch/scans", response_model=schemas.BatchScanResponse)
async def start_batch_scans(
    batch_request: schemas.BatchScanRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Start multiple CSPM scans across different accounts or providers."""
    try:
        batch_id = str(uuid.uuid4())
        scan_jobs = []
        
        for scan_config in batch_request.scans:
            # Generate individual scan ID
            scan_id = str(uuid.uuid4())

            # Store credentials securely with short TTL
            cred_key = f"scan:{scan_id}:creds"
            redis_client.setex(
                cred_key,
                300,
                json.dumps(scan_config.credentials.model_dump())
            )

            # Prepare scan configuration for worker (NO credentials in task args)
            scan_config_dict = {
                "provider": scan_config.provider.value,
                "credential_ref": cred_key,
                "account_id": scan_config.account_id,
                "account_name": scan_config.account_name,
                "regions": scan_config.regions,
                "check_ids": scan_config.check_ids,
                "metadata": {
                    **scan_config.metadata,
                    "batch_id": batch_id,
                    "requested_by": current_user["user_id"],
                    "team_id": current_user["team_id"]
                }
            }
            
            # Start Celery task
            task = run_cspm_scan_task.apply_async(
                args=[scan_config_dict],
                task_id=scan_id
            )

            # Namespace the scan under its team (consistent with single scans).
            _index_team_scan(current_user["team_id"], scan_id)

            scan_jobs.append({
                "scan_id": scan_id,
                "provider": scan_config.provider.value,
                "account_id": scan_config.account_id,
                "task_id": task.id,
                "status": "started"
            })
            
        logger.info(f"Started batch scan {batch_id} with {len(scan_jobs)} individual scans")
        
        return schemas.BatchScanResponse(
            batch_id=batch_id,
            total_scans=len(scan_jobs),
            scans=scan_jobs,
            started_at=datetime.utcnow()
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to start batch scans: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start batch scans"
        )


def _team_compliance_reports(
    team_id: str, days: int, provider: Optional[str]
) -> List[Dict[str, Any]]:
    """The newest completed scan report of each of the team's accounts.

    Reports live in the Celery result backend, as GET /api/v1/scans/{id}/report
    reads them. Scans that started before the period, are not finished, or
    whose result has expired are skipped; an older scan of an account that
    was scanned again is superseded by the newer one.
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    newest: Dict[tuple, tuple] = {}
    for metadata in _iter_team_scan_metadata(team_id):
        if provider and metadata.get("provider") != provider:
            continue
        try:
            started = datetime.fromisoformat(metadata["started_at"])
        except (KeyError, ValueError, TypeError):
            continue
        if started < cutoff:
            continue
        task_result = celery_app.AsyncResult(metadata["scan_id"])
        if task_result.status != "SUCCESS":
            continue
        result = task_result.result
        if not isinstance(result, dict) or not isinstance(result.get("report"), dict):
            continue
        key = (metadata.get("provider"), metadata.get("account_id"))
        if key not in newest or started > newest[key][0]:
            newest[key] = (started, result["report"])
    return [report for _, report in newest.values()]


@app.get("/api/v1/compliance/summary", response_model=schemas.ComplianceSummaryResponse)
async def get_compliance_summary(
    days: int = Query(30, ge=1, le=365),
    provider: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Compliance across the newest completed scan of each of the team's accounts.

    With no completed scan in the period every count is 0, ``frameworks`` is
    empty and ``overall_score`` is null. This endpoint used to return the same
    invented account (1547 resources, 86.7%) to every team.
    """
    try:
        reports = _team_compliance_reports(current_user["team_id"], days, provider)
        return {
            **_summarize_compliance(reports),
            "summary_period_days": days,
            "provider_filter": provider,
        }
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to get compliance summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get compliance summary"
        )


@app.get("/api/v1/compliance/findings", response_model=schemas.ComplianceFindingsResponse)
async def get_compliance_findings(
    framework: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    days: int = Query(30, ge=1, le=365),
    provider: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Check verdicts from the newest completed scan of each of the team's accounts.

    This endpoint used to return five invented findings to every team.
    """
    try:
        reports = _team_compliance_reports(current_user["team_id"], days, provider)
        catalog = {check["check_id"]: check for check in check_runner.get_available_checks()}
        findings = _compliance_findings(reports, catalog)

        if framework:
            findings = [f for f in findings if framework in f["frameworks"]]
        if severity:
            findings = [f for f in findings if f["severity"] == severity]
        if status_filter:
            findings = [f for f in findings if f["status"] == status_filter]

        total_count = len(findings)
        return {
            "findings": findings[offset:offset + limit],
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total_count
        }
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to get compliance findings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get compliance findings"
        )


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=schemas.ErrorResponse(
            error="HTTPException",
            message=str(exc.detail),
            details={"status_code": exc.status_code}
        ).model_dump(mode="json")
    )


@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    """Handle validation errors."""
    return JSONResponse(
        status_code=400,
        content=schemas.ErrorResponse(
            error="ValidationError",
            message="Validation error"
        ).model_dump(mode="json")
    )


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=1 if settings.debug else settings.workers
    )
