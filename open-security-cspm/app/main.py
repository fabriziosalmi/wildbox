"""
FastAPI main application for Open Security CSMP
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import uuid
import redis
import json

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn

from .config import settings
from .worker import celery_app, run_cspm_scan_task, get_available_checks_task, health_check_task
from .checks.runner import check_runner
from .checks.framework import CloudProvider
from . import schemas
from .utils import (
    _estimate_scan_duration, _calculate_compliance_score, _generate_executive_summary,
    _get_trending_metrics, _get_resource_inventory_summary, _generate_remediation_roadmap
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format=settings.log_format
)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Cloud Security Posture Management for Wildbox Security Suite",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

# Security
security = HTTPBearer(auto_error=False)

# Redis client for caching
redis_client = redis.from_url(settings.redis_url, decode_responses=True)

# Application state
app_start_time = datetime.utcnow()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Get current user from token.
    For v1, we'll implement basic auth. In production, integrate with wildbox-identity.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    # TODO: Integrate with wildbox-identity service for proper authentication
    # For now, accept any token for development
    return {"user_id": "dev_user", "team_id": "dev_team"}


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
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return schemas.HealthCheckResponse(
            status="unhealthy",
            timestamp=datetime.utcnow(),
            version=settings.app_version,
            checks={
                "api": "unhealthy",
                "error": str(e)
            }
        )


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
        
        # Prepare scan configuration for worker
        scan_config = {
            "provider": scan_request.provider.value,
            "credentials": scan_request.credentials.model_dump(),
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
            timedelta(days=30).total_seconds(),
            json.dumps(scan_metadata)
        )
        
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
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start scan: {str(e)}"
        )


@app.get("/api/v1/scans/{scan_id}", response_model=schemas.ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
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
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan status: {str(e)}"
        )


@app.get("/api/v1/scans/{scan_id}/report", response_model=schemas.ScanReportSchema)
async def get_scan_report(
    scan_id: str,
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
                detail=f"Scan is not completed. Current status: {task_result.status}"
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
    except Exception as e:
        logger.error(f"Failed to get scan report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan report: {str(e)}"
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
        
    except Exception as e:
        logger.error(f"Failed to list checks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list checks: {str(e)}"
        )


@app.get("/api/v1/scans/{scan_id}/compliance", response_model=schemas.ComplianceReportResponse)
async def get_compliance_report(
    scan_id: str,
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
                schemas.ComplianceFrameworkSummary(
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
    except Exception as e:
        logger.error(f"Failed to generate compliance report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate compliance report: {str(e)}"
        )


@app.delete("/api/v1/scans/{scan_id}")
async def cancel_scan(
    scan_id: str,
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
            timedelta(days=30).total_seconds(),
            json.dumps(metadata)
        )
        
        logger.info(f"Cancelled scan {scan_id}")
        
        return {"message": "Scan cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel scan: {str(e)}"
        )


# Dashboard and metrics endpoints

@app.get("/api/v1/dashboard/summary", response_model=schemas.DashboardSummaryResponse)
async def get_dashboard_summary(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get summary for dashboard."""
    try:
        # Get all scans for the team
        team_scans = []
        cursor = 0
        while True:
            # Scan Redis for scan metadata
            scan_keys = redis_client.scan_iter(
                match=f"scan:*:metadata",
                count=1000,
                cursor=cursor
            )
            
            for key in scan_keys:
                metadata = json.loads(redis_client.get(key))
                if metadata.get("team_id") == current_user["team_id"]:
                    team_scans.append(metadata)
            
            # If cursor is 0, we have scanned all keys
            if cursor == 0:
                break
            
            cursor = 0  # For next iteration, set cursor to 0 to continue scanning
        
        # Calculate summary metrics
        total_scans = len(team_scans)
        total_resources = sum(len(s["resources"]) for s in team_scans)
        total_findings = sum(s["summary"].get("total_findings", 0) for s in team_scans)
        total_passed = sum(s["summary"].get("passed", 0) for s in team_scans)
        total_failed = sum(s["summary"].get("failed", 0) for s in team_scans)
        total_skipped = sum(s["summary"].get("skipped", 0) for s in team_scans)
        
        # Get trending metrics
        trending_metrics = _get_trending_metrics(current_user["team_id"])
        
        return schemas.DashboardSummaryResponse(
            total_scans=total_scans,
            total_resources=total_resources,
            total_findings=total_findings,
            total_passed=total_passed,
            total_failed=total_failed,
            total_skipped=total_skipped,
            trending_metrics=trending_metrics
        )
        
    except Exception as e:
        logger.error(f"Failed to get dashboard summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get dashboard summary: {str(e)}"
        )


@app.get("/api/v1/dashboard/executive-summary", response_model=schemas.ExecutiveSummaryResponse)
async def get_executive_summary(
    provider: Optional[str] = None,
    days: int = 30,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get executive summary with high-level security metrics."""
    try:
        # Get recent scans for the team
        recent_scans = []
        scan_keys = redis_client.scan_iter(match=f"scan:*:metadata")
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        for key in scan_keys:
            try:
                metadata = json.loads(redis_client.get(key))
                if (metadata.get("team_id") == current_user["team_id"] and 
                    datetime.fromisoformat(metadata.get("started_at", "")) >= cutoff_date):
                    
                    if not provider or metadata.get("provider") == provider:
                        # Get scan results
                        scan_id = metadata["scan_id"]
                        results_key = f"scan:{scan_id}:results"
                        results_data = redis_client.get(results_key)
                        
                        if results_data:
                            results = json.loads(results_data)
                            recent_scans.append({
                                "metadata": metadata,
                                "results": results
                            })
            except Exception as e:
                logger.warning(f"Error processing scan metadata: {e}")
                continue
        
        # Generate executive summary from all recent scans
        all_results = []
        for scan in recent_scans:
            all_results.extend(scan.get("results", {}).get("results", []))
        
        executive_summary = _generate_executive_summary({"results": all_results})
        
        # Get trending data
        trending_metrics = _get_trending_metrics(redis_client, provider or "all", current_user["team_id"], days)
        
        return schemas.ExecutiveSummaryResponse(
            summary_period_days=days,
            provider_filter=provider,
            security_posture=executive_summary,
            trending_metrics=trending_metrics,
            scan_coverage={
                "total_scans": len(recent_scans),
                "providers_covered": list(set(s["metadata"]["provider"] for s in recent_scans)),
                "accounts_covered": list(set(s["metadata"]["account_id"] for s in recent_scans))
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get executive summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get executive summary: {str(e)}"
        )


@app.get("/api/v1/scans/{scan_id}/remediation-roadmap", response_model=schemas.RemediationRoadmapResponse)
async def get_remediation_roadmap(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get prioritized remediation roadmap for a scan."""
    try:
        # Get scan results
        results_key = f"scan:{scan_id}:results"
        results_data = redis_client.get(results_key)
        
        if not results_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan results not found"
            )
        
        results = json.loads(results_data)
        
        # Generate remediation roadmap
        roadmap = _generate_remediation_roadmap(results)
        
        return schemas.RemediationRoadmapResponse(
            scan_id=scan_id,
            generated_at=datetime.utcnow(),
            total_remediation_items=len(roadmap),
            roadmap=roadmap
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get remediation roadmap: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get remediation roadmap: {str(e)}"
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
            
            # Prepare scan configuration for worker
            scan_config_dict = {
                "provider": scan_config.provider.value,
                "credentials": scan_config.credentials.model_dump(),
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
        
    except Exception as e:
        logger.error(f"Failed to start batch scans: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start batch scans: {str(e)}"
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
        ).model_dump()
    )


@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    """Handle validation errors."""
    return JSONResponse(
        status_code=400,
        content=schemas.ErrorResponse(
            error="ValidationError",
            message=str(exc)
        ).model_dump()
    )


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=1 if settings.debug else settings.workers
    )
