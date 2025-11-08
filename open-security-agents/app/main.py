"""
FastAPI main application for Open Security Agents

AI-powered threat intelligence enrichment service.
"""

import logging
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import redis
from celery.result import AsyncResult

from .schemas import (
    AnalysisTaskRequest, AnalysisTaskStatus, AnalysisResult,
    HealthResponse, StatsResponse, TaskStatus
)
from .config import settings
from .worker import celery_app, run_threat_enrichment_task

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Global state
app_start_time = datetime.now(timezone.utc)
redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global redis_client
    
    # Startup
    logger.info("Starting Open Security Agents...")
    
    try:
        # Test Redis connection
        redis_client = redis.from_url(settings.redis_url)
        redis_client.ping()
        logger.info("Redis connection established")
        
        # Test OpenAI API key
        if not settings.openai_api_key or settings.openai_api_key == "your_openai_api_key_here":
            logger.warning("OpenAI API key not configured - AI analysis will fail")
        else:
            logger.info("OpenAI API key configured")
        
        # Test Celery connection
        try:
            celery_app.control.inspect().ping()
            logger.info("Celery connection established")
        except Exception as e:
            logger.warning(f"Celery connection failed: {e}")
        
        logger.info("Open Security Agents started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Open Security Agents...")


# Determine if running in production
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DISABLE_DOCS = ENVIRONMENT == "production"

# Initialize FastAPI app
app = FastAPI(
    title="Open Security Agents API",
    description="AI-powered threat intelligence enrichment service",
    version="0.1.5",
    docs_url=None if DISABLE_DOCS else "/docs",
    redoc_url=None if DISABLE_DOCS else "/redoc",
    openapi_url=None if DISABLE_DOCS else "/openapi.json",
    lifespan=lifespan
)


# Add Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


app.add_middleware(SecurityHeadersMiddleware)


# Setup CORS with environment-aware configuration
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    services = {}
    
    # Check Redis
    try:
        redis_client.ping()
        services["redis"] = "healthy"
    except Exception:
        services["redis"] = "unhealthy"
    
    # Check Celery
    try:
        celery_app.control.inspect().ping()
        services["celery"] = "healthy"
    except Exception:
        services["celery"] = "unhealthy"
    
    # Check OpenAI
    if settings.openai_api_key and settings.openai_api_key != "your_openai_api_key_here":
        services["openai"] = "configured"
    else:
        services["openai"] = "not_configured"
    
    overall_status = "healthy" if all(s in ["healthy", "configured"] for s in services.values()) else "unhealthy"
    
    return HealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        version="0.1.5",
        services=services
    )


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get service statistics"""
    try:
        # Get Celery stats
        inspect = celery_app.control.inspect()
        active_tasks = inspect.active()
        scheduled_tasks = inspect.scheduled()
        
        # Count tasks
        pending_count = 0
        running_count = 0
        
        if active_tasks:
            for worker, tasks in active_tasks.items():
                running_count += len(tasks)
        
        if scheduled_tasks:
            for worker, tasks in scheduled_tasks.items():
                pending_count += len(tasks)
        
        # Calculate uptime
        uptime = (datetime.now(timezone.utc) - app_start_time).total_seconds()
        
        # Get basic stats from Redis (could be enhanced with more detailed tracking)
        total_analyses = redis_client.get("stats:total_analyses") or 0
        completed_today = redis_client.get("stats:completed_today") or 0
        failed_today = redis_client.get("stats:failed_today") or 0
        
        return StatsResponse(
            total_analyses=int(total_analyses),
            pending_tasks=pending_count,
            running_tasks=running_count,
            completed_today=int(completed_today),
            failed_today=int(failed_today),
            average_duration=None,  # Could be calculated from historical data
            uptime_seconds=uptime
        )
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve statistics"
        )


@app.post("/v1/analyze", response_model=AnalysisTaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def analyze_ioc(
    request: AnalysisTaskRequest,
    authorization: str = Header(None)
):
    """
    Submit an IOC for AI-powered threat analysis.

    Requires Bearer token authentication. Include header:
        Authorization: Bearer <token>

    This endpoint accepts an IOC and starts an asynchronous analysis task.
    The analysis is performed by an AI agent that uses various security tools
    to investigate the IOC and generate a comprehensive threat intelligence report.
    """
    # Authenticate request
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract token from "Bearer <token>" format
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Use: Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    logger.info(f"Authenticated request to analyze IOC: {request.ioc.type}:{request.ioc.value}")
    try:
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Create task metadata
        task_metadata = {
            "task_id": task_id,
            "ioc": request.ioc.dict(),
            "priority": request.priority,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": TaskStatus.PENDING
        }
        
        # Store task metadata in Redis
        redis_client.setex(
            f"task:{task_id}:metadata",
            settings.task_result_expires,
            json.dumps(task_metadata)
        )
        
        # Submit Celery task
        celery_task = run_threat_enrichment_task.delay(
            task_id=task_id,
            ioc=request.ioc.dict()
        )
        
        # Store Celery task ID mapping
        redis_client.setex(
            f"task:{task_id}:celery_id",
            settings.task_result_expires,
            celery_task.id
        )
        
        logger.info(f"Started analysis task {task_id} for IOC {request.ioc.type}:{request.ioc.value}")
        
        # Increment stats
        redis_client.incr("stats:total_analyses")
        
        return AnalysisTaskStatus(
            task_id=task_id,
            status=TaskStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            result_url=f"/v1/analyze/{task_id}"
        )
        
    except Exception as e:
        logger.error(f"Error submitting analysis task: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit analysis task"
        )


@app.get("/v1/analyze/{task_id}")
async def get_analysis_result(task_id: str):
    """
    Get the status and results of an analysis task
    
    Returns the current status of the task. If completed, returns the full
    analysis result including the AI-generated report.
    """
    try:
        # Get Celery task ID
        celery_task_id = redis_client.get(f"task:{task_id}:celery_id")
        if not celery_task_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        # Get Celery task result
        celery_task = AsyncResult(celery_task_id.decode(), app=celery_app)
        
        # Get task metadata
        task_metadata_str = redis_client.get(f"task:{task_id}:metadata")
        if task_metadata_str:
            # Parse metadata using secure JSON deserialization
            task_metadata = json.loads(task_metadata_str.decode())
        else:
            task_metadata = {"created_at": datetime.now(timezone.utc).isoformat()}
        
        # Determine current status
        if celery_task.state == "PENDING":
            status_value = TaskStatus.PENDING
        elif celery_task.state == "STARTED":
            status_value = TaskStatus.RUNNING
        elif celery_task.state == "SUCCESS":
            status_value = TaskStatus.COMPLETED
        elif celery_task.state == "FAILURE":
            status_value = TaskStatus.FAILED
        else:
            status_value = TaskStatus.PENDING
        
        # If task is completed successfully, return full result
        if celery_task.state == "SUCCESS" and celery_task.result:
            return AnalysisResult(**celery_task.result)
        
        # If task failed, include error information
        error_message = None
        if celery_task.state == "FAILURE":
            error_message = str(celery_task.info) if celery_task.info else "Task failed"
        
        # Return status information
        return AnalysisTaskStatus(
            task_id=task_id,
            status=status_value,
            created_at=datetime.fromisoformat(task_metadata["created_at"]),
            started_at=datetime.now(timezone.utc) if status_value == TaskStatus.RUNNING else None,
            completed_at=datetime.now(timezone.utc) if status_value in [TaskStatus.COMPLETED, TaskStatus.FAILED] else None,
            progress=celery_task.info.get("progress") if isinstance(celery_task.info, dict) else None,
            error=error_message,
            result_url=f"/v1/analyze/{task_id}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting analysis result for task {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve analysis result"
        )


@app.delete("/v1/analyze/{task_id}")
async def cancel_analysis(task_id: str):
    """Cancel a pending or running analysis task"""
    try:
        # Get Celery task ID
        celery_task_id = redis_client.get(f"task:{task_id}:celery_id")
        if not celery_task_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        # Revoke the Celery task
        celery_app.control.revoke(celery_task_id.decode(), terminate=True)
        
        logger.info(f"Cancelled analysis task {task_id}")
        
        return {"message": "Task cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling task {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel task"
        )


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Open Security Agents",
        "description": "AI-powered threat intelligence enrichment service",
        "version": "1.0.0",
        "documentation": "/docs",
        "health": "/health",
        "stats": "/stats"
    }
