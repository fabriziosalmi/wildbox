"""
FastAPI main application for Open Security Responder

SOAR orchestration service with REST API interface.
"""

import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, status, Depends
from fastapi.responses import JSONResponse
import redis

from .models import (
    PlaybookExecutionRequest, PlaybookExecutionResult, 
    PlaybookListResponse, HealthCheckResponse
)
from .config import settings
from .playbook_parser import playbook_parser
from .workflow_engine import start_execution, workflow_engine
from .connectors.base import connector_registry
from .auth import get_current_user, require_role, GatewayUser

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    
    # Startup
    logger.info("Starting Open Security Responder...")
    
    try:
        # Load playbooks
        playbooks = playbook_parser.load_playbooks()
        logger.info(f"Loaded {len(playbooks)} playbooks")
        
        # Test Redis connection
        redis_client = redis.from_url(settings.redis_url)
        redis_client.ping()
        logger.info("Redis connection established")
        
        # Initialize connectors (placeholder for week 2)
        logger.info("Connector registry initialized")
        
        # Reconcile work interrupted by the previous process: a worker killed
        # mid-run leaves its record saying RUNNING, and nothing else ever
        # corrects it (WILDBO-REL-02).
        try:
            reaped = workflow_engine.reap_abandoned_runs()
            if reaped:
                logger.warning(f"Startup reconciliation marked {reaped} abandoned run(s) as FAILED")
        except Exception as e:
            # Reconciliation must never prevent the service from starting.
            logger.error(f"Startup reconciliation failed: {e}", exc_info=True)

        logger.info("Open Security Responder started successfully")
        
    except Exception as e:
        # Catch Exception: a Redis outage raises redis.exceptions.ConnectionError,
        # which does not subclass the builtin ConnectionError (WILDBO-ERR-03).
        logger.error(f"Failed to start application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Open Security Responder...")


# Determine if running in production
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DISABLE_DOCS = ENVIRONMENT == "production"

# Initialize FastAPI app
# One version, in one place (WILDBO-API-06): the constructor said 0.1.6 and the
# root endpoint reported 1.0.0.
SERVICE_VERSION = "0.1.6"

app = FastAPI(
    title="Open Security Responder API",
    description="SOAR (Security Orchestration, Automation and Response) microservice",
    version=SERVICE_VERSION,
    docs_url=None if DISABLE_DOCS else "/docs",
    redoc_url=None if DISABLE_DOCS else "/redoc",
    openapi_url=None if DISABLE_DOCS else "/openapi.json",
    lifespan=lifespan
)

# Canonical error contract + correlation id + Prometheus metrics.
# One shape for every Wildbox service (see open_security_shared.errors).
from open_security_shared.errors import install_error_handlers as _install_error_handlers
from open_security_shared.observability import install_observability as _install_observability

_install_error_handlers(app)
_install_observability(app, service_name="responder", service_version="0.1.6")



# Add Security Headers Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


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

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


@app.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Health check endpoint"""
    try:
        # Test Redis connection
        redis_client = redis.from_url(settings.redis_url)
        redis_connected = True
        try:
            redis_client.ping()
        except Exception:
            redis_connected = False
        
        # Count loaded playbooks
        playbooks_loaded = len(playbook_parser.playbooks)
        
        return HealthCheckResponse(
            status="healthy" if redis_connected else "unhealthy",
            timestamp=datetime.utcnow()
        )
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service health check failed"
        )


@app.get("/v1/playbooks", response_model=PlaybookListResponse)
async def list_playbooks(current_user: GatewayUser = Depends(get_current_user)):
    """List all available playbooks"""
    try:
        playbooks_list = playbook_parser.list_playbooks()
        return PlaybookListResponse(
            playbooks=playbooks_list,
            total=len(playbooks_list)
        )
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to list playbooks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list playbooks"
        )


# #182 policy: executing a playbook is an operational action, member-allowed
# (gated only by gateway auth + per-run team ownership, not by role).
@app.post("/v1/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    request: PlaybookExecutionRequest = PlaybookExecutionRequest(),
    current_user: GatewayUser = Depends(get_current_user)
):
    """
    Execute a playbook.

    Authentication handled by gateway via X-Wildbox-* headers.
    Legacy Bearer token support maintained during migration.
    """
    logger.info(f"🔐 Authenticated request to execute playbook: {playbook_id} (User: {current_user.user_id}, Team: {current_user.team_id})")
    
    try:
        # Validate playbook exists
        try:
            playbook = playbook_parser.get_playbook(playbook_id)
        except KeyError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Playbook '{playbook_id}' not found"
            )
        
        # Start execution. The owning team is recorded inside start_execution,
        # before the actor message is sent, so there is no window in which a run
        # is executing with no owner (WILDBO-DATA-06).
        run_id = start_execution(
            playbook_id,
            request.trigger_data,
            team_id=current_user.team_id,
        )

        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "run_id": run_id,
                "playbook_id": playbook_id,
                "playbook_name": playbook.name,
                "status": "accepted",
                "status_url": f"/v1/runs/{run_id}",
                "message": f"Playbook '{playbook.name}' execution started"
            }
        )
        
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to execute playbook {playbook_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute playbook"
        )


@app.get("/v1/runs/{run_id}", response_model=PlaybookExecutionResult)
async def get_execution_status(run_id: str, current_user: GatewayUser = Depends(get_current_user)):
    """Get execution status and results"""
    try:
        execution_result = workflow_engine.get_execution_state(run_id)

        # Treat "not yours" the same as "not found" so existence isn't leaked
        # across teams.
        if not execution_result or not workflow_engine.is_run_owner(run_id, current_user.team_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution '{run_id}' not found"
            )

        return execution_result
        
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to get execution status for {run_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get execution status"
        )


# #182 policy: configuration mutations require owner/admin. Reloading playbook
# definitions from disk changes service config, so it is gated; operational
# endpoints (execute/cancel a run) stay member-allowed.
@app.post("/v1/playbooks/reload")
async def reload_playbooks(current_user: GatewayUser = Depends(require_role("owner", "admin"))):
    """Reload playbooks from disk"""
    try:
        playbooks = playbook_parser.reload_playbooks()
        return {
            "message": "Playbooks reloaded successfully",
            "total_loaded": len(playbooks),
            "playbooks": list(playbooks.keys())
        }
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to reload playbooks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reload playbooks"
        )


@app.get("/v1/connectors")
async def list_connectors(current_user: GatewayUser = Depends(get_current_user)):
    """List all available connectors and their actions"""
    try:
        connectors = connector_registry.list_connectors()
        return {
            "connectors": connectors,
            "total": len(connectors)
        }
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to list connectors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list connectors"
        )


@app.delete("/v1/runs/{run_id}")
async def cancel_execution(run_id: str, current_user: GatewayUser = Depends(get_current_user)):
    """Cancel a running execution"""
    try:
        # For now, we'll just mark it as cancelled in Redis
        execution_result = workflow_engine.get_execution_state(run_id)

        # "Not yours" -> 404, identical to "not found", to avoid cross-team leak.
        if not execution_result or not workflow_engine.is_run_owner(run_id, current_user.team_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution '{run_id}' not found"
            )
        
        if execution_result.status in ["completed", "failed", "cancelled"]:
            return {
                "message": f"Execution '{run_id}' is already {execution_result.status}",
                "status": execution_result.status
            }
        
        # Mark as cancelled (simplified implementation)
        execution_result.status = "cancelled"
        execution_result.end_time = datetime.utcnow()
        workflow_engine.save_execution_state(run_id, execution_result)
        workflow_engine.add_log(run_id, "Execution cancelled by user request")
        
        return {
            "message": f"Execution '{run_id}' cancelled successfully",
            "status": "cancelled"
        }
        
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to cancel execution {run_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel execution"
        )


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Open Security Responder",
        "version": SERVICE_VERSION,
        "description": "SOAR orchestration microservice",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "playbooks": "/v1/playbooks",
            "execute": "/v1/playbooks/{playbook_id}/execute",
            "status": "/v1/runs/{run_id}",
            "connectors": "/v1/connectors"
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
