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

from fastapi import FastAPI, HTTPException, status, Header, Depends, Path
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import redis
from celery.result import AsyncResult
from kombu.exceptions import OperationalError as KombuOperationalError
from limits.errors import StorageError as RateLimitStorageError
from open_security_shared.errors import error_response as _error_response
from open_security_shared.errors import get_request_id as _get_request_id
from redis.exceptions import RedisError

from .schemas import (
    AnalysisTaskRequest, AnalysisTaskStatus, AnalysisResult,
    HealthResponse, StatsResponse, TaskStatus
)
from .config import settings
from .worker import celery_app, run_threat_enrichment_task
from .auth import get_current_user, GatewayUser
from .rate_limit import limit_analysis, limiter, rate_limited_caller
from .stats import COMPLETED, FAILED, LEGACY_KEYS, read_today
from .tools.langchain_tools import enabled_tools
from .tools.wildbox_client import CallerIdentityUnavailable, require_caller_identity
from open_security_shared.api_docs import api_docs_urls

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Where a client reads a task back: the gateway path, the only one a client
# can reach. The service accepts gateway-authenticated requests only, and the
# gateway publishes /v1/<x> as /api/v1/agents/<x>
# (open-security-gateway/nginx/conf.d/wildbox_gateway.conf). It was the
# service's own /v1/analyze/{id}, which on the gateway is not the task
# (#716).
#
# A constant, as the tools service's TASK_STATUS_PATH and the responder's
# RUN_STATUS_PATH are, and a path without scheme or host: nothing in it
# comes from the request, so no Host or X-Forwarded-* header a client sends
# can change where it points, and a client resolves it against the address
# it called. tests/unit/test_result_url.py keeps it equal to the gateway's
# route.
RESULT_PATH = "/api/v1/agents/analyze/{task_id}"


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

        # The daily counters that were never reset; replaced by one key per
        # UTC date (app/stats.py). Nothing reads these any more.
        redis_client.delete(*LEGACY_KEYS)

        # What the model is given, said once at start: the lookup tools, and
        # the team-data tools AGENT_TEAM_DATA_TOOLS names (none by default).
        # The setting was validated when the settings were built.
        team_data = sorted(settings.team_data_tool_names())
        offered = enabled_tools(team_data)
        logger.info(f"Tools given to the model: {', '.join(t.name for t in offered)}")
        if team_data:
            logger.warning(
                "AGENT_TEAM_DATA_TOOLS gives the model team data: what "
                f"{', '.join(team_data)} return is sent to the model provider"
            )

        # Test Anthropic API key
        if not settings.anthropic_api_key or settings.anthropic_api_key == "your_anthropic_api_key_here":
            logger.warning("Anthropic API key not configured - AI analysis will fail")
        else:
            logger.info("Anthropic API key configured")
        
        # Test Celery connection
        try:
            celery_app.control.inspect().ping()
            logger.info("Celery connection established")
        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Celery connection failed: {e}")
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.warning(f"Unexpected Celery error: {type(e).__name__}: {e}")
        
        logger.info("Open Security Agents started successfully")
        
    except (ImportError, RuntimeError) as e:
        logger.error(f"Failed to start application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Open Security Agents...")


# /docs, /redoc and /openapi.json are served in development only, by the rule
# every service shares. They used to be turned off for the exact value
# "production", so any other environment, "staging" included, published the
# schema (#679).
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# One version, in one place. The FastAPI constructor said 0.1.6 while the root
# endpoint reported 1.0.0, so the two things a caller can ask disagreed
# (WILDBO-API-06).
SERVICE_VERSION = "0.1.6"

# Initialize FastAPI app
app = FastAPI(
    title="Open Security Agents API",
    description="AI-powered threat intelligence enrichment service",
    version=SERVICE_VERSION,
    lifespan=lifespan,
    **api_docs_urls(ENVIRONMENT),
)

# Canonical error contract + correlation id + Prometheus metrics.
# One shape for every Wildbox service (see open_security_shared.errors).
from open_security_shared.errors import install_error_handlers as _install_error_handlers
from open_security_shared.observability import install_observability as _install_observability

_install_error_handlers(app)
_install_observability(app, service_name="agents", service_version="0.1.6")


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(RateLimitStorageError)
async def _rate_limit_storage_unavailable(request: Request, exc: RateLimitStorageError):
    """The limiter could not count the request: refuse it, with a 503.

    The counters are in Redis (app/rate_limit.py). A submission that cannot
    be counted is not accepted uncounted, and it is not a server fault to
    report as 500: the caller can retry.
    """
    logger.error(f"Rate limit storage unavailable: {exc}")
    return _error_response(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "Rate limiting temporarily unavailable",
        request_id=_get_request_id(request),
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
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",")
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
    
    # Check Anthropic
    if settings.anthropic_api_key and settings.anthropic_api_key != "your_anthropic_api_key_here":
        services["anthropic"] = "configured"
    else:
        services["anthropic"] = "not_configured"
    
    overall_status = "healthy" if all(s in ["healthy", "configured"] for s in services.values()) else "unhealthy"
    
    return HealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        version=SERVICE_VERSION,
        services=services
    )


@app.get("/stats", response_model=StatsResponse)
async def get_stats(user: GatewayUser = Depends(get_current_user)):
    """Get service statistics. Requires authentication."""
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
        
        # total_analyses counts since the Redis data was last cleared. The
        # two daily counters are those of the current UTC date (app/stats.py);
        # they were single keys that nothing reset.
        total_analyses = redis_client.get("stats:total_analyses") or 0
        completed_today = read_today(redis_client, COMPLETED)
        failed_today = read_today(redis_client, FAILED)

        return StatsResponse(
            total_analyses=int(total_analyses),
            pending_tasks=pending_count,
            running_tasks=running_count,
            completed_today=int(completed_today),
            failed_today=int(failed_today),
            average_duration=None,  # Could be calculated from historical data
            uptime_seconds=uptime
        )
        
    except (KombuOperationalError, RedisError, ConnectionError, TimeoutError) as e:
        # See the note on the analyze endpoint: the library exceptions do not
        # subclass the builtins (WILDBO-ERR-03).
        logger.error(f"Database connection error in stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database temporarily unavailable"
        )
    except ValueError as e:
        logger.error(f"Invalid data in stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Data integrity error"
        )


@app.post("/v1/analyze", response_model=AnalysisTaskStatus, status_code=status.HTTP_202_ACCEPTED)
@limit_analysis
async def analyze_ioc(
    # slowapi finds the request by the parameter's name: it must be `request`
    # and a starlette Request. It was the body model, under that name, so the
    # limiter raised on every call and the endpoint answered 500 (#582).
    request: Request,
    analysis: AnalysisTaskRequest,
    # Authenticates the caller and hands the verified identity to the
    # limiter, which keys the limit by user, not by peer address (#651).
    user: GatewayUser = Depends(rate_limited_caller)
):
    """
    Submit an IOC for AI-powered threat analysis.

    Authentication via gateway (X-Wildbox-* headers) or legacy Bearer token.

    This endpoint accepts an IOC and starts an asynchronous analysis task.
    The analysis is performed by an AI agent that uses various security tools
    to investigate the IOC and generate a comprehensive threat intelligence report.
    """
    logger.info(f"[AUTH] Authenticated user {user.user_id} (team: {user.team_id}) analyzing IOC type: {analysis.ioc.type}")

    # The worker refuses a task whose caller is missing or incomplete (#594);
    # refuse it here as well, before any state is written or work enqueued.
    try:
        caller = require_caller_identity(
            {
                "user_id": user.user_id,
                "team_id": user.team_id,
                "role": getattr(user, "role", "member"),
            }
        )
    except CallerIdentityUnavailable as e:
        logger.warning(f"[AUTH] Refusing analysis: {e}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A user and team identity is required to run an analysis",
        )

    try:
        # Generate unique task ID
        task_id = str(uuid.uuid4())
        
        # Create task metadata
        task_metadata = {
            "task_id": task_id,
            "ioc": analysis.ioc.dict(),
            "priority": analysis.priority,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": TaskStatus.PENDING
        }
        
        # Write ALL of the task's Redis state before the work is dispatched, in
        # one pipeline.
        #
        # This used to be: enqueue, then three separate unguarded setex/incr
        # calls. A Redis failure after the enqueue left the analysis running on
        # the worker while the caller got a 500 and believed nothing had
        # started -- and because task:{id}:celery_id was never written, the
        # result was unreachable forever (WILDBO-ERR-04). The owner record in
        # particular must exist before anything can read the task.
        pipe = redis_client.pipeline()
        pipe.setex(
            f"task:{task_id}:metadata",
            settings.task_result_expires,
            json.dumps(task_metadata),
        )
        pipe.setex(
            f"task:{task_id}:user_id",
            owner_record_ttl(),
            str(user.user_id),
        )
        pipe.incr("stats:total_analyses")
        pipe.execute()

        # Submit Celery task, forwarding the caller's gateway identity so tool
        # calls run with the user's real team scope, not the legacy key (#175).
        try:
            celery_task = run_threat_enrichment_task.delay(
                task_id=task_id,
                ioc=analysis.ioc.dict(),
                caller=caller,
            )
        except Exception:
            # Nothing was enqueued: remove the state we just wrote so a failed
            # submission leaves no half-created task behind.
            redis_client.delete(
                f"task:{task_id}:metadata",
                f"task:{task_id}:user_id",
            )
            raise

        # The celery id is the last thing written: if this fails the task is
        # already running, so revoke it rather than orphaning it.
        #
        # The owner record is rewritten in the same transaction, so its
        # expiry is measured from the same instant as the celery id's and
        # it outlives the celery id by OWNER_RECORD_GRACE_SECONDS. Written
        # separately, the celery id expired after the owner record, and in
        # that window the task was addressable with no owner (#650).
        try:
            pipe = redis_client.pipeline()
            pipe.setex(
                f"task:{task_id}:celery_id",
                settings.task_result_expires,
                celery_task.id,
            )
            pipe.setex(
                f"task:{task_id}:user_id",
                owner_record_ttl(),
                str(user.user_id),
            )
            pipe.execute()
        except Exception:
            logger.error(
                f"Could not record celery id for task {task_id}; revoking the "
                "enqueued task so it does not run unreachable"
            )
            try:
                celery_task.revoke(terminate=False)
            except Exception:
                logger.error(f"Revoke of task {task_id} also failed", exc_info=True)
            redis_client.delete(
                f"task:{task_id}:metadata",
                f"task:{task_id}:user_id",
            )
            raise

        return AnalysisTaskStatus(
            task_id=task_id,
            status=TaskStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            result_url=RESULT_PATH.format(task_id=task_id)
        )
        
    except (KombuOperationalError, RedisError, ConnectionError, TimeoutError) as e:
        # kombu.exceptions.OperationalError (broker down) and
        # redis.exceptions.ConnectionError (Redis down) are plain Exception
        # subclasses -- redis's shadows the builtin name but does not inherit
        # from it -- so this branch could never fire during the exact incident it
        # was written for, and the caller got a bare 500 (WILDBO-ERR-03).
        logger.error(f"Task queue connection error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Task queue temporarily unavailable"
        )
    except ValueError as e:
        logger.error(f"Invalid task data: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid analysis request"
        )


# The owner record outlives everything that can address the task. It is
# written with the task's other keys and rewritten together with the celery
# id, always with this much more time to live than either (#650).
OWNER_RECORD_GRACE_SECONDS = 300


def owner_record_ttl() -> int:
    """Seconds the task:{id}:user_id record lives."""
    return settings.task_result_expires + OWNER_RECORD_GRACE_SECONDS


def _task_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Task not found",
    )


def _authorize_task(task_id: str, user: GatewayUser) -> bytes:
    """Return the task's celery id if ``user`` owns the task; 404 otherwise.

    Every handler that reads or acts on a task goes through here, so the
    ownership rule is written once. It fails closed:

    - no celery id: the task does not exist (or has expired);
    - no owner record: the task cannot be attributed to anyone. This is an
      inconsistency, not an anonymous task, so nobody may use it. DELETE
      used to read ``if task_owner and ...`` and let any caller revoke
      such a task (#650); GET had the same defect (WILDBO-ERR-05);
    - another user's task: answered exactly like a task that does not
      exist, so the answer does not confirm that a task id is live.
    """
    celery_task_id = redis_client.get(f"task:{task_id}:celery_id")
    if not celery_task_id:
        raise _task_not_found()

    task_owner = redis_client.get(f"task:{task_id}:user_id")
    if not task_owner:
        logger.error(f"Task {task_id} has no owner record; refusing access")
        raise _task_not_found()

    if task_owner.decode() != str(user.user_id):
        logger.warning(
            f"User {user.user_id} asked for task {task_id}, which belongs to "
            "another user; answering 404"
        )
        raise _task_not_found()

    return celery_task_id


@app.get("/v1/analyze/{task_id}")
async def get_analysis_result(
    task_id: str = Path(..., regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    user: GatewayUser = Depends(get_current_user)
):
    """
    Get the status and results of an analysis task. Requires authentication.
    """
    try:
        celery_task_id = _authorize_task(task_id, user)

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
        
        # If task failed, return generic error (details are in server logs)
        error_message = None
        if celery_task.state == "FAILURE":
            error_message = "Analysis failed. Please retry or contact support."
        
        # Return status information
        return AnalysisTaskStatus(
            task_id=task_id,
            status=status_value,
            created_at=datetime.fromisoformat(task_metadata["created_at"]),
            started_at=datetime.now(timezone.utc) if status_value == TaskStatus.RUNNING else None,
            completed_at=datetime.now(timezone.utc) if status_value in [TaskStatus.COMPLETED, TaskStatus.FAILED] else None,
            progress=celery_task.info.get("progress") if isinstance(celery_task.info, dict) else None,
            error=error_message,
            result_url=RESULT_PATH.format(task_id=task_id)
        )
        
    except HTTPException:
        raise
    except (KombuOperationalError, RedisError, ValueError, KeyError, TypeError,
            ConnectionError, TimeoutError) as e:
        logger.error(f"Error getting analysis result for task {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve analysis result"
        )


@app.delete("/v1/analyze/{task_id}")
async def cancel_analysis(
    task_id: str = Path(..., regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    user: GatewayUser = Depends(get_current_user)
):
    """Cancel a pending or running analysis task. Requires authentication."""
    try:
        # Ownership is established before anything is revoked.
        celery_task_id = _authorize_task(task_id, user)

        # Revoke the Celery task
        celery_app.control.revoke(celery_task_id.decode(), terminate=True)
        
        logger.info(f"Cancelled analysis task {task_id}")
        
        return {"message": "Task cancelled successfully"}
        
    except HTTPException:
        raise
    except (KombuOperationalError, RedisError, ConnectionError, TimeoutError) as e:
        logger.error(f"Task queue connection error cancelling {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Task queue temporarily unavailable"
        )
    except KeyError as e:
        logger.error(f"Invalid task data for {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found or invalid"
        )


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Open Security Agents",
        "description": "AI-powered threat intelligence enrichment service",
        "version": SERVICE_VERSION,
        "documentation": "/docs",
        "health": "/health",
        "stats": "/stats"
    }
