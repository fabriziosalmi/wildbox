"""
FastAPI application for Open Security Identity service.
"""

import os

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .config import settings
from .database import get_db
from .api_v1.endpoints import users, api_keys, analytics, user_api_keys
from .internal import router as internal_router
from . import logout

# Import fastapi-users components
from .user_manager import (
    auth_backend,
    current_superuser,
    fastapi_users,
    require_password_changed,
)
from .schemas import UserRead, UserCreate, UserUpdate

# Interactive API documentation and the OpenAPI schema are served in
# development only, as agents, responder and cspm already do. identity served
# /docs and /redoc unconditionally, publishing its full route map, including
# admin and internal endpoints, in production (#496).
DISABLE_DOCS = os.getenv("ENVIRONMENT", "development") == "production"

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Identity, authentication, and authorization service for Wildbox Security Suite",
    docs_url=None if DISABLE_DOCS else "/docs",
    redoc_url=None if DISABLE_DOCS else "/redoc",
    openapi_url=None if DISABLE_DOCS else "/openapi.json",
)

# Canonical error contract + correlation id + Prometheus metrics.
# One shape for every Wildbox service (see open_security_shared.errors).
from open_security_shared.errors import install_error_handlers as _install_error_handlers
from open_security_shared.observability import install_observability as _install_observability

_install_error_handlers(app)
_install_observability(app, service_name="identity", service_version=settings.app_version)


# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

# Middleware per aggiungere la sessione DB alla request (NECESSARIO per on_after_register)
@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    """Database session middleware with proper error handling."""
    from sqlalchemy.exc import SQLAlchemyError, OperationalError
    import logging
    
    logger = logging.getLogger(__name__)
    response = Response("Internal server error", status_code=500)
    
    try:
        db_gen = get_db()
        request.state.db = await db_gen.__anext__()
        response = await call_next(request)
    except OperationalError as e:
        logger.error(f"Database connection error: {e}")
        request.state.db = None
        return JSONResponse(
            status_code=503,
            content={"detail": "Database temporarily unavailable"}
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error in middleware: {e}")
        request.state.db = None
        response = await call_next(request)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Unexpected middleware error: {type(e).__name__}: {e}")
        request.state.db = None
        response = await call_next(request)
    finally:
        if hasattr(request.state, 'db') and request.state.db:
            try:
                await request.state.db.close()
            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                logger.warning(f"Error closing database session: {e}")
    
    return response

# An account a team admin created must change its initial password before
# anything else (#573). Every router of authenticated routes carries this
# gate; the auth routers (login, logout, register, password reset, verify)
# and /internal do not, so a flagged account can still log in and out.
PASSWORD_CHANGED = [Depends(require_password_changed)]

# FastAPI Users routers (sostituiscono auth.router)
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix=f"{settings.api_v1_prefix}/auth/jwt",
    tags=["authentication"]
)

app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix=f"{settings.api_v1_prefix}/auth",
    tags=["authentication"]
)

app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix=f"{settings.api_v1_prefix}/users",
    tags=["users"],
    dependencies=PASSWORD_CHANGED,
)

# Logout / token revocation (WILDBO-AUTH-01). fastapi-users' JWT strategy has no
# server-side logout, so this supplies the write side of the blacklist that
# /internal/authorize now consults.
app.include_router(
    logout.router,
    prefix=f"{settings.api_v1_prefix}/auth",
    tags=["authentication"]
)

# Router per reset password e verifica email (opzionali ma raccomandati)
app.include_router(
    fastapi_users.get_reset_password_router(),
    prefix=f"{settings.api_v1_prefix}/auth",
    tags=["authentication"]
)

app.include_router(
    fastapi_users.get_verify_router(UserRead),
    prefix=f"{settings.api_v1_prefix}/auth",
    tags=["authentication"]
)

# Include routers custom esistenti (users.router ora contiene solo endpoint admin custom)
app.include_router(
    users.router,
    prefix=f"{settings.api_v1_prefix}/admin",
    tags=["admin"],
    dependencies=PASSWORD_CHANGED,
)

app.include_router(
    api_keys.router,
    prefix=f"{settings.api_v1_prefix}/teams",
    tags=["api-keys"],
    dependencies=PASSWORD_CHANGED,
)

# User-friendly API keys endpoints (without team_id in path)
app.include_router(
    user_api_keys.router,
    prefix=settings.api_v1_prefix,
    tags=["user-api-keys"],
    dependencies=PASSWORD_CHANGED,
)

app.include_router(
    analytics.router,
    prefix=f"{settings.api_v1_prefix}/analytics",
    tags=["analytics"],
    dependencies=PASSWORD_CHANGED,
)

app.include_router(
    internal_router,
    prefix=settings.internal_api_prefix,
    tags=["internal"]
)


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "healthy",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    from .database import get_db
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError, OperationalError
    import time
    
    health_status = {
        "status": "healthy",
        "service": settings.app_name,
        "timestamp": time.time(),
        "checks": {}
    }
    
    # Database health check with specific error handling
    db_start = time.time()
    try:
        db_gen = get_db()
        db: AsyncSession = await db_gen.__anext__()
        result = await db.execute(text("SELECT 1"))
        await db.close()
        db_time = (time.time() - db_start) * 1000
        health_status["checks"]["database"] = {
            "status": "healthy", 
            "response_time_ms": round(db_time, 2)
        }
    except OperationalError:
        health_status["status"] = "unhealthy"
        health_status["checks"]["database"] = {"status": "unhealthy"}
    except SQLAlchemyError:
        health_status["status"] = "degraded"
        health_status["checks"]["database"] = {"status": "degraded"}
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError):
        health_status["status"] = "unhealthy"
        health_status["checks"]["database"] = {"status": "unhealthy"}

    # Redis holds the token blacklist and the login-lockout counters. Both fail
    # open when Redis is down -- logins keep working, but a revoked token is
    # accepted again and lockout stops counting -- so its loss degrades the
    # service rather than taking it down. Reported so the admin page's Redis
    # status comes from a real check, not from "identity answered" (#559).
    health_status["checks"]["redis"] = await _redis_check()
    if (
        health_status["checks"]["redis"]["status"] != "healthy"
        and health_status["status"] == "healthy"
    ):
        health_status["status"] = "degraded"

    return health_status


async def _redis_check() -> dict:
    """PING identity's Redis, bounded so a hung connection cannot stall /health."""
    import asyncio
    import time

    from redis.exceptions import RedisError

    from .token_blacklist import get_redis

    start = time.time()
    try:
        redis = await get_redis()
        await asyncio.wait_for(redis.ping(), timeout=2)
    except (RedisError, OSError, asyncio.TimeoutError):
        return {"status": "unhealthy"}
    return {
        "status": "healthy",
        "response_time_ms": round((time.time() - start) * 1000, 2),
    }


@app.get(
    "/api/v1/admin/metrics",
    dependencies=[Depends(current_superuser), *PASSWORD_CHANGED],
)
async def get_metrics():
    """Business counts (users, teams, active API keys), for platform superusers.

    Not /metrics: install_observability() registers the Prometheus text
    exposition there, and it registers first, so this handler was shadowed and
    the endpoint returned an exposition where callers expected JSON. Both are
    wanted -- Prometheus scrapes /metrics (monitoring/prometheus.yml), and these
    counts are a privileged view for operators -- so they live at separate
    paths rather than one silently replacing the other.

    Identity authenticates the caller itself, from the bearer token, and
    requires is_superuser (#664). This used to accept the X-Gateway-Secret
    header alone, and the gateway stamped that header on every request it
    passed through to identity, authenticated or not, so anyone could read
    these counts at /api/v1/identity/admin/metrics. The gateway secret proves
    that a request comes from the gateway, not who is making it: only the
    routes the gateway calls on its own behalf (/internal) may rely on it.
    """
    import time

    from sqlalchemy import func, select
    from sqlalchemy.exc import SQLAlchemyError

    from .database import get_db
    from .models import ApiKey, Team, User

    # The imports are outside the try: this one used to import APIKey, a
    # name the models never had, and the handler below turned the ImportError
    # into "unavailable" with every count at zero, on every call.
    try:
        metrics = {
            "service": settings.app_name,
            "version": settings.app_version,
            "timestamp": time.time(),
            "uptime_seconds": int(time.time() - app.state.start_time) if hasattr(app.state, 'start_time') else 0,
            "metrics": {}
        }
        
        db_gen = get_db()
        db = await db_gen.__anext__()
        
        # Get user count
        user_count = await db.execute(select(func.count()).select_from(User))
        metrics["metrics"]["users_total"] = user_count.scalar()
        
        # Get team count
        team_count = await db.execute(select(func.count()).select_from(Team))
        metrics["metrics"]["teams_total"] = team_count.scalar()
        
        # Get active API keys
        api_key_count = await db.execute(
            select(func.count()).select_from(ApiKey).where(ApiKey.is_active == True)
        )
        metrics["metrics"]["api_keys_active"] = api_key_count.scalar()

        await db.close()

    except (SQLAlchemyError, OSError):
        # The database is unavailable: report it, with zero counts.
        metrics = {
            "service": "identity",
            "timestamp": time.time(),
            "metrics": {
                "error": "unavailable",
                "users_total": 0,
                "teams_total": 0,
                "api_keys_active": 0
            }
        }
    
    return metrics


@app.on_event("startup")
async def startup_event():
    """Initialize application state on startup."""
    import time
    app.state.start_time = time.time()



@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Custom 404 handler."""
    return JSONResponse(
        status_code=404,
        content={"detail": "Endpoint not found"}
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """Custom 500 handler."""
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    # Binding all interfaces is intended: this entry point runs the service
    # inside its container, where it is reached through the container network.
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",  # nosec B104
        port=settings.port,
        reload=settings.debug
    )
