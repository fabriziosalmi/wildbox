"""
FastAPI application for Open Security Identity service.
"""

import logging

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import OperationalError, SQLAlchemyError
import uvicorn

from .config import settings
from .database import get_db
from .db_errors import code_path, describe_database_error
from .api_v1.endpoints import users, api_keys, analytics, user_api_keys
from .internal import router as internal_router
from .team_contacts import router as team_contacts_router
from . import logout

# Import fastapi-users components
from .user_manager import (
    auth_backend,
    current_superuser,
    fastapi_users,
    require_password_changed,
)
from .schemas import UserRead, UserCreate, UserUpdate
from open_security_shared.api_docs import api_docs_urls

# Create FastAPI application
#
# Interactive API documentation and the OpenAPI schema are served in
# development only, by the rule every service shares. identity served /docs
# and /redoc unconditionally, publishing its full route map, including admin
# and internal endpoints, in production (#496); then it turned them off for
# the exact value "production" only, so "staging" still published them
# (#679). settings.environment is the value the production checks in
# app/config.py read.
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Identity, authentication, and authorization service for Wildbox Security Suite",
    **api_docs_urls(settings.environment),
)

# Canonical error contract + correlation id + Prometheus metrics.
# One shape for every Wildbox service (see open_security_shared.errors).
from open_security_shared.errors import (
    error_response as _error_response,
    get_request_id as _get_request_id,
    install_error_handlers as _install_error_handlers,
)
from open_security_shared.observability import install_observability as _install_observability

# These are the only error handlers of the service. Two more used to be
# registered at the end of this module, by status code: one answered
# {"detail": "Endpoint not found"} to every 404, including the ones a route
# raised with its own message ("User not found"), and one replaced the
# catch-all with {"detail": "Internal server error"}, which has no request id
# (#722). A handler registered for a status code runs before the handlers
# registered for an exception class, so do not add one.
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

# The service adds no middleware of its own, on purpose.
#
# There was one, db_session_middleware. It made a session for
# request.state.db, which nothing has read since the registration hook moved
# to fastapi-users' own session, and it wrapped call_next in the same try as
# that. Its except clauses were written for the session ("fail gracefully":
# go on without one) and so answered an error a *route* raised (ValueError,
# KeyError, TypeError, ConnectionError, TimeoutError, any SQLAlchemyError) by
# calling call_next a second time: a failed request was dispatched again.
# On the Starlette this service pins the second run was torn down at its
# first suspension, which here comes before any handler, so nothing was done
# twice; in an application where nothing suspends before the handler, the
# handler's body ran twice. That is not this service's to rely on (#735).
#
# What it was for is now where it belongs. A connection the pool hands out
# stale is the pool's to replace (pool_pre_ping and pool_recycle, in
# app/database.py). A database that cannot be reached is a 503, answered by
# the exception handler below, once, for the error the route raised, in the
# canonical body like every other error of the service (#722). Every other
# error goes to the shared handlers.
@app.exception_handler(OperationalError)
async def database_unavailable_handler(request: Request, exc: OperationalError):
    """503 for a database that cannot be reached; the cause stays in the log."""
    request_id = _get_request_id(request)
    logging.getLogger(__name__).error(
        "Database connection error: %s", exc, extra={"request_id": request_id}
    )
    return _error_response(
        code=503,
        message="Database temporarily unavailable",
        request_id=request_id,
    )


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(request: Request, exc: SQLAlchemyError):
    """500 for any other database error, logged without the database's words.

    The answer is the one the shared handler gives an unhandled error, which
    is where these went. Its log line is the exception's text and traceback,
    and PostgreSQL writes values in its messages: ``DETAIL: Key
    (email)=(alice@example.com) already exists`` for a unique violation,
    the value itself for one a column's type refuses. ``hide_parameters``
    removes the bound parameters from the text, not those (#778). The log
    says the class, the SQLSTATE and the constraint, and where in the code.

    OperationalError keeps the handler above: what it says is about the
    connection, which the operator needs and no caller wrote.
    """
    request_id = _get_request_id(request)
    logging.getLogger(__name__).error(
        "Database error: %s\n%s",
        describe_database_error(exc),
        code_path(exc),
        extra={"request_id": request_id, "path": str(request.url.path)},
    )
    return _error_response(
        code=500,
        message="An internal error occurred",
        error_type="InternalServerError",
        request_id=request_id,
    )


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

# Who guardian may e-mail about a team (#705): for guardian's worker, with
# a secret of its own. See app/team_contacts.py.
app.include_router(
    team_contacts_router,
    prefix=settings.internal_api_prefix,
    tags=["internal"],
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

    import logging

    from .auth import api_key_hash_secret_is_fallback

    if api_key_hash_secret_is_fallback():
        # Names the variables, never their values. Only a development
        # environment gets here: every other one refuses to start in this
        # state (Settings).
        logging.getLogger(__name__).warning(
            "API_KEY_HASH_SECRET is not set: API-key digests are keyed by "
            "JWT_SECRET_KEY, so rotating JWT_SECRET_KEY invalidates every API "
            "key. Set API_KEY_HASH_SECRET (required unless ENVIRONMENT=development)."
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
