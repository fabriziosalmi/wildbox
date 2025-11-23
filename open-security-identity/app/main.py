"""
FastAPI application for Open Security Identity service.
"""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .config import settings
from .database import get_db
from .api_v1.endpoints import users, api_keys, billing, analytics, user_api_keys
from .internal import router as internal_router
from .webhooks import router as webhooks_router

# Import fastapi-users components
from .user_manager import auth_backend, fastapi_users
from .schemas import UserRead, UserCreate, UserUpdate

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Identity, authentication, authorization, and billing service for Wildbox Security Suite",
    docs_url="/docs",
    redoc_url="/redoc",
)

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
    tags=["users"]
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
    tags=["admin"]
)

app.include_router(
    api_keys.router,
    prefix=f"{settings.api_v1_prefix}/teams",
    tags=["api-keys"]
)

# User-friendly API keys endpoints (without team_id in path)
app.include_router(
    user_api_keys.router,
    prefix=settings.api_v1_prefix,
    tags=["user-api-keys"]
)

app.include_router(
    billing.router,
    prefix=f"{settings.api_v1_prefix}/billing",
    tags=["billing"]
)

app.include_router(
    analytics.router,
    prefix=f"{settings.api_v1_prefix}/analytics",
    tags=["analytics"]
)

app.include_router(
    internal_router,
    prefix=settings.internal_api_prefix,
    tags=["internal"]
)

app.include_router(
    webhooks_router,
    prefix="/webhooks",
    tags=["webhooks"]
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
        "version": settings.app_version,
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
    except OperationalError as e:
        health_status["status"] = "unhealthy"
        health_status["checks"]["database"] = {
            "status": "unhealthy", 
            "error": "Database connection failed",
            "details": str(e)
        }
    except SQLAlchemyError as e:
        health_status["status"] = "degraded"
        health_status["checks"]["database"] = {
            "status": "degraded",
            "error": "Database query error",
            "details": str(e)
        }
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        health_status["status"] = "unhealthy"
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "error": "Unexpected database error",
            "details": str(type(e).__name__)
        }
    
    return health_status


@app.get("/metrics")
async def get_metrics():
    """Metrics endpoint for Prometheus/monitoring."""
    from .database import get_db
    from sqlalchemy import text, select, func
    from .models import User, Team, APIKey
    import time
    
    metrics = {
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": time.time(),
        "uptime_seconds": int(time.time() - app.state.start_time) if hasattr(app.state, 'start_time') else 0,
        "metrics": {}
    }
    
    try:
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
            select(func.count()).select_from(APIKey).where(APIKey.is_active == True)
        )
        metrics["metrics"]["api_keys_active"] = api_key_count.scalar()
        
        await db.close()
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        metrics["metrics"]["error"] = str(type(e).__name__)
    
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
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.port,
        reload=settings.debug
    )
