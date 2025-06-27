"""
FastAPI application for Open Security Identity service.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from .config import settings
from .api_v1.endpoints import auth, users, api_keys, billing, analytics
from .internal import router as internal_router
from .webhooks import router as webhooks_router

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

# Include routers
app.include_router(
    auth.router,
    prefix=f"{settings.api_v1_prefix}/auth",
    tags=["authentication"]
)

app.include_router(
    users.router,
    prefix=f"{settings.api_v1_prefix}/users",
    tags=["users"]
)

app.include_router(
    api_keys.router,
    prefix=f"{settings.api_v1_prefix}/teams",
    tags=["api-keys"]
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
    import asyncio
    
    health_status = {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "checks": {}
    }
    
    # Database health check
    try:
        # Get database session and test connection
        db_gen = get_db()
        db: AsyncSession = await db_gen.__anext__()
        result = await db.execute(text("SELECT 1"))
        await db.close()
        health_status["checks"]["database"] = {"status": "healthy", "response_time_ms": 0}
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["checks"]["database"] = {"status": "unhealthy", "error": str(e)}
    
    return health_status


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
