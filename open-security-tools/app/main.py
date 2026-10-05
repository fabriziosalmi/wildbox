"""Main FastAPI application with dynamic tool discovery."""

import os
import sys
import time
import importlib.util
from typing import Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import ValidationError

from app.config import settings
from app.logging_config import configure_logging, get_logger
from app.middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware, CacheControlMiddleware
from open_security_shared.errors import install_error_handlers
from open_security_shared.observability import install_observability
from app.api.router import router as api_router, DISCOVERED_TOOLS, register_tool_endpoint
from app.api.async_router import router as async_router
from app.execution_manager import execution_manager
from app.tool_loader import discover_tools as _discover_tools

# Configure logging first
configure_logging()
logger = get_logger(__name__)

def discover_tools() -> Dict[str, Any]:
    """
    Discover the security tools available to this process.

    Delegates to app.tool_loader, the single implementation of the plugin
    contract shared with the Celery worker (WILDBO-ARCH-06). Tools are imported
    as real packages, so relative imports inside a tool work and each tool is
    executed once per process rather than re-imported per task.
    """
    return _discover_tools()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Wildbox Security API starting up...")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Max concurrent tools: {settings.max_concurrent_tools}")
    logger.info(f"Default tool timeout: {settings.tool_timeout}s")
    
    # Initialize security integration
    try:
        from app.security_integration import security_integration
        if security_integration.security_enabled:
            logger.info("🔐 Security controls are ENABLED")
            if security_integration.strict_mode:
                logger.info("🔒 Security strict mode is ACTIVE")
            else:
                logger.info("🔓 Security graceful mode is ACTIVE")
        else:
            logger.info("⚠️  Security controls are DISABLED")
    except ImportError:
        logger.info("Security integration not available")
    
    # Validate API key is set and secure
    try:
        api_key = settings.get_api_key()
        if not api_key:
            logger.error("CRITICAL: No API key configured! Set API_KEY in .env file.")
            raise ValueError("API key is required")
        
        # Warn about potentially weak keys
        if len(api_key) < 32:
            logger.warning("API key is shorter than recommended 32 characters")
        
        if settings.is_production() and any(pattern in api_key.lower() for pattern in ['test', 'demo', 'default']):
            logger.error("CRITICAL: Weak API key detected in production environment!")
            raise ValueError("Insecure API key in production")
            
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"API key validation failed: {e}")
        if settings.is_production():
            raise e
    
    yield
    
    # Shutdown
    logger.info("Wildbox Security API shutting down...")
    cancelled_count = await execution_manager.cancel_all_executions()
    if cancelled_count > 0:
        logger.info(f"Cancelled {cancelled_count} active tool executions")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title="Wildbox Security Tools",
        description="A modular security tools platform with dynamic tool discovery",
        version="0.1.6",
        # No Swagger UI or ReDoc pages: the standalone web UI that served
        # them is gone (#581). The schema stays at /openapi.json.
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
        lifespan=lifespan
    )
    
    # Add middleware (order matters!)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CacheControlMiddleware)
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add exception handlers. The canonical shape lives in the shared package so
    # every Wildbox service answers with the same body (see WILDBO-API-02); the
    # local app.exceptions module now delegates to it.
    install_error_handlers(app)

    # Correlation id (X-Request-ID, propagated from the gateway) and the
    # Prometheus endpoint: GET /metrics, registered by the shared package as
    # in every other service and scraped by monitoring/prometheus.yml. It is
    # the service's only metrics endpoint (#646).
    install_observability(app, service_name="tools", service_version="0.1.6")
    
    # Discover and register tools
    discovered_tools = discover_tools()
    
    # Update the global DISCOVERED_TOOLS dictionary
    DISCOVERED_TOOLS.clear()
    DISCOVERED_TOOLS.update(discovered_tools)
    
    # Register dynamic endpoints for each tool
    for tool_name, tool_module in discovered_tools.items():
        register_tool_endpoint(app, tool_name, tool_module)
    
    # Include routers
    app.include_router(api_router)
    app.include_router(async_router)  # Async execution endpoints
    
    # The service's one health route: the image's HEALTHCHECK and the compose
    # healthcheck probe it (curl -f http://localhost:8000/health), and so do
    # the integration tests, directly on the service port. A second handler
    # for the same path used to be registered further down; FastAPI serves
    # the first one registered, so that one never ran (#646).
    @app.get("/health", tags=["System"])
    async def health_check():
        """Health of this service: status, loaded tools, active executions."""
        start_time = time.time()
        try:
            active_executions = execution_manager.get_active_executions()
            response_time_ms = (time.time() - start_time) * 1000
            
            return {
                "status": "healthy",
                "service": "tools",
                "version": "1.0.0",
                "timestamp": time.time(),
                "response_time_ms": round(response_time_ms, 2),
                "environment": settings.environment,
                "tools_count": len(discovered_tools),
                "available_tools": list(discovered_tools.keys()),
                "active_executions": len(active_executions),
                "max_concurrent_tools": settings.max_concurrent_tools,
                "default_timeout": settings.tool_timeout
            }
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Health check error: {e}")
            response_time_ms = (time.time() - start_time) * 1000
            return {
                "status": "degraded",
                "service": "tools",
                "version": "1.0.0",
                "timestamp": time.time(),
                "response_time_ms": round(response_time_ms, 2),
                "error": "An internal error occurred"
            }

    # There is deliberately no /api/system/* route. Four used to be registered
    # here without authentication: info, metrics, operational-metrics and
    # health-aggregate. They reported on the whole platform (environment and
    # debug flag, execution counters, the health body of every other
    # service), which only a platform operator should read, and this
    # service cannot tell one from a tenant: the gateway forwards a team
    # role, and anyone who registers owns a team of their own. Nothing
    # called them either, and what they said was not true: the counters
    # stayed at zero, and a healthy stack was reported as degraded.
    # Operators have GET /metrics (Prometheus) for the counters and each
    # service's own health check (#646). Do not add a route here without a
    # dependency on app.auth.get_current_user.

    # Root redirect
    @app.get("/api")
    async def api_root():
        """API root endpoint with basic information."""
        return {
            "message": "Wildbox Security Tools",
            "version": "1.0.0",
            "tools": f"/api/tools",
            "available_tools": list(discovered_tools.keys())
        }
    
    return app


# Create the application instance
app = create_app()

if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting Wildbox Security API server...")
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
