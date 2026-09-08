"""Main FastAPI application with dynamic tool discovery."""

import os
import sys
import time
import importlib.util
from pathlib import Path
from typing import Dict, Any, List
from contextlib import asynccontextmanager
import time
from datetime import datetime

from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import ValidationError

from app.config import settings
from app.logging_config import configure_logging, get_logger
from app.middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware, CacheControlMiddleware
from open_security_shared.errors import install_error_handlers
from open_security_shared.observability import install_observability, metrics_response
from app.api.router import router as api_router, DISCOVERED_TOOLS, register_tool_endpoint
from app.api.async_router import router as async_router
from app.web.router import router as web_router
from app.web.router import DISCOVERED_TOOLS as web_discovered_tools
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
    app.state.start_time = time.time()
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
        docs_url=None,  # Disable default docs, using custom ones
        redoc_url=None,  # Disable default redoc, using custom ones
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

    # Correlation id (X-Request-ID, propagated from the gateway) + Prometheus
    # metrics at /metrics in exposition format.
    install_observability(app, service_name="tools", service_version="0.1.6", metrics_path=None)
    
    # Discover and register tools
    discovered_tools = discover_tools()
    
    # Update the global DISCOVERED_TOOLS dictionary
    DISCOVERED_TOOLS.clear()
    DISCOVERED_TOOLS.update(discovered_tools)
    
    # Update web router's tools dictionary
    web_discovered_tools.clear()
    web_discovered_tools.update(discovered_tools)
    
    # Register dynamic endpoints for each tool
    for tool_name, tool_module in discovered_tools.items():
        register_tool_endpoint(app, tool_name, tool_module)
    
    # Include routers
    app.include_router(api_router)
    app.include_router(async_router)  # Async execution endpoints
    app.include_router(web_router)
    
    # Mount static files
    static_path = Path(__file__).parent / "web" / "static"
    if static_path.exists():
        app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
    else:
        logger.warning("Static files directory not found")
    
    # Health check endpoint with more details
    @app.get("/health", tags=["System"])
    async def health_check():
        """Enhanced health check endpoint."""
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
    
    # Metrics endpoint for observability
    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics():
        """
        Prometheus exposition format.

        This endpoint used to return hand-built JSON that no scraper could parse
        (WILDBO-OBS-03). The JSON view an operator or the dashboard may still
        want is unchanged and lives at /api/system/metrics.
        """
        return metrics_response()

    @app.get("/api/system/operational-metrics", tags=["System"])
    async def get_metrics():
        """
        Get operational metrics for the tools service as JSON.
        Returns tool execution statistics and system health metrics.
        """
        start_time = time.time()
        try:
            active_executions = execution_manager.get_active_executions()
            
            # Get execution statistics
            total_executions = 0
            successful_executions = 0
            failed_executions = 0
            
            # Real counters. The hasattr guard that used to wrap this checked
            # for a method that existed nowhere, so these were reported as zero
            # on every call (WILDBO-OBS-01).
            stats = execution_manager.get_execution_stats()
            total_executions = stats.get('total', 0)
            successful_executions = stats.get('successful', 0)
            failed_executions = stats.get('failed', 0)
            
            return {
                "service": "tools",
                "version": "1.0.0",
                "timestamp": time.time(),
                "uptime_seconds": time.time() - app.state.start_time if hasattr(app.state, 'start_time') else 0,
                "metrics": {
                    "tools_total": len(discovered_tools),
                    "tools_available": len(discovered_tools),
                    "executions_active": len(active_executions),
                    "executions_total": total_executions,
                    "executions_successful": successful_executions,
                    "executions_failed": failed_executions,
                    "max_concurrent": settings.max_concurrent_tools,
                    "default_timeout_seconds": settings.tool_timeout,
                    "rate_limit_requests": settings.rate_limit_requests,
                    "rate_limit_window_seconds": settings.rate_limit_window
                },
                "tools": list(discovered_tools.keys())
            }
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error collecting metrics: {e}")
            return {
                "service": "tools",
                "version": "1.0.0",
                "timestamp": time.time(),
                "error": "Failed to collect metrics",
                "details": str(e)
            }
    
    # System information endpoint
    @app.get("/api/system/info", tags=["System"])
    async def system_info():
        """Get detailed system information."""
        active_executions = execution_manager.get_active_executions()
        return {
            "application": {
                "name": "Wildbox Security Tools",
                "version": "1.0.0",
                "environment": settings.environment,
                "debug": settings.debug
            },
            "tools": {
                "count": len(discovered_tools),
                "available": list(discovered_tools.keys())
            },
            "execution": {
                "active_count": len(active_executions),
                "max_concurrent": settings.max_concurrent_tools,
                "default_timeout": settings.tool_timeout
            },
            "security": {
                "rate_limit_requests": settings.rate_limit_requests,
                "rate_limit_window": settings.rate_limit_window
            }
        }
    
    @app.get("/api/system/metrics", tags=["System"])
    async def system_metrics():
        """Get system performance metrics."""
        from app.middleware import metrics_middleware
        
        base_metrics = {
            "uptime": time.time() - startup_time,
            "tools": {
                "total": len(discovered_tools),
                "statistics": {}
            },
            "execution": {
                "active": len(execution_manager.get_active_executions()),
                "total_completed": len(execution_manager.get_execution_history())
            }
        }
        
        # Add tool-specific statistics
        for tool_name in discovered_tools.keys():
            base_metrics["tools"]["statistics"][tool_name] = execution_manager.get_tool_statistics(tool_name)
        
        # Add HTTP metrics if available
        if metrics_middleware:
            base_metrics["http"] = metrics_middleware.get_metrics()
        
        return base_metrics

    # Store startup time for uptime calculation
    global startup_time
    startup_time = time.time()
    
    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint for Docker and monitoring."""
        uptime = time.time() - startup_time
        return {
            "status": "healthy",
            "uptime_seconds": round(uptime, 2),
            "version": "1.0.0",
            "tools_loaded": len(discovered_tools),
            "timestamp": time.time()
        }
    
    # Root redirect
    @app.get("/api")
    async def api_root():
        """API root endpoint with basic information."""
        return {
            "message": "Wildbox Security Tools",
            "version": "1.0.0",
            "docs": "/docs",
            "tools": f"/api/tools",
            "available_tools": list(discovered_tools.keys())
        }
    
    @app.get("/api/system/health-aggregate", tags=["System"])
    async def system_health_aggregate():
        """Get aggregated health metrics from all services."""
        import httpx
        
        services = {
            "identity": settings.identity_service_url or "http://open-security-identity:8001",
            "data": settings.data_service_url or "http://open-security-data:8002", 
            "guardian": settings.guardian_service_url or "http://open-security-guardian:8013",
            "sensor": settings.sensor_service_url or "http://open-security-sensor:8004",
            "responder": settings.responder_service_url or "http://open-security-responder:8018",
            "agents": settings.agents_service_url or "http://open-security-agents:8006",
            "cspm": settings.cspm_service_url or "http://open-security-cspm:8019"
        }
        
        health_status = {
            "api": {
                "status": "operational",
                "uptime": time.time() - startup_time,
                "response_time": 0,  # Will be calculated
                "version": "1.0.0"
            }
        }
        
        total_services = len(services) + 1  # +1 for API itself
        operational_services = 1  # API is operational
        total_response_time = 0
        
        async with httpx.AsyncClient(timeout=5.0) as client:
            for service_name, service_url in services.items():
                try:
                    start_time = time.time()
                    response = await client.get(f"{service_url}/health")
                    response_time = (time.time() - start_time) * 1000
                    
                    if response.status_code == 200:
                        health_status[service_name] = {
                            "status": "operational",
                            "response_time": response_time,
                            "data": response.json()
                        }
                        operational_services += 1
                        total_response_time += response_time
                    else:
                        health_status[service_name] = {
                            "status": "degraded",
                            "response_time": response_time,
                            "error": f"HTTP {response.status_code}"
                        }
                        total_response_time += response_time
                        
                except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                    health_status[service_name] = {
                        "status": "down",
                        "error": str(e)
                    }
        
        # Calculate aggregate metrics
        uptime_percentage = (operational_services / total_services) * 100
        avg_response_time = total_response_time / total_services if total_services > 0 else 0
        error_rate = ((total_services - operational_services) / total_services) * 100
        
        overall_status = "operational"
        if uptime_percentage < 50:
            overall_status = "down"
        elif uptime_percentage < 90:
            overall_status = "degraded"
            
        return {
            "status": overall_status,
            "uptime_percentage": round(uptime_percentage, 2),
            "avg_response_time": round(avg_response_time, 0),
            "error_rate": round(error_rate, 2),
            "services": health_status,
            "summary": {
                "total_services": total_services,
                "operational_services": operational_services,
                "degraded_services": total_services - operational_services,
                "timestamp": datetime.now().isoformat()
            }
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
