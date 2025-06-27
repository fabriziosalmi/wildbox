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
from app.exceptions import (
    http_exception_handler,
    validation_exception_handler,
    pydantic_validation_exception_handler,
    general_exception_handler,
    starlette_http_exception_handler
)
from app.api.router import router as api_router, DISCOVERED_TOOLS, register_tool_endpoint
from app.web.router import router as web_router
from app.web.router import DISCOVERED_TOOLS as web_discovered_tools
from app.execution_manager import execution_manager
from app.secure_execution_manager import SecureToolExecutionManager

# Configure logging first
configure_logging()
logger = get_logger(__name__)

def discover_tools() -> Dict[str, Any]:
    """
    Dynamically discover security tools in the tools directory.
    
    Returns:
        Dictionary mapping tool names to their modules
    """
    tools = {}
    tools_dir = Path(__file__).parent / "tools"
    
    if not tools_dir.exists():
        logger.warning("Tools directory not found")
        return tools
    
    logger.info(f"Discovering tools in: {tools_dir}")
    
    for tool_dir in tools_dir.iterdir():
        if not tool_dir.is_dir() or tool_dir.name.startswith('_'):
            continue
            
        tool_name = tool_dir.name
        main_file = tool_dir / "main.py"
        schemas_file = tool_dir / "schemas.py"
        
        if not main_file.exists() or not schemas_file.exists():
            logger.warning(f"Tool {tool_name} missing required files (main.py or schemas.py)")
            continue
        
        try:
            # Import the standardized_schemas module first
            standardized_schemas_path = Path(__file__).parent / "standardized_schemas.py"
            standardized_spec = importlib.util.spec_from_file_location("standardized_schemas", standardized_schemas_path)
            standardized_module = importlib.util.module_from_spec(standardized_spec)
            standardized_spec.loader.exec_module(standardized_module)
            
            # Import the tool's schemas module with standardized_schemas available
            schemas_spec = importlib.util.spec_from_file_location(f"{tool_name}.schemas", schemas_file)
            schemas_module = importlib.util.module_from_spec(schemas_spec)
            
            # Add standardized_schemas to sys.modules temporarily so schemas.py can import it
            sys.modules['standardized_schemas'] = standardized_module
            
            # Add the tool directory to sys.path temporarily for schemas
            sys.path.insert(0, str(tool_dir))
            try:
                schemas_spec.loader.exec_module(schemas_module)
            finally:
                sys.path.remove(str(tool_dir))
                # Clean up the temporary standardized_schemas module from sys.modules
                if 'standardized_schemas' in sys.modules:
                    del sys.modules['standardized_schemas']
            
            # Import the tool's main module
            spec = importlib.util.spec_from_file_location(f"{tool_name}.main", main_file)
            main_module = importlib.util.module_from_spec(spec)
            
            # Add the schemas module to sys.modules temporarily so main.py can import it
            schemas_module_name = f"{tool_name}_schemas_temp"
            sys.modules['schemas'] = schemas_module
            
            # Add the tool directory to sys.path temporarily
            sys.path.insert(0, str(tool_dir))
            try:
                spec.loader.exec_module(main_module)
            finally:
                sys.path.remove(str(tool_dir))
                # Clean up the temporary schemas module from sys.modules
                if 'schemas' in sys.modules:
                    del sys.modules['schemas']
            
            # Attach schemas to main module for easier access
            main_module.schemas = schemas_module
            
            # Validate required components
            if not hasattr(main_module, 'execute_tool'):
                logger.error(f"Tool {tool_name} missing execute_tool function")
                continue
                
            if not hasattr(main_module, 'TOOL_INFO'):
                logger.warning(f"Tool {tool_name} missing TOOL_INFO metadata")
                main_module.TOOL_INFO = {
                    "name": tool_name,
                    "display_name": tool_name.replace("_", " ").title(),
                    "description": "No description provided",
                    "version": "unknown",
                    "author": "unknown",
                    "category": "general"
                }
            
            tools[tool_name] = main_module
            logger.info(f"Successfully loaded tool: {tool_name}")
            
        except Exception as e:
            logger.error(f"Failed to load tool {tool_name}: {str(e)}")
            continue
    
    logger.info(f"Discovered {len(tools)} tools: {list(tools.keys())}")
    return tools


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
            
    except Exception as e:
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
        version="1.0.0",
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
    
    # Add exception handlers
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValidationError, pydantic_validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
    
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
        active_executions = execution_manager.get_active_executions()
        return {
            "status": "healthy",
            "version": "1.0.0",
            "environment": settings.environment,
            "tools_count": len(discovered_tools),
            "available_tools": list(discovered_tools.keys()),
            "active_executions": len(active_executions),
            "max_concurrent_tools": settings.max_concurrent_tools,
            "default_timeout": settings.tool_timeout
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
                        
                except Exception as e:
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
