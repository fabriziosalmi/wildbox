"""Main FastAPI application with dynamic tool discovery."""

import os
import sys
import time
import importlib.util
from pathlib import Path
from typing import Dict, Any, List
from contextlib import asynccontextmanager
import time

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
            # Import the tool's schemas module first
            schemas_spec = importlib.util.spec_from_file_location(f"{tool_name}.schemas", schemas_file)
            schemas_module = importlib.util.module_from_spec(schemas_spec)
            
            # Add the tool directory to sys.path temporarily for schemas
            sys.path.insert(0, str(tool_dir))
            try:
                schemas_spec.loader.exec_module(schemas_module)
            finally:
                sys.path.remove(str(tool_dir))
            
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
        title="Wildbox Security API",
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
                "name": "Wildbox Security API",
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
            "message": "Wildbox Security API",
            "version": "1.0.0",
            "docs": "/docs",
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
