"""
FastAPI main application for Open Security Responder

SOAR orchestration service with REST API interface.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import redis

from .models import (
    PlaybookExecutionRequest, PlaybookExecutionResult, 
    PlaybookListResponse, HealthCheckResponse
)
from .config import settings
from .playbook_parser import playbook_parser
from .workflow_engine import start_execution, workflow_engine
from .connectors.base import connector_registry

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
        
        logger.info("Open Security Responder started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Open Security Responder...")


# Initialize FastAPI app
app = FastAPI(
    title="Open Security Responder",
    description="SOAR (Security Orchestration, Automation and Response) microservice",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
            timestamp=datetime.utcnow(),
            version="1.0.0",
            redis_connected=redis_connected,
            playbooks_loaded=playbooks_loaded
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )


@app.get("/v1/playbooks", response_model=PlaybookListResponse)
async def list_playbooks():
    """List all available playbooks"""
    try:
        playbooks_list = playbook_parser.list_playbooks()
        return PlaybookListResponse(
            playbooks=playbooks_list,
            total=len(playbooks_list)
        )
    except Exception as e:
        logger.error(f"Failed to list playbooks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list playbooks: {str(e)}"
        )


@app.post("/v1/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    request: PlaybookExecutionRequest = PlaybookExecutionRequest()
):
    """Execute a playbook"""
    try:
        # Validate playbook exists
        try:
            playbook = playbook_parser.get_playbook(playbook_id)
        except KeyError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Playbook '{playbook_id}' not found"
            )
        
        # Start execution
        run_id = start_execution(playbook_id, request.trigger_data)
        
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
    except Exception as e:
        logger.error(f"Failed to execute playbook {playbook_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute playbook: {str(e)}"
        )


@app.get("/v1/runs/{run_id}", response_model=PlaybookExecutionResult)
async def get_execution_status(run_id: str):
    """Get execution status and results"""
    try:
        execution_result = workflow_engine.get_execution_state(run_id)
        
        if not execution_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution '{run_id}' not found"
            )
        
        return execution_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get execution status for {run_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get execution status: {str(e)}"
        )


@app.post("/v1/playbooks/reload")
async def reload_playbooks():
    """Reload playbooks from disk"""
    try:
        playbooks = playbook_parser.reload_playbooks()
        return {
            "message": "Playbooks reloaded successfully",
            "total_loaded": len(playbooks),
            "playbooks": list(playbooks.keys())
        }
    except Exception as e:
        logger.error(f"Failed to reload playbooks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reload playbooks: {str(e)}"
        )


@app.get("/v1/connectors")
async def list_connectors():
    """List all available connectors and their actions"""
    try:
        connectors = connector_registry.list_connectors()
        return {
            "connectors": connectors,
            "total": len(connectors)
        }
    except Exception as e:
        logger.error(f"Failed to list connectors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list connectors: {str(e)}"
        )


@app.delete("/v1/runs/{run_id}")
async def cancel_execution(run_id: str):
    """Cancel a running execution"""
    try:
        # For now, we'll just mark it as cancelled in Redis
        execution_result = workflow_engine.get_execution_state(run_id)
        
        if not execution_result:
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
    except Exception as e:
        logger.error(f"Failed to cancel execution {run_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel execution: {str(e)}"
        )


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Open Security Responder",
        "version": "1.0.0",
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
