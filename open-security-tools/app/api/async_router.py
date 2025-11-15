"""
Async execution endpoints for long-running tools.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from typing import Dict, Any
from celery.result import AsyncResult

from app.auth import verify_api_key
from app.celery_app import celery_app
from app.tasks import execute_tool_async
from app.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api", tags=["Async Tool Execution"])


@router.post("/tools/{tool_name}/async", status_code=status.HTTP_202_ACCEPTED)
async def submit_tool_async(
    tool_name: str,
    request: Request,
    input_data: dict = Body(...),
    api_key: str = Depends(verify_api_key)
) -> Dict[str, Any]:
    """
    Submit a tool for asynchronous execution.
    
    Returns immediately with a task_id that can be used to check status.
    
    Args:
        tool_name: Name of the tool to execute
        input_data: Tool input parameters
        
    Returns:
        202 Accepted with task_id and status URL
    """
    logger.info(f"Submitting async tool execution: {tool_name}", extra={
        "tool": tool_name,
        "request_id": getattr(request.state, 'request_id', 'unknown')
    })
    
    # Get user ID from request state if available (set by auth middleware)
    user_id = getattr(request.state, 'user_id', 'anonymous')
    
    # Submit task to Celery
    task = execute_tool_async.apply_async(
        kwargs={
            'tool_name': tool_name,
            'input_data': input_data,
            'user_id': user_id,
            'timeout': input_data.get('timeout')
        }
    )
    
    logger.info(f"Async task submitted: {tool_name}", extra={
        "tool": tool_name,
        "task_id": task.id,
        "request_id": getattr(request.state, 'request_id', 'unknown')
    })
    
    return {
        "task_id": task.id,
        "status": "accepted",
        "tool_name": tool_name,
        "status_url": f"/api/tasks/{task.id}",
        "message": "Task submitted successfully. Use task_id to check status."
    }


@router.get("/tasks/{task_id}")
async def get_task_status(
    task_id: str,
    request: Request,
    api_key: str = Depends(verify_api_key)
) -> Dict[str, Any]:
    """
    Get the status and result of an async task.
    
    Args:
        task_id: The task ID returned by the submit endpoint
        
    Returns:
        Task status and result (if completed)
    """
    logger.debug(f"Checking task status: {task_id}", extra={
        "task_id": task_id,
        "request_id": getattr(request.state, 'request_id', 'unknown')
    })
    
    # Get task result
    task_result = AsyncResult(task_id, app=celery_app)
    
    # Map Celery states to our response format
    state = task_result.state
    
    response = {
        "task_id": task_id,
        "state": state,
    }
    
    if state == 'PENDING':
        response.update({
            "status": "pending",
            "message": "Task is waiting to be executed"
        })
    
    elif state == 'STARTED' or state == 'RUNNING':
        response.update({
            "status": "running",
            "message": "Task is currently executing"
        })
        # Add progress info if available
        if task_result.info:
            response["info"] = task_result.info
    
    elif state == 'SUCCESS':
        result = task_result.result
        response.update({
            "status": "completed",
            "result": result.get('result'),
            "duration": result.get('duration'),
            "tool_name": result.get('tool_name'),
            "completed_at": task_result.date_done.isoformat() if task_result.date_done else None
        })
    
    elif state == 'FAILURE':
        response.update({
            "status": "failed",
            "error": str(task_result.info),
            "message": "Task execution failed"
        })
    
    elif state == 'RETRY':
        response.update({
            "status": "retrying",
            "message": "Task is being retried after a failure",
            "info": task_result.info
        })
    
    elif state == 'REVOKED':
        response.update({
            "status": "cancelled",
            "message": "Task was cancelled"
        })
    
    else:
        response.update({
            "status": "unknown",
            "message": f"Unknown task state: {state}"
        })
    
    return response


@router.delete("/tasks/{task_id}")
async def cancel_task(
    task_id: str,
    request: Request,
    api_key: str = Depends(verify_api_key)
) -> Dict[str, Any]:
    """
    Cancel a running task.
    
    Args:
        task_id: The task ID to cancel
        
    Returns:
        Confirmation of cancellation
    """
    logger.info(f"Cancelling task: {task_id}", extra={
        "task_id": task_id,
        "request_id": getattr(request.state, 'request_id', 'unknown')
    })
    
    task_result = AsyncResult(task_id, app=celery_app)
    
    if task_result.state in ['PENDING', 'STARTED', 'RUNNING', 'RETRY']:
        task_result.revoke(terminate=True)
        
        return {
            "task_id": task_id,
            "status": "cancelled",
            "message": "Task cancellation requested"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Task cannot be cancelled (current state: {task_result.state})"
        )


@router.get("/tasks")
async def list_tasks(
    request: Request,
    api_key: str = Depends(verify_api_key),
    limit: int = 50
) -> Dict[str, Any]:
    """
    List recent tasks (requires Flower or custom tracking).
    
    Note: This is a placeholder. Full implementation would require
    Redis tracking or Flower API integration.
    """
    return {
        "message": "Task listing requires Flower monitoring or custom tracking",
        "flower_url": "http://localhost:5555",
        "note": "Use Flower web UI for comprehensive task monitoring"
    }
