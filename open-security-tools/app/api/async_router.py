"""
Async execution endpoints for long-running tools.

The gateway serves these as ``POST /api/v1/tools/{tool_name}/async`` and
``GET``/``DELETE /api/v1/tasks/{task_id}``, ``GET /api/v1/tasks`` (#567).

A task belongs to the user who submitted it. Reading, cancelling and listing
are answered from the owner record taken at submission (app/task_ownership.py):
any task the caller did not submit is "not found", whether it exists or not.
"""

import uuid
from typing import Any, Dict, Optional

from celery.result import AsyncResult
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from kombu.exceptions import OperationalError
from open_security_shared.gateway_auth import GatewayUser
from redis.exceptions import RedisError

from app.auth import verify_api_key
from app.celery_app import celery_app
from app.logging_config import get_logger
from app.task_ownership import (
    TaskOwnership,
    TaskOwnershipUnavailable,
    get_task_ownership,
)
from app.tasks import execute_tool_async

logger = get_logger(__name__)

router = APIRouter(prefix="/api", tags=["Async Tool Execution"])

# Where a client reads a task back: the gateway path, the only one a client
# can reach (the service accepts gateway-authenticated requests only).
TASK_STATUS_PATH = "/api/v1/tasks/{task_id}"

TASK_NOT_FOUND = "Task not found"


def _ownership() -> TaskOwnership:
    try:
        return get_task_ownership()
    except TaskOwnershipUnavailable as e:
        logger.error(f"Async task tracking unavailable: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Asynchronous execution is unavailable",
        )


def _tracking_failed(e: Exception) -> HTTPException:
    logger.error(f"Async task tracking failed: {e}")
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Asynchronous execution is unavailable",
    )


def _owned_task(task_id: str, caller: GatewayUser) -> Dict[str, Any]:
    """The caller's owner record for the task, or 404.

    404 and not 403 for another user's task: the answer must not confirm that
    a task id exists.
    """
    try:
        owner = _ownership().owned_by(task_id, str(caller.user_id))
    except RedisError as e:
        raise _tracking_failed(e)
    if owner is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=TASK_NOT_FOUND
        )
    return owner


def _status_of(state: str, result: Any) -> str:
    """The status a client sees for a Celery state."""
    if state == "SUCCESS":
        # The task finishes without raising when the tool failed, timed out or
        # was refused, and reports which in its own status.
        if isinstance(result, dict):
            return result.get("status", "completed")
        return "completed"
    return {
        "PENDING": "pending",
        "STARTED": "running",
        "RUNNING": "running",
        "RETRY": "retrying",
        "FAILURE": "failed",
        "REVOKED": "cancelled",
    }.get(state, "unknown")


@router.post("/tools/{tool_name}/async", status_code=status.HTTP_202_ACCEPTED)
def submit_tool_async(
    tool_name: str,
    request: Request,
    input_data: dict = Body(...),
    caller: GatewayUser = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Submit a tool for asynchronous execution.

    Returns immediately with a task_id that the caller, and only the caller,
    can use to read, cancel and list the task.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    logger.info(
        f"Submitting async tool execution: {tool_name}",
        extra={"tool": tool_name, "request_id": request_id},
    )

    # The caller the request authenticated as. This read request.state.user_id,
    # which nothing sets, so every task ran for the literal caller "anonymous"
    # (#563). Tools that act on a caller's behalf are authorized for this one.
    user_id = str(caller.user_id)

    # The owner is recorded before the task is queued, so there is no moment
    # at which the task exists and its owner cannot read it (#567).
    task_id = str(uuid.uuid4())
    ownership = _ownership()
    try:
        ownership.record(
            task_id, user_id=user_id, team_id=str(caller.team_id), tool_name=tool_name
        )
    except RedisError as e:
        raise _tracking_failed(e)

    try:
        execute_tool_async.apply_async(
            task_id=task_id,
            kwargs={
                "tool_name": tool_name,
                "input_data": input_data,
                "user_id": user_id,
                "timeout": input_data.get("timeout"),
            },
        )
    except (OperationalError, OSError) as e:
        # The task was never queued; its record would only list a task that
        # stays pending. If Redis is down as well, the record expires on its own.
        try:
            ownership.forget(task_id, user_id)
        except RedisError as forget_error:
            logger.warning(
                f"Could not drop the record of task {task_id}: {forget_error}"
            )
        raise _tracking_failed(e)

    logger.info(
        f"Async task submitted: {tool_name}",
        extra={"tool": tool_name, "task_id": task_id, "request_id": request_id},
    )

    return {
        "task_id": task_id,
        "status": "accepted",
        "tool_name": tool_name,
        "status_url": TASK_STATUS_PATH.format(task_id=task_id),
        "message": "Task submitted successfully. Use task_id to check status.",
    }


@router.get("/tasks/{task_id}")
def get_task_status(
    task_id: str,
    request: Request,
    caller: GatewayUser = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Get the status and result of one of the caller's async tasks.

    Returns:
        Task status and result (if completed); 404 for a task the caller did
        not submit.
    """
    owner = _owned_task(task_id, caller)
    logger.debug(
        f"Checking task status: {task_id}",
        extra={
            "task_id": task_id,
            "request_id": getattr(request.state, "request_id", "unknown"),
        },
    )

    task_result = AsyncResult(task_id, app=celery_app)
    state = task_result.state

    response = {
        "task_id": task_id,
        "state": state,
        "tool_name": owner.get("tool_name"),
        "submitted_at": owner.get("submitted_at"),
    }

    if state == "PENDING":
        response.update(
            {"status": "pending", "message": "Task is waiting to be executed"}
        )

    elif state in ("STARTED", "RUNNING"):
        response.update({"status": "running", "message": "Task is currently executing"})
        if task_result.info:
            response["info"] = task_result.info

    elif state == "SUCCESS":
        result = task_result.result
        result = result if isinstance(result, dict) else {}
        response.update(
            {
                "status": _status_of(state, result),
                "error": result.get("error"),
                "result": result.get("result"),
                "duration": result.get("duration"),
                "tool_name": result.get("tool_name", owner.get("tool_name")),
                "completed_at": (
                    task_result.date_done.isoformat() if task_result.date_done else None
                ),
            }
        )

    elif state == "FAILURE":
        response.update(
            {
                "status": "failed",
                "error": str(task_result.info),
                "message": "Task execution failed",
            }
        )

    elif state == "RETRY":
        response.update(
            {
                "status": "retrying",
                "message": "Task is being retried after a failure",
                "info": str(task_result.info),
            }
        )

    elif state == "REVOKED":
        response.update({"status": "cancelled", "message": "Task was cancelled"})

    else:
        response.update(
            {"status": "unknown", "message": f"Unknown task state: {state}"}
        )

    return response


@router.delete("/tasks/{task_id}")
def cancel_task(
    task_id: str,
    request: Request,
    caller: GatewayUser = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Cancel one of the caller's pending or running tasks.

    404 for a task the caller did not submit; 400 for one that has finished.
    """
    _owned_task(task_id, caller)
    logger.info(
        f"Cancelling task: {task_id}",
        extra={
            "task_id": task_id,
            "request_id": getattr(request.state, "request_id", "unknown"),
        },
    )

    task_result = AsyncResult(task_id, app=celery_app)

    if task_result.state in ["PENDING", "STARTED", "RUNNING", "RETRY"]:
        task_result.revoke(terminate=True)

        return {
            "task_id": task_id,
            "status": "cancelled",
            "message": "Task cancellation requested",
        }
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Task cannot be cancelled (current state: {task_result.state})",
    )


@router.get("/tasks")
def list_tasks(
    caller: GatewayUser = Depends(verify_api_key),
    limit: int = Query(50, ge=1, le=100),
) -> Dict[str, Any]:
    """
    List the caller's recent async tasks, newest first.

    Only tasks the caller submitted, within the last day (the life of an owner
    record). This was a placeholder that pointed at Flower.
    """
    try:
        owned = _ownership().list_for(str(caller.user_id), limit)
    except RedisError as e:
        raise _tracking_failed(e)

    tasks = []
    for owner in owned:
        task_result = AsyncResult(owner["task_id"], app=celery_app)
        state = task_result.state
        result: Optional[Any] = task_result.result if state == "SUCCESS" else None
        tasks.append(
            {
                "task_id": owner["task_id"],
                "tool_name": owner.get("tool_name"),
                "submitted_at": owner.get("submitted_at"),
                "state": state,
                "status": _status_of(state, result),
                "status_url": TASK_STATUS_PATH.format(task_id=owner["task_id"]),
            }
        )

    return {"tasks": tasks, "count": len(tasks)}
