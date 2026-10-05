"""
Async execution endpoints for long-running tools.

The gateway serves these as ``POST /api/v1/tools/{tool_name}/async`` and
``GET``/``DELETE /api/v1/tasks/{task_id}``, ``GET /api/v1/tasks`` (#567).

A task belongs to the user who submitted it. Reading, cancelling and listing
are answered from the owner record taken at submission (app/task_ownership.py):
any task the caller did not submit is "not found", whether it exists or not.
"""

import re
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from celery.result import AsyncResult
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from kombu.exceptions import OperationalError
from open_security_shared.gateway_auth import GatewayUser
from redis.exceptions import RedisError

from app.auth import require_tools_execute, verify_api_key
from app.celery_app import celery_app
from app.logging_config import get_logger
from app.prerun import PRE_RUN_REFUSALS, check_tool_request, http_error, refusal_log
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


# A state the stored result does not let us read.
UNREADABLE = "UNKNOWN"

# The progress fields execute_tool_async writes with update_state. STARTED
# carries the worker's host name and pid, which are not the caller's business.
PROGRESS_FIELDS = ("tool_name", "started_at", "status")

# An exception class name, the only part of a failure a client is shown: the
# message and traceback can carry internal paths, hosts and values.
_EXCEPTION_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,127}")


def _undecoded_meta(task_id: str) -> Dict[str, Any]:
    """The stored meta without turning its result back into an exception.

    Celery cannot rebuild an exception from a FAILURE or REVOKED result that
    is not in its own format (a dict without ``exc_type``, as written by
    ``update_state(state=FAILURE, meta={...})``) and raises ValueError, from
    ``AsyncResult.state`` as well. The state itself is still in the record.
    """
    backend = celery_app.backend
    try:
        payload = backend.get(backend.get_key_for_task(task_id))
        if payload is None:
            return {"status": "PENDING", "result": None}
        meta = backend.decode(payload)
    except Exception as e:  # noqa: BLE001 -- anything here is an unreadable record
        logger.warning(f"Unreadable result record for task {task_id}: {e!r}")
        return {"status": UNREADABLE, "result": None}
    if not isinstance(meta, dict):
        return {"status": UNREADABLE, "result": None}
    return meta


def _task_meta(task_id: str) -> Dict[str, Any]:
    """The task's state, result and completion time, read once.

    One read, not ``AsyncResult.state`` followed by ``.info``: Celery caches a
    result only once it is final, so each of those reads the backend again,
    and a task cancelled in between was RUNNING for the first and REVOKED for
    the second. The second then held a TaskRevokedError, which the response
    could not serialize, and the read answered 500 (#619).
    """
    try:
        meta = celery_app.backend.get_task_meta(task_id)
    except (RedisError, OperationalError, OSError) as e:
        raise _tracking_failed(e)
    except Exception as e:  # noqa: BLE001 -- a record Celery cannot decode
        logger.warning(f"Could not decode the result of task {task_id}: {e!r}")
        meta = _undecoded_meta(task_id)
    if not isinstance(meta, dict):
        return {"status": UNREADABLE, "result": None}
    return meta


def _state_of(meta: Dict[str, Any]) -> str:
    state = meta.get("status")
    return state if isinstance(state, str) and state else UNREADABLE


def _failure_name(result: Any) -> Optional[str]:
    """The exception class behind a failed or retried task, if it is known."""
    if isinstance(result, BaseException):
        name = type(result).__name__
    elif isinstance(result, dict):
        name = result.get("exc_type")
    else:
        name = None
    if isinstance(name, str) and _EXCEPTION_NAME.fullmatch(name):
        return name
    return None


def _failure_message(result: Any) -> str:
    name = _failure_name(result)
    if name:
        return f"Task execution failed ({name})"
    return "Task execution failed"


def _progress(info: Any) -> Optional[Dict[str, Any]]:
    """The progress fields of a running task, JSON-serializable."""
    if not isinstance(info, dict):
        return None
    progress = {
        key: info[key]
        for key in PROGRESS_FIELDS
        if isinstance(info.get(key), (str, int, float, bool))
    }
    return progress or None


def _completed_at(date_done: Any) -> Optional[str]:
    if isinstance(date_done, datetime):
        return date_done.isoformat()
    if isinstance(date_done, str):
        return date_done
    return None


@router.post("/tools/{tool_name}/async", status_code=status.HTTP_202_ACCEPTED)
def submit_tool_async(
    tool_name: str,
    request: Request,
    input_data: dict = Body(...),
    # Running a tool: tools:execute, checked here as at the gateway (#637).
    caller: GatewayUser = Depends(require_tools_execute),
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

    # Nothing invalid is queued (#743). What the synchronous route answers
    # before a run exists is answered here too, from the same check
    # (app/prerun.py): 404 for a name that is no tool, 422 for input the
    # tool's model refuses, 400 for a target the policy refuses. This route
    # used to queue anything and answer 202; the caller then read the
    # refusal back from the task, after it had taken a place in the queue
    # and a worker. The task checks again when it runs, since a name can
    # resolve differently by then. This handler is not a coroutine, so the
    # policy's name resolution runs in a worker thread.
    try:
        check_tool_request(tool_name, input_data)
    except PRE_RUN_REFUSALS as e:
        logger.warning(
            f"Async submission refused, {tool_name!r}: {refusal_log(e)}",
            extra={"request_id": request_id},
        )
        raise http_error(e)

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

    meta = _task_meta(task_id)
    state = _state_of(meta)
    result = meta.get("result")

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
        progress = _progress(result)
        if progress:
            response["info"] = progress

    elif state == "SUCCESS":
        result = result if isinstance(result, dict) else {}
        response.update(
            {
                "status": _status_of(state, result),
                "error": result.get("error"),
                "result": result.get("result"),
                "duration": result.get("duration"),
                "tool_name": result.get("tool_name", owner.get("tool_name")),
                "completed_at": _completed_at(meta.get("date_done")),
            }
        )

    elif state == "FAILURE":
        response.update(
            {
                "status": "failed",
                "error": _failure_message(result),
                "message": "Task execution failed",
                "completed_at": _completed_at(meta.get("date_done")),
            }
        )

    elif state == "RETRY":
        response.update(
            {
                "status": "retrying",
                "message": "Task is being retried after a failure",
                "info": _failure_message(result),
            }
        )

    elif state == "REVOKED":
        response.update(
            {
                "status": "cancelled",
                "message": "Task was cancelled",
                "completed_at": _completed_at(meta.get("date_done")),
            }
        )

    else:
        response.update(
            {"status": "unknown", "message": "The task state cannot be read"}
        )

    return response


@router.delete("/tasks/{task_id}")
def cancel_task(
    task_id: str,
    request: Request,
    # Cancelling is tools:execute, as running the tool was (#637).
    caller: GatewayUser = Depends(require_tools_execute),
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

    state = _state_of(_task_meta(task_id))

    if state in ("PENDING", "STARTED", "RUNNING", "RETRY"):
        AsyncResult(task_id, app=celery_app).revoke(terminate=True)

        return {
            "task_id": task_id,
            "status": "cancelled",
            "message": "Task cancellation requested",
        }
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Task cannot be cancelled (current state: {state})",
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
        meta = _task_meta(owner["task_id"])
        state = _state_of(meta)
        result = meta.get("result") if state == "SUCCESS" else None
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
