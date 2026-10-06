"""
Celery tasks for asynchronous tool execution.
"""

import time
import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional
from celery import Task, signals
from celery.exceptions import Ignore, SoftTimeLimitExceeded, TimeLimitExceeded

from app import async_metrics
from app.celery_app import celery_app
from app.execution_manager import ExecutionStatus, ToolAuthorizationError, authorize_tool_call
from app.log_safety import error_site
from app.prerun import PRE_RUN_REFUSALS, check_tool_request, refusal_log, refusal_text
from app.task_ownership import TaskOwnershipUnavailable, get_task_ownership
from app.tool_loader import load_tool_module as _shared_load_tool_module
from app.logging_config import get_logger

logger = get_logger(__name__)

TASK_NAME = 'app.tasks.execute_tool_async'

# What a task's result says when its tool raised: the words of the
# synchronous route's 500, followed by the class of the exception.
TOOL_FAILED = "Tool execution failed"

# Where the task body leaves the outcome of a run it ends by returning, for
# _count_returned_task below. The result a client reads says "failed" for a
# task that never started its tool (no such tool, input that does not
# validate, a refused target); the counter says "refused" for those, as it
# does for a caller who may not run the tool, so that "failed" means in both
# counters what the alert on it says: the tool ran and raised.
_OUTCOME_ATTRIBUTE = 'wildbox_outcome'


ARGUMENTS_NOT_SHOWN = "<not shown>"


def shown_arguments(kwargs: Optional[Dict[str, Any]]) -> str:
    """What a task's message says its arguments are: all but the input.

    Celery sends, beside the arguments a task runs with, a text of them for
    people to read: ``kwargsrepr``. It is what the worker puts in the record
    of "Task received" and of a failure, what ``celery inspect active``
    answers, and what the task events carry to Flower, which shows it. By
    default it is the first 1024 characters of ``repr(kwargs)``: the tool's
    input, credentials included. The text is written here instead, with the
    number of fields in place of the input.
    """
    if not isinstance(kwargs, dict):
        return ARGUMENTS_NOT_SHOWN
    shown = {
        name: value
        for name, value in kwargs.items()
        if name in ("tool_name", "user_id", "timeout")
        and isinstance(value, (str, int, float, type(None)))
    }
    if "input_data" in kwargs:
        fields = kwargs["input_data"]
        shown["input_data"] = (
            f"<{len(fields)} field(s)>" if isinstance(fields, dict) else ARGUMENTS_NOT_SHOWN
        )
    return repr(shown)


class ToolExecutionTask(Task):
    """Base task class with retry logic and error handling."""

    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 2, 'countdown': 5}
    retry_backoff = True
    retry_backoff_max = 600
    retry_jitter = True

    def apply_async(self, args=None, kwargs=None, **options):
        """Send the task with a description of its arguments that omits the input.

        Here and not where the route submits it, so that it also holds for
        the message a retry sends: Celery builds that one from the request
        and does not carry the description over (#755).
        """
        options["argsrepr"] = ARGUMENTS_NOT_SHOWN if args else "()"
        options["kwargsrepr"] = shown_arguments(kwargs)
        return super().apply_async(args, kwargs, **options)


# --- counting the asynchronous runs (#721) ----------------------------------
#
# One count per task, added when Celery settles the task's state and by the
# process that settles it, which is not always the one that ran it:
#
#   returned (completed, a soft time limit, a refusal)   task_success, child
#   raised, retries exhausted                            task_failure, child
#   killed at the hard time limit                        task_failure, MAIN
#   cancelled, waiting or running                        task_revoked, MAIN
#
# A counter in the task body would miss the last two: the child is killed, or
# never ran. A retry is not an end and is not counted; a task whose child
# died and that Celery put back on the queue (task_reject_on_worker_lost) is
# counted when it does end. The counts are in Redis (app/async_metrics.py)
# because the processes above share nothing else, and the API exports them.
#
# task_prerun counts every start, so that the API can also export whether
# the worker is taking tasks off the queue at all.
#
# The handlers are connected without a sender and compare the task's name:
# the object this module binds to execute_tool_async is a proxy, not the
# task instance Celery sends as the sender.


def _is_tool_task(sender) -> bool:
    return getattr(sender, 'name', None) == TASK_NAME


def _tool_name(kwargs) -> Optional[str]:
    return kwargs.get('tool_name') if isinstance(kwargs, dict) else None


@signals.task_prerun.connect
def _count_taken_task(sender=None, task_id=None, **_):
    if _is_tool_task(sender):
        async_metrics.record_taken(task_id)


@signals.task_success.connect
def _count_returned_task(sender=None, result=None, **_):
    if not _is_tool_task(sender):
        return
    request = sender.request
    outcome = getattr(request, _OUTCOME_ATTRIBUTE, None)
    if outcome is None:
        # The body always sets it; a result without one is counted for what
        # it says rather than not at all.
        status = result.get('status') if isinstance(result, dict) else None
        outcome = status if status in async_metrics.OUTCOMES else async_metrics.COMPLETED
    async_metrics.record_outcome(request.id, _tool_name(request.kwargs), outcome)


@signals.task_failure.connect
def _count_failed_task(sender=None, task_id=None, exception=None, kwargs=None, **_):
    if not _is_tool_task(sender):
        return
    # TimeLimitExceeded is the hard limit: the worker's main process killed
    # the child and reports here. The soft limit is caught in the task body.
    outcome = (
        async_metrics.TIMEOUT
        if isinstance(exception, TimeLimitExceeded)
        else async_metrics.FAILED
    )
    async_metrics.record_outcome(task_id, _tool_name(kwargs), outcome)


@signals.task_revoked.connect
def _count_cancelled_task(sender=None, request=None, terminated=None, **_):
    if not _is_tool_task(sender):
        return
    async_metrics.record_outcome(
        getattr(request, 'id', None),
        _tool_name(getattr(request, 'kwargs', None)),
        async_metrics.CANCELLED,
        # Cancelled while it waited: the worker took it off the queue only to
        # drop it, and no start has counted it as consumed.
        taken_now=not terminated,
    )


# How many starts of one task may end with its process gone. A process can be
# killed once for a reason that has nothing to do with the task (the kernel
# under memory pressure, a worker stopped hard), and the task deserves another
# go. A tool that takes its process down every time must not come back for
# ever: after this many starts that left no result, the next delivery fails
# the task (#743).
MAX_LOST_STARTS = 3


def _starts_lost(task_id: Optional[str], retries: int) -> int:
    """Count this start; return how many earlier ones left no result.

    Every start is counted in Redis (app/task_ownership.py). A task has one
    start, plus one for each retry Celery scheduled, and each of those ends
    with a state. Any start beyond that number is a redelivery: the process
    that ran an earlier one died, or its whole worker was killed and the
    broker gave the task to another. As for a cancellation, a Redis that
    does not answer is raised.
    """
    if not task_id:
        return 0
    try:
        ownership = get_task_ownership()
    except TaskOwnershipUnavailable:
        return 0
    return max(0, ownership.count_start(task_id) - 1 - int(retries or 0))


def _cancelled_by_its_owner(task_id: Optional[str]) -> bool:
    """Whether the task's owner cancelled it (app/task_ownership.py, #743).

    A Redis that does not answer is raised, not read as "no": the task is
    retried and then failed, never run without having asked. Without a
    REDIS_URL there is no queue and no record to ask for.
    """
    if not task_id:
        return False
    try:
        ownership = get_task_ownership()
    except TaskOwnershipUnavailable:
        return False
    return ownership.is_cancelled(task_id)


@celery_app.task(
    bind=True,
    base=ToolExecutionTask,
    name=TASK_NAME,
    track_started=True
)
def execute_tool_async(
    self,
    tool_name: str,
    input_data: Dict[str, Any],
    user_id: Optional[str] = None,
    timeout: Optional[int] = None
) -> Dict[str, Any]:
    """
    Execute a security tool asynchronously.
    
    Args:
        tool_name: Name of the tool to execute
        input_data: Tool input parameters (as dict)
        user_id: The caller the submitting request authenticated as. Tools
            that act on a caller's behalf require it (see authorize_tool_call).
        timeout: Optional timeout override
        
    Returns:
        Dict containing execution result
    """
    start_time = time.time()
    task_id = self.request.id
    # Whether the tool itself was called: what ends before that is counted
    # as refused, what raises after it as failed (see _OUTCOME_ATTRIBUTE).
    tool_started = False

    def settled(outcome: str) -> None:
        setattr(self.request, _OUTCOME_ATTRIBUTE, outcome)

    # A cancelled task does not run, whichever worker takes it and whenever.
    # Celery's revocation is a message to the workers alive when it is sent;
    # one that started since never heard it and would run the task. The
    # owner's cancellation is a record in Redis, and this is where it holds.
    if _cancelled_by_its_owner(task_id):
        logger.info(
            f"Async tool execution cancelled before it started: {tool_name}",
            extra={"tool_name": tool_name, "task_id": task_id},
        )
        # The state Celery itself writes for a revoked task, so the task
        # reads the same whichever way its cancellation reached the worker.
        self.backend.mark_as_revoked(
            task_id, reason="cancelled by its owner", request=self.request
        )
        async_metrics.record_outcome(task_id, tool_name, async_metrics.CANCELLED)
        # Nothing more to store and nothing to retry: acknowledge and stop.
        raise Ignore()

    # A task that keeps taking its process down is not started again.
    lost = _starts_lost(task_id, self.request.retries)
    if lost >= MAX_LOST_STARTS:
        error_msg = (
            f"The worker process running this task was lost {lost} times; "
            "the task was not started again"
        )
        logger.error(
            f"Async tool execution abandoned: {tool_name}",
            extra={"tool_name": tool_name, "task_id": task_id, "lost_starts": lost},
        )
        settled(async_metrics.FAILED)
        return {
            'status': 'failed',
            'error': error_msg,
            'duration': time.time() - start_time,
            'tool_name': tool_name,
            'task_id': task_id
        }
    
    logger.info(
        f"Starting async tool execution: {tool_name}",
        extra={
            "tool_name": tool_name,
            "task_id": task_id,
            "user_id": user_id,
            "timeout": timeout
        }
    )
    
    # Update task state to RUNNING with metadata
    self.update_state(
        state='RUNNING',
        meta={
            'tool_name': tool_name,
            'started_at': start_time,
            'status': 'executing'
        }
    )
    
    try:
        # The checks that come before a run, the ones the API applied when it
        # accepted the task (app/prerun.py): the name is a tool, the input is
        # what its model accepts, and the target is not private, internal or
        # cloud metadata (#614). They run again here because the answer can
        # have changed since: a name resolves to another address, the
        # operator's allowlist changed, this worker has another set of tools.
        # A refusal is returned, not raised: the task answers "failed" with
        # the reason and is not retried. The caller reads the refusal as the
        # routes word it (refusal_text); the log has its kind and the fields
        # concerned, not the target or the values it names (#755).
        try:
            checked = check_tool_request(tool_name, input_data, load=_load_tool_module)
        except PRE_RUN_REFUSALS as e:
            duration = time.time() - start_time
            logger.warning(
                f"Async tool execution refused before the run: {tool_name}",
                extra={
                    "tool_name": tool_name,
                    "task_id": task_id,
                    "reason": refusal_log(e),
                    "duration": f"{duration:.3f}s",
                    "status": "failed"
                }
            )
            settled(async_metrics.REFUSED)
            return {
                'status': 'failed',
                'error': refusal_text(e),
                'duration': duration,
                'tool_name': tool_name,
                'task_id': task_id
            }
        execute_func = checked.execute
        validated_input = checked.validated_input

        # Authorize the call exactly as the synchronous path does: a tool
        # that declares user_id needs a caller who may run it, and receives
        # that caller (#563). Refusals are returned, not raised, so the retry
        # policy does not run a refused tool again.
        try:
            tool_kwargs = authorize_tool_call(execute_func, tool_name, validated_input, user_id)
        except ToolAuthorizationError as e:
            logger.warning(
                f"Async tool execution refused: {tool_name}",
                extra={"tool_name": tool_name, "task_id": task_id, "reason": str(e)}
            )
            settled(async_metrics.REFUSED)
            return {
                'status': ExecutionStatus.REFUSED.value,
                'error': str(e),
                'duration': time.time() - start_time,
                'tool_name': tool_name,
                'task_id': task_id
            }

        # Execute the tool (handle both sync and async)
        import inspect
        tool_started = True
        if inspect.iscoroutinefunction(execute_func):
            # Async function - need to run in event loop
            import asyncio
            result = asyncio.run(execute_func(validated_input, **tool_kwargs))
        else:
            # Sync function - call directly
            result = execute_func(validated_input, **tool_kwargs)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Convert result to dict if it's a Pydantic model
        if hasattr(result, 'model_dump'):
            result_dict = result.model_dump()
        elif isinstance(result, dict):
            result_dict = result
        else:
            result_dict = {"raw_result": str(result)}
        
        # Enrich with metadata
        result_dict['tool_name'] = tool_name
        result_dict['execution_time'] = duration
        result_dict['task_id'] = task_id
        
        logger.info(
            f"Async tool execution completed: {tool_name}",
            extra={
                "tool_name": tool_name,
                "task_id": task_id,
                "duration": f"{duration:.3f}s",
                "status": "completed"
            }
        )
        
        settled(async_metrics.COMPLETED)
        return {
            'status': 'completed',
            'result': result_dict,
            'duration': duration,
            'tool_name': tool_name,
            'task_id': task_id
        }
        
    except SoftTimeLimitExceeded:
        duration = time.time() - start_time
        error_msg = f"Tool execution exceeded time limit"
        
        logger.warning(
            f"Async tool execution timeout: {tool_name}",
            extra={
                "tool_name": tool_name,
                "task_id": task_id,
                "duration": f"{duration:.3f}s",
                "status": "timeout"
            }
        )
        
        settled(async_metrics.TIMEOUT)
        return {
            'status': 'timeout',
            'error': error_msg,
            'duration': duration,
            'tool_name': tool_name,
            'task_id': task_id
        }
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        duration = time.time() - start_time
        # What the tool raised while it worked on the caller's input. Its
        # text can quote that input (the URL a client could not fetch, the
        # value a parser refused), so it is neither logged nor stored: the
        # log has the class and the line, and the result, which Redis keeps
        # for an hour and the caller reads, says what the synchronous route
        # says for the same failure, with the class (#755). This stored and
        # logged str(e).
        logger.error(
            f"Async tool execution failed: {tool_name}",
            extra={
                "tool_name": tool_name,
                "task_id": task_id,
                "error_type": error_site(e),
                "duration": f"{duration:.3f}s",
                "status": "failed"
            }
        )

        settled(async_metrics.FAILED if tool_started else async_metrics.REFUSED)
        return {
            'status': 'failed',
            'error': f"{TOOL_FAILED} ({type(e).__name__})",
            'duration': duration,
            'tool_name': tool_name,
            'task_id': task_id
        }


def _load_tool_module(tool_name: str):
    """
    Load a tool module for execution in the worker.

    Delegates to app.tool_loader so the worker and the API process load tools
    identically. The worker used to carry its own copy of the dynamic-import
    logic with different sys.modules sequencing (WILDBO-ARCH-06), and it
    re-executed three modules from disk on every task because nothing cached
    them (WILDBO-PERF-05); importlib's module cache now handles that.
    """
    return _shared_load_tool_module(tool_name)

