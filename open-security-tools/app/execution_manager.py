"""Tool execution manager with timeout and concurrency control."""

import asyncio
import time
import inspect
import uuid
from collections import deque
from typing import Any, Deque, Dict, Optional
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from app.config import settings
from app.logging_config import get_logger
from open_security_shared.observability import outcome_counter

logger = get_logger(__name__)

# The outcome an operator alerts on. Tool executions were previously observable
# only as log lines and as counters no endpoint could read (WILDBO-OBS-01/OBS-02).
TOOL_EXECUTIONS = outcome_counter(
    "wildbox_tool_executions_total",
    "Tool executions by tool and outcome.",
    ("tool", "outcome"),
)


class ExecutionStatus(Enum):
    """Tool execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class ExecutionResult:
    """Tool execution result."""
    status: ExecutionStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    duration: Optional[float] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None


class ToolExecutionManager:
    """
    Manages tool execution with timeout and concurrency control.

    SINGLE INSTANCE BY DESIGN. The semaphore, the active-execution registry, the
    history buffer and the per-tool statistics all live in this process, so
    running two replicas of the tools service would double the effective
    concurrency limit with nothing coordinating them, and /metrics would report
    whichever replica answered (WILDBO-SCAL-01).

    The service's Dockerfile starts uvicorn with a single worker, and the
    asynchronous path (Celery) already externalises its state to Redis, so this
    is the synchronous path's constraint alone. To replicate the service, move
    the ceiling to a Redis-backed counter and the registry to Redis keys, or
    route all executions through the Celery path.
    """
    
    def __init__(self, max_concurrent: int = None, default_timeout: int = None):
        self.max_concurrent = max_concurrent or settings.max_concurrent_tools
        self.default_timeout = default_timeout or settings.tool_timeout
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._active_executions: Dict[str, asyncio.Task] = {}
        # Bounded execution history. This was an unbounded list appended to in a
        # finally block on a module-level singleton, so resident memory grew with
        # request count for the life of the process (WILDBO-CONC-05).
        self._history_limit = getattr(settings, "execution_history_limit", 1000)
        self._execution_history: Deque[Dict[str, Any]] = deque(maxlen=self._history_limit)
        self._tool_statistics: Dict[str, Dict[str, Any]] = {}
        
    async def execute_tool(
        self,
        tool_func,
        input_data,
        tool_name: str,
        timeout: Optional[int] = None,
        execution_id: Optional[str] = None,
        user_id: Optional[str] = None  # Add user_id parameter
    ) -> ExecutionResult:
        """
        Execute a tool with timeout and concurrency control.
        
        Args:
            tool_func: The tool function to execute
            input_data: Input data for the tool
            tool_name: Name of the tool
            timeout: Execution timeout in seconds
            execution_id: Unique execution ID
            user_id: User ID for security controls (optional)
            
        Returns:
            ExecutionResult with status and results
        """
        
        timeout = timeout or self.default_timeout
        # Collision-free id. This used to be f"{tool_name}_{int(time.time()*1000)}",
        # so two executions of the same tool in the same millisecond shared a key:
        # the second overwrote the first's registration and the first's cleanup
        # then deregistered the second, leaving a running task invisible to the
        # metrics endpoint and unreachable by cancel_all_executions
        # (WILDBO-CONC-01). Callers may still pass their own id -- api/router.py
        # passes the request id -- but the default is now unique by construction.
        execution_id = execution_id or f"{tool_name}_{uuid.uuid4().hex}"
        
        # Apply security wrapper if available
        try:
            from app.security_integration import security_integration
            if security_integration.security_enabled:
                tool_func = security_integration.secure_tool_execution(tool_name)(tool_func)
        except ImportError:
            logger.debug("Security integration not available, proceeding without security controls")
        
        logger.info(
            f"Starting tool execution: {tool_name}",
            extra={
                "tool_name": tool_name,
                "execution_id": execution_id,
                "timeout": timeout,
                "active_executions": len(self._active_executions),
                "user_id": user_id if user_id else "anonymous"
            }
        )
        
        async with self._semaphore:
            start_time = time.time()
            end_time = None
            duration = 0
            status = ExecutionStatus.FAILED  # Default status
            
            try:
                # Handle both sync and async tool functions
                if inspect.iscoroutinefunction(tool_func):
                    # Async function - create task directly
                    task = asyncio.create_task(tool_func(input_data))
                else:
                    # Sync function - wrap in async and run in executor
                    async def run_sync():
                        loop = asyncio.get_event_loop()
                        return await loop.run_in_executor(None, tool_func, input_data)
                    task = asyncio.create_task(run_sync())
                
                self._active_executions[execution_id] = task
                
                # Execute with timeout
                result = await asyncio.wait_for(task, timeout=timeout)
                end_time = time.time()
                duration = end_time - start_time
                status = ExecutionStatus.COMPLETED
                
                logger.info(
                    f"Tool execution completed: {tool_name}",
                    extra={
                        "tool_name": tool_name,
                        "execution_id": execution_id,
                        "duration": f"{duration:.3f}s",
                        "status": "completed"
                    }
                )
                
                execution_result = ExecutionResult(
                    status=status,
                    result=result,
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                
            except asyncio.TimeoutError:
                end_time = time.time()
                duration = end_time - start_time
                status = ExecutionStatus.TIMEOUT
                
                logger.warning(
                    f"Tool execution timeout: {tool_name}",
                    extra={
                        "tool_name": tool_name,
                        "execution_id": execution_id,
                        "duration": f"{duration:.3f}s",
                        "timeout": timeout,
                        "status": "timeout"
                    }
                )
                
                # Cancel the task
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                
                execution_result = ExecutionResult(
                    status=status,
                    error=f"Tool execution timed out after {timeout} seconds",
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                
            except asyncio.CancelledError:
                end_time = time.time()
                duration = end_time - start_time
                status = ExecutionStatus.CANCELLED
                
                logger.warning(
                    f"Tool execution cancelled: {tool_name}",
                    extra={
                        "tool_name": tool_name,
                        "execution_id": execution_id,
                        "duration": f"{duration:.3f}s",
                        "status": "cancelled"
                    }
                )
                
                execution_result = ExecutionResult(
                    status=status,
                    error="Tool execution was cancelled",
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                
            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                end_time = time.time()
                duration = end_time - start_time
                status = ExecutionStatus.FAILED
                
                logger.error(
                    f"Tool execution failed: {tool_name}",
                    extra={
                        "tool_name": tool_name,
                        "execution_id": execution_id,
                        "error": str(e),
                        "duration": f"{duration:.3f}s",
                        "status": "failed"
                    }
                )
                
                execution_result = ExecutionResult(
                    status=status,
                    error=str(e),
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                
            finally:
                # Clean up, but only our own registration: compare identity so a
                # future id collision cannot deregister someone else's running
                # task (WILDBO-CONC-01).
                if self._active_executions.get(execution_id) is task:
                    del self._active_executions[execution_id]
                
                # Add to execution history
                self._execution_history.append({
                    "execution_id": execution_id,
                    "tool_name": tool_name,
                    "status": status.value,
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration": duration
                })
                
                # Update tool statistics
                if tool_name not in self._tool_statistics:
                    self._tool_statistics[tool_name] = {
                        "total_executions": 0,
                        "total_time": 0.0,
                        "success_count": 0,
                        "failure_count": 0,
                        "timeout_count": 0,
                        "cancelled_count": 0
                    }
                TOOL_EXECUTIONS.labels(tool=tool_name, outcome=status.value).inc()

                tool_stats = self._tool_statistics[tool_name]
                tool_stats["total_executions"] += 1
                tool_stats["total_time"] += duration
                if status == ExecutionStatus.COMPLETED:
                    tool_stats["success_count"] += 1
                elif status == ExecutionStatus.FAILED:
                    tool_stats["failure_count"] += 1
                elif status == ExecutionStatus.TIMEOUT:
                    tool_stats["timeout_count"] += 1
                elif status == ExecutionStatus.CANCELLED:
                    tool_stats["cancelled_count"] += 1
            
            return execution_result
    
    def get_active_executions(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently active executions."""
        return {
            execution_id: {
                "task": task,
                "done": task.done(),
                "cancelled": task.cancelled()
            }
            for execution_id, task in self._active_executions.items()
        }
    
    async def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a specific execution."""
        if execution_id in self._active_executions:
            task = self._active_executions[execution_id]
            if not task.done():
                task.cancel()
                logger.info(f"Cancelled execution: {execution_id}")
                return True
        return False
    
    async def cancel_all_executions(self, drain_timeout: float = 10.0) -> int:
        """
        Cancel every active execution and wait for them to finish unwinding.

        cancel() only schedules a CancelledError at the task's next suspension
        point. The previous version returned immediately, so shutdown proceeded
        -- and the process could exit -- while coroutines were mid-await and
        their finally blocks had not run (WILDBO-CONC-04). We now await the
        cancelled tasks, bounded by drain_timeout, and report how many actually
        terminated rather than how many cancellations were requested.
        """
        tasks = [t for t in list(self._active_executions.values()) if not t.done()]
        for task in tasks:
            task.cancel()

        if not tasks:
            logger.info("No active executions to cancel")
            return 0

        done, pending = await asyncio.wait(tasks, timeout=drain_timeout)
        if pending:
            logger.warning(
                f"{len(pending)} execution(s) did not terminate within "
                f"{drain_timeout}s of cancellation"
            )
        logger.info(f"Cancelled {len(tasks)} active executions, {len(done)} terminated")
        return len(done)
    
    def get_execution_history(self) -> list:
        """Get the execution history (a copy; the internal buffer is bounded)."""
        return list(self._execution_history)

    def get_execution_stats(self) -> Dict[str, int]:
        """
        Aggregate execution counters across all tools.

        The /metrics endpoint guarded on hasattr(execution_manager,
        "get_execution_stats") for a method that existed nowhere, so it reported
        zero executions, zero successes and zero failures on every call, forever
        (WILDBO-OBS-01). The per-tool counters below have always been maintained;
        nothing exposed them.
        """
        totals = {"total": 0, "successful": 0, "failed": 0, "timeout": 0, "cancelled": 0}
        for stats in self._tool_statistics.values():
            totals["total"] += stats.get("total_executions", 0)
            totals["successful"] += stats.get("success_count", 0)
            totals["failed"] += stats.get("failure_count", 0)
            totals["timeout"] += stats.get("timeout_count", 0)
            totals["cancelled"] += stats.get("cancelled_count", 0)
        return totals
    
    def get_tool_statistics(self, tool_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Statistics for one tool, or for all tools when no name is given.

        main.py called this with a tool name against a signature that took none,
        which raised TypeError inside the metrics endpoint (WILDBO-OBS-01).
        """
        if tool_name is not None:
            return dict(self._tool_statistics.get(tool_name, {}))
        return {name: dict(stats) for name, stats in self._tool_statistics.items()}


# Global execution manager instance
execution_manager = ToolExecutionManager()
