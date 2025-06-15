"""Tool execution manager with timeout and concurrency control."""

import asyncio
import time
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


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
    """Manages tool execution with timeout and concurrency control."""
    
    def __init__(self, max_concurrent: int = None, default_timeout: int = None):
        self.max_concurrent = max_concurrent or settings.max_concurrent_tools
        self.default_timeout = default_timeout or settings.tool_timeout
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._active_executions: Dict[str, asyncio.Task] = {}
        
    async def execute_tool(
        self,
        tool_func,
        input_data,
        tool_name: str,
        timeout: Optional[int] = None,
        execution_id: Optional[str] = None
    ) -> ExecutionResult:
        """
        Execute a tool with timeout and concurrency control.
        
        Args:
            tool_func: The tool function to execute
            input_data: Input data for the tool
            tool_name: Name of the tool
            timeout: Execution timeout in seconds
            execution_id: Unique execution ID
            
        Returns:
            ExecutionResult with status and results
        """
        
        timeout = timeout or self.default_timeout
        execution_id = execution_id or f"{tool_name}_{int(time.time() * 1000)}"
        
        logger.info(
            f"Starting tool execution: {tool_name}",
            extra={
                "tool_name": tool_name,
                "execution_id": execution_id,
                "timeout": timeout,
                "active_executions": len(self._active_executions)
            }
        )
        
        async with self._semaphore:
            start_time = time.time()
            
            try:
                # Create the execution task
                task = asyncio.create_task(tool_func(input_data))
                self._active_executions[execution_id] = task
                
                # Execute with timeout
                result = await asyncio.wait_for(task, timeout=timeout)
                end_time = time.time()
                duration = end_time - start_time
                
                logger.info(
                    f"Tool execution completed: {tool_name}",
                    extra={
                        "tool_name": tool_name,
                        "execution_id": execution_id,
                        "duration": f"{duration:.3f}s",
                        "status": "completed"
                    }
                )
                
                return ExecutionResult(
                    status=ExecutionStatus.COMPLETED,
                    result=result,
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                
            except asyncio.TimeoutError:
                end_time = time.time()
                duration = end_time - start_time
                
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
                
                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    error=f"Tool execution timed out after {timeout} seconds",
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                
            except asyncio.CancelledError:
                end_time = time.time()
                duration = end_time - start_time
                
                logger.warning(
                    f"Tool execution cancelled: {tool_name}",
                    extra={
                        "tool_name": tool_name,
                        "execution_id": execution_id,
                        "duration": f"{duration:.3f}s",
                        "status": "cancelled"
                    }
                )
                
                return ExecutionResult(
                    status=ExecutionStatus.CANCELLED,
                    error="Tool execution was cancelled",
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                
            except Exception as e:
                end_time = time.time()
                duration = end_time - start_time
                
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
                
                return ExecutionResult(
                    status=ExecutionStatus.FAILED,
                    error=str(e),
                    duration=duration,
                    start_time=start_time,
                    end_time=end_time
                )
                
            finally:
                # Clean up
                self._active_executions.pop(execution_id, None)
    
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
    
    async def cancel_all_executions(self) -> int:
        """Cancel all active executions."""
        cancelled_count = 0
        for execution_id, task in self._active_executions.items():
            if not task.done():
                task.cancel()
                cancelled_count += 1
        
        logger.info(f"Cancelled {cancelled_count} active executions")
        return cancelled_count


# Global execution manager instance
execution_manager = ToolExecutionManager()
