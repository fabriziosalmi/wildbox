"""
Celery tasks for asynchronous tool execution.
"""

import time
import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional
from celery import Task
from celery.exceptions import SoftTimeLimitExceeded

from app.celery_app import celery_app
from app.execution_manager import ExecutionStatus
from app.logging_config import get_logger

logger = get_logger(__name__)


class ToolExecutionTask(Task):
    """Base task class with retry logic and error handling."""
    
    autoretry_for = (Exception,)
    retry_kwargs = {'max_retries': 2, 'countdown': 5}
    retry_backoff = True
    retry_backoff_max = 600
    retry_jitter = True


@celery_app.task(
    bind=True,
    base=ToolExecutionTask,
    name='app.tasks.execute_tool_async',
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
        user_id: Optional user identifier for tracking
        timeout: Optional timeout override
        
    Returns:
        Dict containing execution result
    """
    start_time = time.time()
    task_id = self.request.id
    
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
        # Dynamically load the tool module
        logger.debug(f"Loading tool module: {tool_name}")
        tool_module = _load_tool_module(tool_name)
        if not tool_module:
            error_msg = f"Tool '{tool_name}' not found"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Get the execute function and input schema
        execute_func = getattr(tool_module, 'execute_tool', None)
        if not execute_func:
            raise ValueError(f"Tool '{tool_name}' missing execute_tool function")
        
        # Get input schema class
        schemas_module = getattr(tool_module, 'schemas', None)
        input_schema_class = _find_input_schema(schemas_module, tool_name)
        
        if not input_schema_class:
            raise ValueError(f"Tool '{tool_name}' missing input schema")
        
        # Validate and convert input
        validated_input = input_schema_class(**input_data)
        
        # Execute the tool (handle both sync and async)
        import inspect
        if inspect.iscoroutinefunction(execute_func):
            # Async function - need to run in event loop
            import asyncio
            result = asyncio.run(execute_func(validated_input))
        else:
            # Sync function - call directly
            result = execute_func(validated_input)
        
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
        
        return {
            'status': 'timeout',
            'error': error_msg,
            'duration': duration,
            'tool_name': tool_name,
            'task_id': task_id
        }
        
    except Exception as e:
        duration = time.time() - start_time
        error_msg = str(e)
        
        logger.error(
            f"Async tool execution failed: {tool_name}",
            extra={
                "tool_name": tool_name,
                "task_id": task_id,
                "error": error_msg,
                "duration": f"{duration:.3f}s",
                "status": "failed"
            }
        )
        
        return {
            'status': 'failed',
            'error': error_msg,
            'duration': duration,
            'tool_name': tool_name,
            'task_id': task_id
        }


def _load_tool_module(tool_name: str):
    """Load a tool module dynamically."""
    tools_dir = Path(__file__).parent / "tools"
    tool_dir = tools_dir / tool_name
    
    logger.debug(f"Looking for tool in: {tool_dir}")
    
    if not tool_dir.exists():
        logger.error(f"Tool directory not found: {tool_dir}")
        return None
    
    main_file = tool_dir / "main.py"
    schemas_file = tool_dir / "schemas.py"
    
    if not main_file.exists() or not schemas_file.exists():
        return None
    
    try:
        # Import standardized schemas first
        standardized_schemas_path = Path(__file__).parent / "standardized_schemas.py"
        spec = importlib.util.spec_from_file_location("standardized_schemas", standardized_schemas_path)
        standardized_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(standardized_module)
        
        import sys
        sys.modules['standardized_schemas'] = standardized_module
        
        # Add tool directory to sys.path temporarily for imports
        sys.path.insert(0, str(tool_dir))
        
        try:
            # Load schemas
            schemas_spec = importlib.util.spec_from_file_location(f"{tool_name}.schemas", schemas_file)
            schemas_module = importlib.util.module_from_spec(schemas_spec)
            
            # Make schemas available for main.py imports
            sys.modules['schemas'] = schemas_module
            schemas_spec.loader.exec_module(schemas_module)
            
            # Load main
            main_spec = importlib.util.spec_from_file_location(f"{tool_name}.main", main_file)
            main_module = importlib.util.module_from_spec(main_spec)
            
            # Attach schemas to main module
            main_module.schemas = schemas_module
            main_spec.loader.exec_module(main_module)
            
        finally:
            # Clean up sys.path and sys.modules
            if str(tool_dir) in sys.path:
                sys.path.remove(str(tool_dir))
            if 'schemas' in sys.modules:
                del sys.modules['schemas']
            if 'standardized_schemas' in sys.modules:
                del sys.modules['standardized_schemas']
        
        return main_module
        
    except Exception as e:
        logger.error(f"Failed to load tool module {tool_name}: {e}")
        return None


def _find_input_schema(schemas_module, tool_name: str):
    """Find the input schema class in a schemas module."""
    if not schemas_module:
        return None
    
    from pydantic import BaseModel
    
    for attr_name in dir(schemas_module):
        try:
            attr = getattr(schemas_module, attr_name)
            if (isinstance(attr, type) and 
                issubclass(attr, BaseModel) and 
                attr is not BaseModel):
                attr_name_lower = attr.__name__.lower()
                if 'input' in attr_name_lower or 'request' in attr_name_lower:
                    if attr.__name__ not in ('BaseToolInput',):
                        return attr
        except (TypeError, AttributeError):
            continue
    
    return None
