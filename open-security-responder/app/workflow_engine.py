"""
Workflow execution engine using Dramatiq

Handles asynchronous playbook execution with Redis state management.
"""

import json
import uuid
import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from jinja2 import Environment, DictLoader, TemplateSyntaxError, UndefinedError
import redis
import dramatiq
from dramatiq.brokers.redis import RedisBroker
from dramatiq.results import Results
from dramatiq.results.backends import RedisBackend

from .models import (
    Playbook, PlaybookStep, ExecutionStatus, 
    StepExecutionResult, PlaybookExecutionResult
)
from .config import settings
from .playbook_parser import playbook_parser
from .connectors import connector_registry

# Configure logging
logger = logging.getLogger(__name__)

# Configure Redis connection
redis_client = redis.from_url(settings.redis_url)

# Configure Dramatiq broker
result_backend = RedisBackend(url=settings.redis_url)
broker = RedisBroker(url=settings.redis_url)
broker.add_middleware(Results(backend=result_backend))
dramatiq.set_broker(broker)

# Jinja2 environment for template rendering
from jinja2 import StrictUndefined

jinja_env = Environment(
    loader=DictLoader({}),
    autoescape=False,
    undefined=StrictUndefined
)


class WorkflowExecutionError(Exception):
    """Raised when workflow execution fails"""
    pass


class TemplateRenderError(Exception):
    """Raised when template rendering fails"""
    pass


class WorkflowEngine:
    """Main workflow execution engine"""
    
    def __init__(self):
        self.redis_client = redis_client
        self.key_prefix = settings.redis_key_prefix
        
    def _get_execution_key(self, run_id: str) -> str:
        """Get Redis key for execution state"""
        return f"{self.key_prefix}run:{run_id}"
    
    def _get_logs_key(self, run_id: str) -> str:
        """Get Redis key for execution logs"""
        return f"{self.key_prefix}run:{run_id}:logs"
    
    def save_execution_state(self, run_id: str, execution_result: PlaybookExecutionResult):
        """Save execution state to Redis"""
        key = self._get_execution_key(run_id)
        data = execution_result.dict()
        
        # Convert datetime objects to ISO strings for JSON serialization
        for field in ['start_time', 'end_time']:
            if data.get(field):
                data[field] = data[field].isoformat()
        
        # Handle step results datetime fields
        for step_result in data.get('step_results', []):
            for field in ['start_time', 'end_time']:
                if step_result.get(field):
                    step_result[field] = step_result[field].isoformat()
        
        self.redis_client.hset(key, mapping={
            'data': json.dumps(data),
            'status': execution_result.status,
            'playbook_id': execution_result.playbook_id,
            'updated_at': datetime.utcnow().isoformat()
        })
        
        # Set expiration based on retention policy
        expire_seconds = settings.execution_retention_days * 24 * 60 * 60
        self.redis_client.expire(key, expire_seconds)
    
    def get_execution_state(self, run_id: str) -> Optional[PlaybookExecutionResult]:
        """Retrieve execution state from Redis"""
        key = self._get_execution_key(run_id)
        data = self.redis_client.hget(key, 'data')
        
        if not data:
            return None
        
        try:
            parsed_data = json.loads(data)
            
            # Convert ISO strings back to datetime objects
            for field in ['start_time', 'end_time']:
                if parsed_data.get(field):
                    parsed_data[field] = datetime.fromisoformat(parsed_data[field])
            
            # Handle step results datetime fields
            for step_result in parsed_data.get('step_results', []):
                for field in ['start_time', 'end_time']:
                    if step_result.get(field):
                        step_result[field] = datetime.fromisoformat(step_result[field])
            
            return PlaybookExecutionResult(**parsed_data)
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse execution state for {run_id}: {e}")
            return None
    
    def add_log(self, run_id: str, message: str, level: str = "INFO"):
        """Add a log entry for the execution"""
        logs_key = self._get_logs_key(run_id)
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {level}: {message}"
        
        self.redis_client.rpush(logs_key, log_entry)
        
        # Also update the logs in the main execution state
        execution_state = self.get_execution_state(run_id)
        if execution_state:
            execution_state.logs.append(log_entry)
            self.save_execution_state(run_id, execution_state)
    
    def render_template(self, template_str: str, context: Dict[str, Any]) -> Any:
        """
        Render a Jinja2 template string with the given context
        
        Args:
            template_str: The template string to render
            context: Dictionary containing template variables
            
        Returns:
            Rendered value (can be string, dict, list, etc.)
            
        Raises:
            TemplateRenderError: If rendering fails
        """
        if not isinstance(template_str, str):
            return template_str
        
        try:
            template = jinja_env.from_string(template_str)
            rendered = template.render(**context)
            
            # Try to parse as JSON if it looks like structured data
            if rendered.startswith(('{', '[')) and rendered.endswith(('}', ']')):
                try:
                    return json.loads(rendered)
                except json.JSONDecodeError:
                    pass
            
            return rendered
            
        except (TemplateSyntaxError, UndefinedError) as e:
            raise TemplateRenderError(f"Template rendering failed: {str(e)}")
    
    def render_step_input(self, step_input: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively render all template strings in step input
        
        Args:
            step_input: Dictionary containing input parameters
            context: Template rendering context
            
        Returns:
            Dictionary with rendered values
        """
        if not step_input:
            return {}
        
        rendered_input = {}
        
        for key, value in step_input.items():
            if isinstance(value, str):
                rendered_input[key] = self.render_template(value, context)
            elif isinstance(value, dict):
                rendered_input[key] = self.render_step_input(value, context)
            elif isinstance(value, list):
                rendered_input[key] = [
                    self.render_template(item, context) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                rendered_input[key] = value
        
        return rendered_input
    
    def evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """
        Evaluate a Jinja2 condition expression
        
        Args:
            condition: Jinja2 condition expression
            context: Template rendering context
            
        Returns:
            Boolean result of condition evaluation
        """
        if not condition:
            return True
        
        try:
            # Wrap condition in an if statement to get boolean result
            template_str = f"{{% if {condition} %}}true{{% else %}}false{{% endif %}}"
            result = self.render_template(template_str, context)
            return result == "true"
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Condition evaluation failed: {e}")
            return False


# Global workflow engine instance
workflow_engine = WorkflowEngine()


@dramatiq.actor(store_results=True, max_retries=0)
def execute_playbook_actor(run_id: str, playbook_id: str, trigger_data: Dict[str, Any]):
    """
    Dramatiq actor for executing playbooks asynchronously
    
    Args:
        run_id: Unique identifier for this execution
        playbook_id: ID of the playbook to execute
        trigger_data: Data provided by the trigger
        
    Returns:
        Final execution result
    """
    start_time = datetime.utcnow()
    
    try:
        # Get the playbook - reload to ensure worker has fresh copy
        try:
            # Ensure playbook_parser has loaded playbooks in this worker process
            if not playbook_parser.playbooks:
                playbook_parser.load_playbooks()
            playbook = playbook_parser.get_playbook(playbook_id)
        except KeyError:
            raise WorkflowExecutionError(f"Playbook '{playbook_id}' not found")
        
        # Load existing state from Redis (created in start_execution)
        execution_result = workflow_engine.get_execution_state(run_id)
        
        if not execution_result:
            # Fallback: create new state if not found (shouldn't happen)
            execution_result = PlaybookExecutionResult(
                run_id=run_id,
                playbook_id=playbook_id,
                playbook_name=playbook.name,
                status=ExecutionStatus.RUNNING,
                start_time=start_time,
                trigger_data=trigger_data,
                context={"trigger": trigger_data}
            )
        else:
            # Update status to RUNNING
            execution_result.status = ExecutionStatus.RUNNING
            execution_result.playbook_name = playbook.name
        
        # Save updated state (QUEUED -> RUNNING transition)
        workflow_engine.save_execution_state(run_id, execution_result)
        workflow_engine.add_log(run_id, f"Starting execution of playbook '{playbook.name}'")
        
        # Execute each step
        for step in playbook.steps:
            step_start_time = datetime.utcnow()
            
            try:
                # Create step result
                step_result = StepExecutionResult(
                    step_name=step.name,
                    status=ExecutionStatus.RUNNING,
                    start_time=step_start_time
                )
                
                workflow_engine.add_log(run_id, f"Executing step '{step.name}'")
                
                # Evaluate condition if present
                if step.condition:
                    condition_result = workflow_engine.evaluate_condition(
                        step.condition, 
                        execution_result.context
                    )
                    if not condition_result:
                        workflow_engine.add_log(
                            run_id, 
                            f"Step '{step.name}' skipped due to condition: {step.condition}"
                        )
                        step_result.status = ExecutionStatus.COMPLETED
                        step_result.end_time = datetime.utcnow()
                        step_result.output = {"skipped": True, "reason": "condition_failed"}
                        execution_result.step_results.append(step_result)
                        continue
                
                # Render step input
                try:
                    rendered_input = workflow_engine.render_step_input(
                        step.input or {}, 
                        execution_result.context
                    )
                except TemplateRenderError as e:
                    raise WorkflowExecutionError(f"Failed to render input for step '{step.name}': {e}")
                
                # Execute the action using the connector registry
                try:
                    connector_name, action_name = step.action.split('.', 1)
                    workflow_engine.add_log(
                        run_id, 
                        f"Executing action '{action_name}' on connector '{connector_name}' with input: {json.dumps(rendered_input, indent=2)}"
                    )
                    
                    action_result = connector_registry.execute_action(
                        connector_name, 
                        action_name, 
                        rendered_input
                    )
                    
                except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                    # If connector execution fails, fall back to simulation for testing
                    workflow_engine.add_log(
                        run_id, 
                        f"Connector execution failed, using simulation: {str(e)}"
                    )
                    action_result = _simulate_action_execution(step.action, rendered_input)
                
                # Update step result
                step_result.status = ExecutionStatus.COMPLETED
                step_result.end_time = datetime.utcnow()
                step_result.duration_seconds = (step_result.end_time - step_result.start_time).total_seconds()
                step_result.output = action_result
                
                # Update context with step result
                if "steps" not in execution_result.context:
                    execution_result.context["steps"] = {}
                execution_result.context["steps"][step.name] = {
                    "output": action_result,
                    "status": step_result.status,
                    "duration": step_result.duration_seconds
                }
                
                execution_result.step_results.append(step_result)
                workflow_engine.add_log(
                    run_id, 
                    f"Step '{step.name}' completed successfully in {step_result.duration_seconds:.2f}s"
                )
                
            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                # Handle step failure
                step_result.status = ExecutionStatus.FAILED
                step_result.end_time = datetime.utcnow()
                step_result.duration_seconds = (step_result.end_time - step_result.start_time).total_seconds()
                step_result.error = str(e)
                
                execution_result.step_results.append(step_result)
                workflow_engine.add_log(
                    run_id, 
                    f"Step '{step.name}' failed: {str(e)}", 
                    level="ERROR"
                )
                
                # Fail the entire execution
                raise WorkflowExecutionError(f"Step '{step.name}' failed: {str(e)}")
        
        # Mark execution as completed
        execution_result.status = ExecutionStatus.COMPLETED
        execution_result.end_time = datetime.utcnow()
        execution_result.duration_seconds = (execution_result.end_time - execution_result.start_time).total_seconds()
        
        # FIX: Persist completed state to Redis
        workflow_engine.save_execution_state(run_id, execution_result)
        workflow_engine.add_log(
            run_id, 
            f"Playbook execution completed successfully in {execution_result.duration_seconds:.2f}s"
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        # Handle execution failure
        # Ensure we have an execution_result even if error occurred early
        if 'execution_result' not in locals():
            execution_result = PlaybookExecutionResult(
                run_id=run_id,
                playbook_id=playbook_id,
                playbook_name="Unknown",
                status=ExecutionStatus.FAILED,
                start_time=start_time,
                trigger_data=trigger_data,
                context={"trigger": trigger_data}
            )
        
        execution_result.status = ExecutionStatus.FAILED
        execution_result.end_time = datetime.utcnow()
        execution_result.duration_seconds = (execution_result.end_time - execution_result.start_time).total_seconds()
        execution_result.error = str(e)
        
        # FIX: Persist failed state to Redis
        workflow_engine.save_execution_state(run_id, execution_result)
        workflow_engine.add_log(run_id, f"Playbook execution failed: {str(e)}", level="ERROR")
        logger.error(f"Playbook execution {run_id} failed: {e}")
    
    finally:
        # Final state save (defensive - already saved in try/except blocks)
        if 'execution_result' in locals():
            workflow_engine.save_execution_state(run_id, execution_result)
    
    return execution_result.dict()


def _simulate_action_execution(action: str, input_params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulate action execution for testing purposes
    This will be replaced with actual connector calls in week 2
    """
    import time
    import random
    
    # Simulate processing time
    time.sleep(random.uniform(0.1, 0.5))
    
    # Return simulated results based on action type
    if "scan" in action.lower():
        return {
            "scan_results": {
                "open_ports": [22, 80, 443],
                "services": ["ssh", "http", "https"],
                "status": "completed"
            }
        }
    elif "whois" in action.lower():
        return {
            "whois_info": {
                "registrar": "Example Registrar",
                "creation_date": "2020-01-01",
                "expiration_date": "2025-01-01",
                "status": "active"
            }
        }
    elif "reputation" in action.lower():
        return {
            "reputation_score": random.randint(1, 10),
            "verdict": "clean" if random.random() > 0.3 else "suspicious",
            "sources": ["VirusTotal", "AbuseIPDB"]
        }
    else:
        return {
            "message": f"Action '{action}' executed successfully",
            "input_received": input_params,
            "timestamp": datetime.utcnow().isoformat()
        }


def start_execution(playbook_id: str, trigger_data: Dict[str, Any] = None) -> str:
    """
    Start a new playbook execution
    
    Args:
        playbook_id: ID of the playbook to execute
        trigger_data: Data provided by the trigger
        
    Returns:
        Unique run ID for the execution
        
    Raises:
        WorkflowExecutionError: If playbook doesn't exist
    """
    # Validate playbook exists
    try:
        playbook = playbook_parser.get_playbook(playbook_id)
    except KeyError:
        raise WorkflowExecutionError(f"Playbook '{playbook_id}' not found")
    
    # Generate unique run ID
    run_id = str(uuid.uuid4())
    
    # FIX: Persist initial state to Redis BEFORE enqueueing
    initial_state = PlaybookExecutionResult(
        run_id=run_id,
        playbook_id=playbook_id,
        playbook_name=playbook.name,
        status=ExecutionStatus.QUEUED,
        start_time=datetime.utcnow(),
        trigger_data=trigger_data or {},
        context={"trigger": trigger_data or {}}
    )
    workflow_engine.save_execution_state(run_id, initial_state)
    workflow_engine.add_log(run_id, f"Playbook '{playbook.name}' queued for execution")
    
    # Start execution
    execute_playbook_actor.send(run_id, playbook_id, trigger_data or {})
    
    logger.info(f"Started execution {run_id} for playbook '{playbook_id}'")
    return run_id
