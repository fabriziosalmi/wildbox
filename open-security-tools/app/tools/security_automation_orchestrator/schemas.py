from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Dict, Any, Literal, Optional
from datetime import datetime

class AutomationWorkflowInput(BaseToolInput):
    workflow_name: str = Field(..., description="Name of the automation workflow")
    trigger_type: Literal["event", "schedule", "manual", "api"] = Field(..., description="Trigger type (event, schedule, manual, api)")
    workflow_steps: List[Dict[str, Any]] = Field(..., description="List of workflow steps with tool and parameters")
    # The modes main.py runs; any other value ran the conditional mode (#611).
    execution_mode: Literal["sequential", "parallel", "conditional"] = Field("sequential", description="Execution mode (sequential, parallel, conditional)")
    timeout_minutes: Optional[int] = Field(30, description="Workflow timeout in minutes")
    retry_policy: Optional[Dict[str, Any]] = Field({}, description="Retry policy configuration")

class WorkflowStep(BaseModel):
    step_id: str
    step_name: str
    tool_name: str
    parameters: Dict[str, Any]
    execution_order: int
    dependencies: List[str]
    timeout_minutes: int
    retry_count: int
    status: str
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    output: Optional[Dict[str, Any]]
    error_message: Optional[str]

class WorkflowExecution(BaseModel):
    execution_id: str
    workflow_name: str
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    total_steps: int
    completed_steps: int
    failed_steps: int
    execution_logs: List[str]
    step_results: List[WorkflowStep]

class AutomationMetrics(BaseModel):
    total_executions: int
    successful_executions: int
    failed_executions: int
    average_execution_time: str
    most_used_tools: List[str]
    error_patterns: List[str]

class SecurityAutomationOutput(BaseToolOutput):
    success: bool
    execution_id: str
    workflow_execution: WorkflowExecution
    automation_metrics: AutomationMetrics
    recommendations: List[str]
    next_scheduled_run: Optional[str]
