"""
Pydantic models for Open Security Responder

Type-safe representations of playbooks, triggers, and execution state.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, validator


class TriggerType(str, Enum):
    """Supported trigger types"""
    API = "api"
    WEBHOOK = "webhook"
    SCHEDULE = "schedule"


class PlaybookTrigger(BaseModel):
    """Represents the trigger configuration for a playbook"""
    
    type: TriggerType = Field(..., description="Type of trigger")
    config: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Trigger-specific configuration"
    )
    
    class Config:
        use_enum_values = True


class StepFailurePolicy(str, Enum):
    """What to do when a step fails"""
    STOP = "stop"
    CONTINUE = "continue"


class PlaybookStep(BaseModel):
    """Represents a single step in a playbook execution"""

    # Unknown keys are rejected, not ignored.
    #
    # pydantic's default is to drop them silently, and that is how
    # playbooks/all_star_e2e.yml came to write every step's arguments under
    # `params:` while the engine reads `input`. The playbook looked configured,
    # loaded without a murmur, and passed nothing: every step ran with an empty
    # input and died on "missing 2 required positional arguments". A key that
    # does nothing must be a loading error, and the parser already turns one
    # into a startup failure the operator can see.
    #
    # It follows that every field below has to be honoured somewhere. That is
    # why retry_count is gone: it was declared here and read by nothing, so a
    # playbook asking for retries never got them.
    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = Field(
        default=None,
        description="Stable identifier for this step, for humans and logs"
    )
    name: str = Field(..., description="Unique name for this step")
    description: Optional[str] = Field(
        default=None,
        description="What this step does and why"
    )
    action: str = Field(..., description="Action in format 'connector.method'")
    input: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Input parameters for the action"
    )
    condition: Optional[str] = Field(
        default=None,
        description="Jinja2 condition to evaluate before executing step"
    )
    on_failure: StepFailurePolicy = Field(
        default=StepFailurePolicy.STOP,
        description="Whether a failure of this step ends the run or is recorded and skipped"
    )
    timeout: Optional[int] = Field(
        default=300,
        description="Timeout in seconds for step execution"
    )
    
    @validator('action')
    def validate_action_format(cls, v):
        """Ensure action follows 'connector.method' format"""
        if '.' not in v:
            raise ValueError("Action must be in format 'connector.method'")
        parts = v.split('.')
        if len(parts) != 2:
            raise ValueError("Action must have exactly one dot separator")
        return v


class Playbook(BaseModel):
    """Main playbook model representing a complete automation workflow"""

    # Same reasoning as PlaybookStep: a top-level key the engine does not read
    # must fail to load rather than be dropped. playbooks/all_star_e2e.yml
    # carried an `output:` block mapping step results into a result document;
    # nothing in the engine has ever rendered it, so the playbook promised an
    # output shape it did not produce. It is tracked separately.
    model_config = ConfigDict(extra="forbid")
    
    playbook_id: str = Field(..., description="Unique identifier for the playbook")
    name: str = Field(..., description="Human-readable name")
    description: Optional[str] = Field(
        default=None,
        description="Detailed description of the playbook purpose"
    )
    version: Optional[str] = Field(default="1.0", description="Playbook version")
    author: Optional[str] = Field(default=None, description="Playbook author")
    tags: Optional[List[str]] = Field(
        default_factory=list,
        description="Tags for categorization"
    )
    trigger: PlaybookTrigger = Field(..., description="Trigger configuration")
    steps: List[PlaybookStep] = Field(..., description="List of execution steps")
    
    @validator('playbook_id')
    def validate_playbook_id(cls, v):
        """Ensure playbook_id is valid identifier"""
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError("playbook_id must contain only alphanumeric, underscore, and hyphen characters")
        return v
    
    @validator('steps')
    def validate_steps_not_empty(cls, v):
        """Ensure at least one step is defined"""
        if not v:
            raise ValueError("Playbook must have at least one step")
        return v
    
    @validator('steps')
    def validate_step_names_unique(cls, v):
        """Ensure step names are unique within the playbook"""
        names = [step.name for step in v]
        if len(names) != len(set(names)):
            raise ValueError("Step names must be unique within a playbook")
        return v


class ExecutionStatus(str, Enum):
    """Possible execution states"""
    QUEUED = "queued"      # Added for state persistence fix
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


def step_context_key(step: PlaybookStep) -> str:
    """The key a step's result is filed under in the execution context.

    It is the id when the step has one, and the name otherwise. This is what a
    later step writes in `{{ steps.<key>.output }}` or in a condition.

    A named function rather than the expression inline, because the two are not
    interchangeable and the difference is invisible when it is wrong: keying by
    `name` made every cross-step reference in a playbook that uses ids resolve
    to nothing -- a false condition, an empty template -- with no error
    anywhere. Named, it can be tested.
    """
    return step.id or step.name


class StepExecutionResult(BaseModel):
    """Result of a single step execution"""
    
    step_name: str
    status: ExecutionStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_seconds: Optional[float] = None
    
    class Config:
        use_enum_values = True


class PlaybookExecutionResult(BaseModel):
    """Complete result of a playbook execution"""
    
    run_id: str
    playbook_id: str
    playbook_name: str
    status: ExecutionStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    trigger_data: Dict[str, Any]
    step_results: List[StepExecutionResult] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    logs: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: Optional[float] = None
    
    class Config:
        use_enum_values = True


class PlaybookExecutionRequest(BaseModel):
    """Request model for playbook execution"""
    
    trigger_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Data provided by the trigger"
    )
    context: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Additional context for the execution"
    )


class PlaybookListResponse(BaseModel):
    """Response model for listing playbooks"""
    
    playbooks: List[Dict[str, Any]] = Field(
        description="List of available playbooks with basic info"
    )
    total: int = Field(description="Total number of playbooks")


class HealthCheckResponse(BaseModel):
    """Health check response model"""

    status: str
    timestamp: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
