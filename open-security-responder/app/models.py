"""
Pydantic models for Open Security Responder

Type-safe representations of playbooks, triggers, and execution state.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator


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


class PlaybookStep(BaseModel):
    """Represents a single step in a playbook execution"""
    
    name: str = Field(..., description="Unique name for this step")
    action: str = Field(..., description="Action in format 'connector.method'")
    input: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Input parameters for the action"
    )
    condition: Optional[str] = Field(
        default=None,
        description="Jinja2 condition to evaluate before executing step"
    )
    timeout: Optional[int] = Field(
        default=300,
        description="Timeout in seconds for step execution"
    )
    retry_count: Optional[int] = Field(
        default=0,
        description="Number of retries on failure"
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
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


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
    version: str
    redis_connected: bool
    playbooks_loaded: int
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
