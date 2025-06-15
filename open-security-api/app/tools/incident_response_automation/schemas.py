from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class IncidentResponseInput(BaseModel):
    incident_type: str = Field(..., description="Type of incident (malware, data_breach, ddos, insider_threat, phishing)")
    severity: str = Field(..., description="Incident severity (low, medium, high, critical)")
    affected_assets: List[str] = Field(..., description="List of affected systems/assets")
    incident_description: str = Field(..., description="Detailed description of the incident")
    initial_indicators: Optional[List[str]] = Field([], description="Initial indicators of compromise")
    response_mode: str = Field("automatic", description="Response mode (automatic, guided, manual)")

class ResponseAction(BaseModel):
    action_id: str
    action_type: str
    description: str
    priority: int
    estimated_time: str
    dependencies: List[str]
    automated: bool
    status: str

class Playbook(BaseModel):
    playbook_name: str
    incident_type: str
    actions: List[ResponseAction]
    estimated_duration: str
    success_criteria: List[str]

class ContainmentMeasure(BaseModel):
    measure_type: str
    target: str
    action: str
    impact_level: str
    reversible: bool
    implemented: bool

class IncidentTimeline(BaseModel):
    timestamp: datetime
    event: str
    actor: str
    action: str
    outcome: str

class IncidentResponseOutput(BaseModel):
    success: bool
    incident_id: str
    response_status: str
    playbook_executed: Playbook
    containment_measures: List[ContainmentMeasure]
    timeline: List[IncidentTimeline]
    artifacts_collected: List[str]
    next_steps: List[str]
    lessons_learned: List[str]
    completion_time: str
