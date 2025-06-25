from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Dict, Any, Optional
from datetime import datetime

class ThreatHuntingInput(BaseToolInput):
    hunt_type: str = Field(..., description="Type of threat hunt (ioc_search, behavioral_analysis, timeline_analysis, lateral_movement)")
    target_data: str = Field(..., description="Target data source or indicators")
    time_range: Optional[str] = Field("24h", description="Time range for the hunt (1h, 24h, 7d, 30d)")
    indicators: Optional[List[str]] = Field([], description="Known indicators to search for")
    hunt_parameters: Optional[Dict[str, Any]] = Field({}, description="Additional hunt parameters")

class ThreatIndicator(BaseModel):
    indicator: str
    type: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    source: str
    description: str

class ThreatEvent(BaseModel):
    timestamp: datetime
    event_type: str
    severity: str
    source: str
    target: str
    description: str
    indicators: List[str]
    mitre_tactics: List[str]

class HuntResults(BaseModel):
    total_events: int
    suspicious_events: int
    high_confidence_indicators: List[ThreatIndicator]
    event_timeline: List[ThreatEvent]
    recommended_actions: List[str]

class ThreatHuntingOutput(BaseToolOutput):
    success: bool
    hunt_id: str
    hunt_type: str
    execution_time: str
    results: HuntResults
    summary: str
    recommendations: List[str]
