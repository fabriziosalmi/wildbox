"""
Pydantic models for Open Security Agents API

Defines the data structures for IOC analysis requests and responses.

The examples are declared the pydantic v2 way, ``model_config`` with
``json_schema_extra``. They were ``class Config: schema_extra``, the v1 key,
which v2 ignores with a warning: no example reached the OpenAPI schema
(#727). tests/unit/test_schema_examples.py keeps each example valid for its
own model, so that what the schema shows is something the API can answer.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator
import re


class IOCType(str, Enum):
    """Supported IOC types"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"

# Regex patterns for IOC validation
IOC_REGEX_PATTERNS = {
    IOCType.IPV4: r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
    IOCType.IPV6: r"^[0-9a-fA-F:]{2,40}$", # Simplified, more complex regex exists
    IOCType.DOMAIN: r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$",
    IOCType.URL: r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
    IOCType.MD5: r"^[a-f0-9]{32}$",
    IOCType.SHA1: r"^[a-f0-9]{40}$",
    IOCType.SHA256: r"^[a-f0-9]{64}$",
    IOCType.EMAIL: r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
}


class IOCInput(BaseModel):
    """Input IOC for analysis"""
    type: IOCType = Field(..., description="Type of IOC")
    value: str = Field(..., description="IOC value to analyze")
    
    @field_validator('value')
    @classmethod
    def validate_ioc_value(cls, v: str, info: ValidationInfo) -> str:
        # ``type`` is declared first, so it is validated first: it is in
        # ``info.data`` unless it was itself invalid, and then the request
        # is refused for that.
        ioc_type = info.data.get('type')
        if ioc_type and ioc_type in IOC_REGEX_PATTERNS:
            pattern = IOC_REGEX_PATTERNS[ioc_type]
            if not re.match(pattern, v):
                raise ValueError(f"Invalid format for {ioc_type.value} IOC: '{v}'")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "ipv4",
                "value": "203.0.113.10"
            }
        }
    )


class TaskPriority(str, Enum):
    """Task priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class AnalysisTaskRequest(BaseModel):
    """Request to analyze an IOC"""
    ioc: IOCInput = Field(..., description="IOC to analyze")
    priority: TaskPriority = Field(default=TaskPriority.NORMAL, description="Task priority")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ioc": {
                    "type": "domain",
                    "value": "suspicious.example.com"
                },
                "priority": "high"
            }
        }
    )


class TaskStatus(str, Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REVOKED = "revoked"


class AnalysisTaskStatus(BaseModel):
    """Status of an analysis task"""
    task_id: str = Field(..., description="Unique task identifier")
    status: TaskStatus = Field(..., description="Current task status")
    created_at: datetime = Field(..., description="Task creation timestamp")
    started_at: Optional[datetime] = Field(None, description="Task start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Task completion timestamp")
    progress: Optional[str] = Field(None, description="Current progress description")
    error: Optional[str] = Field(None, description="Error message if failed")
    result_url: Optional[str] = Field(
        None,
        description=(
            "Where to read the task: its path on the gateway, "
            "/api/v1/agents/analyze/{task_id}, to resolve against the address "
            "the client called"
        ),
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "running",
                "created_at": "2026-10-03T10:00:00Z",
                "started_at": "2026-10-03T10:00:05Z",
                "progress": "Running AI analysis...",
                "result_url": "/api/v1/agents/analyze/550e8400-e29b-41d4-a716-446655440000"
            }
        }
    )


class ThreatVerdict(str, Enum):
    """Threat assessment verdict"""
    MALICIOUS = "Malicious"
    SUSPICIOUS = "Suspicious" 
    BENIGN = "Benign"
    INFORMATIONAL = "Informational"


class AnalysisEvidence(BaseModel):
    """Piece of evidence from analysis"""
    source: str = Field(..., description="Source of evidence (tool name)")
    finding: str = Field(..., description="Description of finding")
    severity: str = Field(..., description="Severity level (low, medium, high, critical)")
    data: Optional[Dict[str, Any]] = Field(None, description="Raw data from tool")


class AnalysisResult(BaseModel):
    """Complete analysis result"""
    task_id: str = Field(..., description="Task identifier")
    ioc: IOCInput = Field(..., description="Original IOC analyzed")
    verdict: ThreatVerdict = Field(..., description="Overall threat assessment")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    executive_summary: str = Field(..., description="Brief summary of findings")
    evidence: List[AnalysisEvidence] = Field(default_factory=list, description="Supporting evidence")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended actions")
    full_report: str = Field(..., description="Complete analysis report in Markdown")
    analysis_duration: Optional[float] = Field(None, description="Analysis duration in seconds")
    tools_used: List[str] = Field(default_factory=list, description="List of tools used")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": "550e8400-e29b-41d4-a716-446655440000",
                "ioc": {"type": "ipv4", "value": "203.0.113.10"},
                "verdict": "Suspicious",
                "confidence": 0.75,
                "executive_summary": "IP shows signs of malicious activity with open ports and suspicious services.",
                "evidence": [
                    {
                        "source": "port_scan_tool",
                        "finding": "Multiple open ports detected including FTP and Telnet",
                        "severity": "medium"
                    }
                ],
                "recommended_actions": [
                    "Block IP in firewall",
                    "Monitor for similar IPs in same subnet"
                ],
                "full_report": "# Threat Analysis Report\n\n## Executive Summary\n...",
                "analysis_duration": 45.2,
                "tools_used": ["port_scan_tool", "whois_lookup_tool", "reputation_check_tool"]
            }
        }
    )


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(..., description="Response timestamp")
    version: str = Field(..., description="Service version")
    services: Dict[str, str] = Field(..., description="Dependent service status")


class StatsResponse(BaseModel):
    """Service statistics response"""
    total_analyses: int = Field(..., description="Total analyses performed")
    pending_tasks: int = Field(..., description="Currently pending tasks")
    running_tasks: int = Field(..., description="Currently running tasks")
    completed_today: int = Field(..., description="Analyses completed today")
    failed_today: int = Field(..., description="Analyses failed today")
    average_duration: Optional[float] = Field(None, description="Average analysis duration")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")
    model_configured: bool = Field(
        ...,
        description=(
            "Whether a model API key is set. Without one every analysis "
            "fails, with the reason \"not configured\""
        ),
    )
