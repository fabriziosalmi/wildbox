"""
Pydantic models for Open Security Agents API

Defines the data structures for IOC analysis requests and responses.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


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


class IOCInput(BaseModel):
    """Input IOC for analysis"""
    type: IOCType = Field(..., description="Type of IOC")
    value: str = Field(..., description="IOC value to analyze")
    
    class Config:
        schema_extra = {
            "example": {
                "type": "ipv4",
                "value": "192.168.1.100"
            }
        }


class AnalysisTaskRequest(BaseModel):
    """Request to analyze an IOC"""
    ioc: IOCInput = Field(..., description="IOC to analyze")
    priority: str = Field(default="normal", description="Task priority (low, normal, high)")
    
    class Config:
        schema_extra = {
            "example": {
                "ioc": {
                    "type": "domain",
                    "value": "suspicious-domain.com"
                },
                "priority": "high"
            }
        }


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
    result_url: Optional[str] = Field(None, description="URL to fetch results when completed")
    
    class Config:
        schema_extra = {
            "example": {
                "task_id": "abc-123-def",
                "status": "running",
                "created_at": "2025-06-25T10:00:00Z",
                "started_at": "2025-06-25T10:00:05Z",
                "progress": "Performing WHOIS lookup...",
                "result_url": "/v1/analyze/abc-123-def"
            }
        }


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
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw tool outputs")
    analysis_duration: Optional[float] = Field(None, description="Analysis duration in seconds")
    tools_used: List[str] = Field(default_factory=list, description="List of tools used")
    
    class Config:
        schema_extra = {
            "example": {
                "task_id": "abc-123-def",
                "ioc": {"type": "ipv4", "value": "192.168.1.100"},
                "verdict": "Suspicious",
                "confidence": 0.75,
                "executive_summary": "IP shows signs of malicious activity with open ports and suspicious services.",
                "evidence": [
                    {
                        "source": "port_scanner",
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
                "tools_used": ["port_scanner", "whois_lookup", "reputation_check"]
            }
        }


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
