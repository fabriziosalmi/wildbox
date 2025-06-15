"""Pydantic schemas for the sample tool."""

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime


class SampleToolInput(BaseModel):
    """Input schema for the sample security tool."""
    
    target: str = Field(
        ...,
        description="Target domain or IP address to scan",
        example="example.com"
    )
    scan_type: str = Field(
        default="basic",
        description="Type of scan to perform",
        example="basic"
    )
    timeout: int = Field(
        default=30,
        description="Timeout in seconds for the scan",
        ge=1,
        le=300
    )


class PortInfo(BaseModel):
    """Information about a discovered port."""
    
    port: int = Field(..., description="Port number")
    state: str = Field(..., description="Port state (open/closed/filtered)")
    service: Optional[str] = Field(None, description="Service running on the port")
    version: Optional[str] = Field(None, description="Service version if detected")


class SampleToolOutput(BaseModel):
    """Output schema for the sample security tool."""
    
    target: str = Field(..., description="Target that was scanned")
    scan_type: str = Field(..., description="Type of scan performed")
    timestamp: datetime = Field(..., description="When the scan was performed")
    duration: float = Field(..., description="Scan duration in seconds")
    status: str = Field(..., description="Scan status (success/failed/partial)")
    findings: Dict[str, Any] = Field(..., description="Detailed scan findings")
    open_ports: List[PortInfo] = Field(default=[], description="List of open ports found")
    vulnerabilities: List[str] = Field(default=[], description="Potential vulnerabilities detected")
    recommendations: List[str] = Field(default=[], description="Security recommendations")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
