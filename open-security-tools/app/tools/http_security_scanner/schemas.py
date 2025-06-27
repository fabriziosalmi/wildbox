"""Pydantic schemas for the HTTP Security Headers Scanner."""

from pydantic import BaseModel, Field, HttpUrl
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import Dict, Any, List, Optional
from datetime import datetime


class HttpSecurityScannerInput(BaseToolInput):
    """Input schema for the HTTP Security Headers Scanner."""
    
    url: str = Field(
        ...,
        description="Target URL to scan for security headers",
        example="https://example.com"
    )
    follow_redirects: bool = Field(
        default=True,
        description="Whether to follow HTTP redirects"
    )
    timeout: int = Field(
        default=10,
        description="Request timeout in seconds",
        ge=1,
        le=60
    )
    check_subpaths: bool = Field(
        default=False,
        description="Check common subpaths like /admin, /api, etc."
    )


class SecurityHeader(BaseModel):
    """Information about a security header."""
    
    name: str = Field(..., description="Header name")
    value: Optional[str] = Field(None, description="Header value if present")
    present: bool = Field(..., description="Whether the header is present")
    severity: str = Field(..., description="Severity level: low, medium, high, critical")
    description: str = Field(..., description="Description of what this header does")
    recommendation: Optional[str] = Field(None, description="Recommendation if header is missing")


class HttpSecurityScannerOutput(BaseToolOutput):
    """Output schema for the HTTP Security Headers Scanner."""
    
    url: str = Field(..., description="URL that was scanned")
    timestamp: datetime = Field(..., description="When the scan was performed")
    duration: float = Field(..., description="Scan duration in seconds")
    status: str = Field(..., description="Scan status (success/failed/partial)")
    http_status: Optional[int] = Field(None, description="HTTP response status code")
    security_headers: List[SecurityHeader] = Field(default=[], description="Security headers analysis")
    missing_headers: List[str] = Field(default=[], description="List of missing critical headers")
    vulnerabilities: List[str] = Field(default=[], description="Potential security vulnerabilities")
    recommendations: List[str] = Field(default=[], description="Security recommendations")
    security_score: int = Field(..., description="Security score out of 100")
    findings: Dict[str, Any] = Field(..., description="Detailed scan findings")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
