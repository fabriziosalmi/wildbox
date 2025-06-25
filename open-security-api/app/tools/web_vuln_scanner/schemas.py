"""Web vulnerability scanner tool schemas."""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum


class ScanDepth(str, Enum):
    """Scan depth options."""
    SURFACE = "surface"
    STANDARD = "standard"
    DEEP = "deep"


class VulnerabilityLevel(str, Enum):
    """Vulnerability severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WebVulnScannerInput(BaseToolInput):
    """Input schema for the web vulnerability scanner."""
    
    target_url: str = Field(
        ...,
        description="Target website URL to scan",
        example="https://example.com"
    )
    scan_depth: ScanDepth = Field(
        default=ScanDepth.STANDARD,
        description="Depth of the vulnerability scan"
    )
    check_ssl: bool = Field(
        default=True,
        description="Include SSL/TLS security checks"
    )
    check_headers: bool = Field(
        default=True,
        description="Analyze HTTP security headers"
    )
    check_forms: bool = Field(
        default=True,
        description="Scan for form-based vulnerabilities"
    )
    max_pages: int = Field(
        default=50,
        description="Maximum number of pages to crawl",
        ge=1,
        le=500
    )
    timeout: int = Field(
        default=60,
        description="Timeout in seconds for the scan",
        ge=10,
        le=600
    )


class VulnerabilityFinding(BaseModel):
    """Details of a vulnerability finding."""
    
    id: str = Field(..., description="Vulnerability ID")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description")
    severity: VulnerabilityLevel = Field(..., description="Severity level")
    url: str = Field(..., description="URL where vulnerability was found")
    evidence: Optional[str] = Field(None, description="Evidence or proof of concept")
    remediation: str = Field(..., description="How to fix the vulnerability")


class SecurityHeader(BaseModel):
    """Security header analysis."""
    
    header: str = Field(..., description="Header name")
    present: bool = Field(..., description="Whether header is present")
    value: Optional[str] = Field(None, description="Header value if present")
    recommendation: str = Field(..., description="Security recommendation")


class WebVulnScannerOutput(BaseToolOutput):
    """Output schema for the web vulnerability scanner."""
    
    target_url: str = Field(..., description="Target URL that was scanned")
    scan_depth: str = Field(..., description="Scan depth used")
    timestamp: datetime = Field(..., description="When the scan was performed")
    duration: float = Field(..., description="Scan duration in seconds")
    status: str = Field(..., description="Scan status")
    pages_scanned: int = Field(..., description="Number of pages scanned")
    vulnerabilities: List[VulnerabilityFinding] = Field(default=[], description="Vulnerabilities found")
    security_headers: List[SecurityHeader] = Field(default=[], description="Security headers analysis")
    ssl_info: Dict[str, Any] = Field(default={}, description="SSL/TLS certificate information")
    summary: Dict[str, int] = Field(default={}, description="Vulnerability count by severity")
    recommendations: List[str] = Field(default=[], description="Overall security recommendations")
