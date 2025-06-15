"""
HTTP Header Security Analyzer Schemas

Pydantic models for HTTP header security analysis requests and responses.
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Dict, Any, Optional


class HeaderAnalyzerInput(BaseModel):
    """Input model for HTTP header security analysis."""
    
    url: HttpUrl = Field(
        ...,
        description="Target URL to analyze HTTP headers",
        example="https://example.com"
    )
    follow_redirects: bool = Field(
        default=True,
        description="Whether to follow HTTP redirects during analysis"
    )
    check_subdomains: bool = Field(
        default=False,
        description="Whether to check common subdomains for header consistency"
    )
    custom_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Custom headers to include in the request",
        example={"User-Agent": "Custom-Scanner/1.0"}
    )


class SecurityHeaderInfo(BaseModel):
    """Information about a specific security header."""
    
    name: str = Field(..., description="Header name")
    value: Optional[str] = Field(None, description="Header value")
    present: bool = Field(..., description="Whether the header is present")
    recommendation: Optional[str] = Field(None, description="Security recommendation")
    severity: str = Field(..., description="Severity level: low, medium, high, critical")
    description: str = Field(..., description="Description of the header's security purpose")


class HeaderAnalysis(BaseModel):
    """Detailed analysis of HTTP headers."""
    
    url: str = Field(..., description="Analyzed URL")
    status_code: int = Field(..., description="HTTP response status code")
    headers: Dict[str, str] = Field(..., description="All response headers")
    security_headers: List[SecurityHeaderInfo] = Field(..., description="Security header analysis")
    missing_headers: List[SecurityHeaderInfo] = Field(..., description="Missing security headers")
    security_score: int = Field(..., description="Overall security score (0-100)")
    vulnerabilities: List[Dict[str, Any]] = Field(..., description="Identified vulnerabilities")
    recommendations: List[str] = Field(..., description="Security recommendations")


class HeaderAnalyzerOutput(BaseModel):
    """Output model for HTTP header security analysis."""
    
    success: bool = Field(..., description="Whether the analysis was successful")
    results: Optional[HeaderAnalysis] = Field(None, description="Analysis results")
    error: Optional[str] = Field(None, description="Error message if analysis failed")
    message: str = Field(..., description="Human-readable status message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "results": {
                    "url": "https://example.com",
                    "status_code": 200,
                    "headers": {
                        "content-type": "text/html",
                        "strict-transport-security": "max-age=31536000"
                    },
                    "security_headers": [
                        {
                            "name": "Strict-Transport-Security",
                            "value": "max-age=31536000",
                            "present": True,
                            "recommendation": "Consider adding includeSubDomains directive",
                            "severity": "medium",
                            "description": "Enforces HTTPS connections"
                        }
                    ],
                    "missing_headers": [
                        {
                            "name": "Content-Security-Policy",
                            "present": False,
                            "recommendation": "Implement CSP to prevent XSS attacks",
                            "severity": "high",
                            "description": "Prevents XSS and data injection attacks"
                        }
                    ],
                    "security_score": 65,
                    "vulnerabilities": [
                        {
                            "type": "Missing CSP",
                            "severity": "high",
                            "description": "No Content Security Policy header found"
                        }
                    ],
                    "recommendations": [
                        "Implement Content-Security-Policy header",
                        "Add X-Frame-Options to prevent clickjacking"
                    ]
                },
                "message": "HTTP header analysis completed successfully"
            }
        }
