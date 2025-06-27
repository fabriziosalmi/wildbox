"""Pydantic schemas for the cookie security scanner tool."""

from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict
from datetime import datetime

class CookieScannerInput(BaseToolInput):
    target_url: str = Field(..., description="Target URL to analyze cookies", example="https://example.com")
    include_subdomains: bool = Field(default=True, description="Include subdomain cookie analysis")
    timeout: int = Field(default=10, description="Request timeout in seconds", ge=1, le=60)

class CookieAnalysis(BaseModel):
    name: str = Field(..., description="Cookie name")
    value: str = Field(..., description="Cookie value (truncated if sensitive)")
    domain: Optional[str] = Field(None, description="Cookie domain")
    path: Optional[str] = Field(None, description="Cookie path")
    secure: bool = Field(..., description="Secure flag status")
    httponly: bool = Field(..., description="HttpOnly flag status")
    samesite: Optional[str] = Field(None, description="SameSite attribute")
    expires: Optional[str] = Field(None, description="Expiration time")
    max_age: Optional[int] = Field(None, description="Max-Age value")
    vulnerabilities: List[str] = Field(default=[], description="Security issues found")
    risk_level: str = Field(..., description="Risk level: low, medium, high, critical")

class CookieScannerOutput(BaseToolOutput):
    success: bool = Field(..., description="Whether the scan was successful")
    target_url: str = Field(..., description="Target URL analyzed")
    timestamp: datetime = Field(..., description="Analysis timestamp")
    total_cookies: int = Field(..., description="Total number of cookies found")
    secure_cookies: int = Field(..., description="Number of secure cookies")
    insecure_cookies: int = Field(..., description="Number of insecure cookies")
    cookies: List[CookieAnalysis] = Field(..., description="Detailed cookie analysis")
    overall_security_score: int = Field(..., description="Overall security score (0-100)")
    recommendations: List[str] = Field(..., description="Security recommendations")
    message: str = Field(..., description="Result message")
    error: Optional[str] = Field(default=None, description="Error message if scan failed")
