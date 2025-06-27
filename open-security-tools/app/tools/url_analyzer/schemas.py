"""
Schemas for URL Shortener Analyzer Tool
"""

from pydantic import BaseModel, Field, HttpUrl
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime


class URLShortenerInput(BaseToolInput):
    """Input schema for URL shortener analysis"""
    shortened_url: HttpUrl = Field(
        description="Shortened URL to analyze"
    )
    follow_redirects: bool = Field(
        default=True,
        description="Follow redirect chains to discover final destination"
    )
    max_redirects: int = Field(
        default=10,
        ge=1,
        le=20,
        description="Maximum number of redirects to follow"
    )
    timeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="Request timeout in seconds"
    )
    check_reputation: bool = Field(
        default=True,
        description="Check URL reputation against known malicious URLs"
    )


class RedirectHop(BaseModel):
    """Individual redirect hop information"""
    step: int = Field(description="Redirect step number")
    url: str = Field(description="URL at this step")
    status_code: int = Field(description="HTTP status code")
    method: str = Field(description="HTTP method used")
    headers: Dict[str, str] = Field(description="Response headers")
    response_time: float = Field(description="Response time in seconds")


class SecurityAnalysis(BaseModel):
    """Security analysis results"""
    is_suspicious: bool = Field(description="Whether the URL chain appears suspicious")
    risk_level: str = Field(description="Risk level (low, medium, high, critical)")
    threats_detected: List[str] = Field(description="List of detected threats")
    reputation_score: Optional[int] = Field(description="Reputation score (0-100)")
    phishing_indicators: List[str] = Field(description="Phishing indicators found")
    malware_indicators: List[str] = Field(description="Malware indicators found")


class URLShortenerOutput(BaseToolOutput):
    """Output schema for URL shortener analysis"""
    success: bool = Field(description="Whether the analysis was successful")
    original_url: str = Field(description="Original shortened URL")
    final_url: Optional[str] = Field(description="Final destination URL")
    redirect_chain: List[RedirectHop] = Field(description="Complete redirect chain")
    total_redirects: int = Field(description="Total number of redirects")
    shortener_service: Optional[str] = Field(description="Detected URL shortener service")
    security_analysis: SecurityAnalysis = Field(description="Security analysis results")
    timestamp: datetime = Field(description="Analysis timestamp")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")
