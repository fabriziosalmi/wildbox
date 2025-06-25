"""
Schemas for URL Security Scanner Tool
"""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime


class URLSecurityInput(BaseToolInput):
    """Input schema for URL security scanning"""
    url: str = Field(
        description="URL to analyze for security risks"
    )
    check_reputation: bool = Field(
        default=True,
        description="Check URL reputation against threat databases"
    )
    analyze_structure: bool = Field(
        default=True,
        description="Analyze URL structure for suspicious patterns"
    )
    check_redirects: bool = Field(
        default=True,
        description="Follow and analyze redirect chains"
    )
    max_redirects: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of redirects to follow"
    )
    timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Request timeout in seconds"
    )


class URLComponents(BaseModel):
    """URL component analysis"""
    scheme: str = Field(description="URL scheme (http, https, etc.)")
    domain: str = Field(description="Domain name")
    subdomain: Optional[str] = Field(description="Subdomain if present")
    path: str = Field(description="URL path")
    query: Optional[str] = Field(description="Query string")
    fragment: Optional[str] = Field(description="URL fragment")
    port: Optional[int] = Field(description="Port number if specified")


class SecurityAnalysis(BaseModel):
    """URL security analysis results"""
    is_https: bool = Field(description="Whether URL uses HTTPS")
    has_suspicious_patterns: bool = Field(description="Contains suspicious patterns")
    suspicious_patterns: List[str] = Field(description="List of suspicious patterns found")
    domain_age_days: Optional[int] = Field(description="Domain age in days if available")
    is_shortened_url: bool = Field(description="Whether this appears to be a shortened URL")
    has_suspicious_tld: bool = Field(description="Whether TLD is commonly used for malicious purposes")
    encoding_issues: List[str] = Field(description="URL encoding issues found")


class RedirectAnalysis(BaseModel):
    """Redirect chain analysis"""
    redirect_count: int = Field(description="Number of redirects followed")
    redirect_chain: List[str] = Field(description="Chain of URLs in redirects")
    final_url: str = Field(description="Final destination URL")
    has_suspicious_redirects: bool = Field(description="Whether redirect chain contains suspicious URLs")
    redirect_security_issues: List[str] = Field(description="Security issues in redirect chain")


class ReputationAnalysis(BaseModel):
    """URL reputation analysis"""
    is_malicious: bool = Field(description="Whether URL is flagged as malicious")
    threat_categories: List[str] = Field(description="Categories of threats detected")
    reputation_score: float = Field(description="Reputation score (0-100, higher is better)")
    blacklist_matches: List[str] = Field(description="Blacklists that flagged this URL")
    whitelist_matches: List[str] = Field(description="Whitelists that approved this URL")


class URLSecurityOutput(BaseToolOutput):
    """Output schema for URL security analysis"""
    success: bool = Field(description="Whether the analysis was successful")
    original_url: str = Field(description="Original URL analyzed")
    url_components: URLComponents = Field(description="Parsed URL components")
    security_analysis: SecurityAnalysis = Field(description="Security analysis results")
    redirect_analysis: Optional[RedirectAnalysis] = Field(description="Redirect analysis if enabled")
    reputation_analysis: Optional[ReputationAnalysis] = Field(description="Reputation analysis if enabled")
    overall_risk_score: float = Field(description="Overall risk score (0-100, higher is riskier)")
    risk_level: str = Field(description="Risk level (low, medium, high, critical)")
    recommendations: List[str] = Field(description="Security recommendations")
    analysis_timestamp: datetime = Field(description="When the analysis was performed")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")
