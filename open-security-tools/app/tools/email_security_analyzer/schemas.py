"""
Schemas for Email Security Analyzer Tool
"""

from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime


class EmailSecurityInput(BaseToolInput):
    """Input schema for email security analysis"""
    email_headers: str = Field(
        description="Raw email headers to analyze"
    )
    sender_email: Optional[str] = Field(
        default=None,
        description="Sender email address (if not in headers)"
    )
    check_spf: bool = Field(
        default=True,
        description="Check SPF (Sender Policy Framework) records"
    )
    check_dkim: bool = Field(
        default=True,
        description="Check DKIM (DomainKeys Identified Mail) signatures"
    )
    check_dmarc: bool = Field(
        default=True,
        description="Check DMARC (Domain-based Message Authentication) policies"
    )
    analyze_reputation: bool = Field(
        default=True,
        description="Analyze sender domain reputation"
    )
    check_blacklists: bool = Field(
        default=True,
        description="Check against email blacklists"
    )


class SPFAnalysis(BaseModel):
    """SPF analysis results"""
    spf_record_found: bool = Field(description="Whether SPF record exists")
    spf_record: Optional[str] = Field(description="SPF record content")
    spf_result: str = Field(description="SPF check result (pass, fail, softfail, neutral)")
    spf_issues: List[str] = Field(description="SPF configuration issues")
    authorized_senders: List[str] = Field(description="Authorized sender IPs/domains")


class DKIMAnalysis(BaseModel):
    """DKIM analysis results"""
    dkim_signature_found: bool = Field(description="Whether DKIM signature exists")
    dkim_valid: bool = Field(description="Whether DKIM signature is valid")
    dkim_domain: Optional[str] = Field(description="DKIM signing domain")
    dkim_selector: Optional[str] = Field(description="DKIM selector")
    dkim_algorithm: Optional[str] = Field(description="DKIM signing algorithm")
    dkim_issues: List[str] = Field(description="DKIM validation issues")


class DMARCAnalysis(BaseModel):
    """DMARC analysis results"""
    dmarc_record_found: bool = Field(description="Whether DMARC record exists")
    dmarc_record: Optional[str] = Field(description="DMARC record content")
    dmarc_policy: Optional[str] = Field(description="DMARC policy (none, quarantine, reject)")
    dmarc_alignment: Dict[str, bool] = Field(description="SPF and DKIM alignment")
    dmarc_issues: List[str] = Field(description="DMARC configuration issues")
    dmarc_compliance: bool = Field(description="Whether email passes DMARC")


class EmailRouting(BaseModel):
    """Email routing analysis"""
    hop_count: int = Field(description="Number of routing hops")
    routing_path: List[str] = Field(description="Email routing path")
    suspicious_hops: List[str] = Field(description="Suspicious routing hops")
    geo_locations: List[str] = Field(description="Geographic locations in routing")
    delivery_delay: Optional[float] = Field(description="Total delivery delay in hours")


class ReputationAnalysis(BaseModel):
    """Sender reputation analysis"""
    domain_reputation: str = Field(description="Domain reputation (good, neutral, poor, malicious)")
    ip_reputation: str = Field(description="IP reputation")
    sender_score: float = Field(description="Sender reputation score (0-100)")
    blacklist_status: Dict[str, bool] = Field(description="Blacklist check results")
    whitelist_status: Dict[str, bool] = Field(description="Whitelist check results")
    domain_age_days: Optional[int] = Field(description="Domain age in days")


class PhishingIndicators(BaseModel):
    """Phishing detection indicators"""
    suspicious_patterns: List[str] = Field(description="Suspicious patterns detected")
    domain_spoofing: bool = Field(description="Potential domain spoofing detected")
    suspicious_links: List[str] = Field(description="Suspicious URLs found")
    brand_impersonation: Optional[str] = Field(description="Potential brand being impersonated")
    urgency_indicators: List[str] = Field(description="Urgency/pressure indicators")
    social_engineering: List[str] = Field(description="Social engineering tactics")


class EmailSecurityOutput(BaseToolOutput):
    """Output schema for email security analysis"""
    success: bool = Field(description="Whether the analysis was successful")
    sender_email: str = Field(description="Sender email address")
    sender_domain: str = Field(description="Sender domain")
    sender_ip: Optional[str] = Field(description="Sender IP address")
    spf_analysis: SPFAnalysis = Field(description="SPF analysis results")
    dkim_analysis: DKIMAnalysis = Field(description="DKIM analysis results")
    dmarc_analysis: DMARCAnalysis = Field(description="DMARC analysis results")
    email_routing: EmailRouting = Field(description="Email routing analysis")
    reputation_analysis: ReputationAnalysis = Field(description="Reputation analysis")
    phishing_indicators: PhishingIndicators = Field(description="Phishing detection results")
    security_score: float = Field(description="Overall email security score (0-100)")
    risk_level: str = Field(description="Risk level (low, medium, high, critical)")
    authentication_summary: Dict[str, str] = Field(description="Summary of authentication checks")
    recommendations: List[str] = Field(description="Security recommendations")
    analysis_timestamp: datetime = Field(description="When analysis was performed")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")
