"""
Schemas for DNS Security Checker Tool
"""

from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime


class DNSSecurityInput(BaseToolInput):
    """Input schema for DNS security checking"""
    domain: str = Field(
        description="Domain name to check for DNS security issues",
        example="example.com"
    )
    check_dnssec: bool = Field(
        default=True,
        description="Check DNSSEC validation"
    )
    check_dmarc: bool = Field(
        default=True,
        description="Check DMARC policy"
    )
    check_spf: bool = Field(
        default=True,
        description="Check SPF records"
    )
    check_dkim: bool = Field(
        default=True,
        description="Check DKIM records"
    )
    check_mx_security: bool = Field(
        default=True,
        description="Check MX record security"
    )
    check_caa: bool = Field(
        default=True,
        description="Check CAA records"
    )
    timeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="DNS query timeout in seconds"
    )


class DNSRecord(BaseModel):
    """DNS record information"""
    record_type: str = Field(description="DNS record type")
    value: str = Field(description="Record value")
    ttl: Optional[int] = Field(description="Time to live")


class SecurityCheck(BaseModel):
    """Individual security check result"""
    check_name: str = Field(description="Name of the security check")
    passed: bool = Field(description="Whether the check passed")
    severity: str = Field(description="Severity level (info, low, medium, high, critical)")
    message: str = Field(description="Check result message")
    details: Optional[str] = Field(description="Additional details")


class DNSSecurityOutput(BaseToolOutput):
    """Output schema for DNS security checking"""
    success: bool = Field(description="Whether the analysis was successful")
    domain: str = Field(description="Domain that was analyzed")
    dns_records: Dict[str, List[DNSRecord]] = Field(description="Discovered DNS records")
    security_checks: List[SecurityCheck] = Field(description="Security check results")
    overall_score: int = Field(description="Overall security score (0-100)")
    risk_level: str = Field(description="Overall risk level")
    recommendations: List[str] = Field(description="Security recommendations")
    timestamp: datetime = Field(description="Analysis timestamp")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")
