"""Pydantic schemas for the SSL/TLS analyzer tool."""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime

class SSLAnalyzerInput(BaseToolInput):
    target: str = Field(..., description="Target domain or IP address", example="example.com")
    port: int = Field(default=443, description="Port to connect to", ge=1, le=65535)
    timeout: int = Field(default=10, description="Timeout in seconds", ge=1, le=60)

class CertificateInfo(BaseModel):
    subject: Dict[str, str] = Field(..., description="Certificate subject information")
    issuer: Dict[str, str] = Field(..., description="Certificate issuer information")
    serial_number: str = Field(..., description="Certificate serial number")
    not_before: datetime = Field(..., description="Certificate valid from date")
    not_after: datetime = Field(..., description="Certificate expiration date")
    days_until_expiry: int = Field(..., description="Days until certificate expires")
    signature_algorithm: str = Field(..., description="Certificate signature algorithm")
    public_key_size: int = Field(..., description="Public key size in bits")
    san_domains: List[str] = Field(..., description="Subject Alternative Names")

class SSLVulnerability(BaseModel):
    name: str = Field(..., description="Vulnerability name")
    severity: str = Field(..., description="Vulnerability severity")
    description: str = Field(..., description="Vulnerability description")

class SSLAnalyzerOutput(BaseToolOutput):
    target: str = Field(..., description="Target that was analyzed")
    port: int = Field(..., description="Port that was analyzed")
    timestamp: datetime = Field(..., description="Analysis timestamp")
    ssl_version: str = Field(..., description="SSL/TLS version")
    cipher_suite: str = Field(..., description="Negotiated cipher suite")
    certificate: CertificateInfo = Field(..., description="Certificate information")
    vulnerabilities: List[SSLVulnerability] = Field(..., description="Detected vulnerabilities")
    security_score: int = Field(..., description="Security score (0-100)")
    recommendations: List[str] = Field(..., description="Security recommendations")
