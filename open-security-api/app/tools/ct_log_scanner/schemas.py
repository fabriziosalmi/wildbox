from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from ...standardized_schemas import BaseToolInput, BaseToolOutput


class CTLogScannerInput(BaseToolInput):
    """Input schema for CT Log Scanner tool"""
    domain: str = Field(..., description="Domain to search in certificate transparency logs")
    include_subdomains: bool = Field(
        default=True,
        description="Include subdomains in the search"
    )
    max_results: int = Field(
        default=100,
        description="Maximum number of certificates to return"
    )
    days_back: int = Field(
        default=365,
        description="Number of days back to search"
    )
    include_expired: bool = Field(
        default=True,
        description="Include expired certificates in results"
    )


class CertificateInfo(BaseModel):
    serial_number: str
    issuer: str
    subject: str
    subject_alt_names: List[str]
    not_before: str
    not_after: str
    is_expired: bool
    is_self_signed: bool
    key_algorithm: str
    signature_algorithm: str
    key_size: Optional[int] = None
    fingerprint_sha256: str
    ct_log_entry_id: str
    log_timestamp: str


class CTLogScannerOutput(BaseToolOutput):
    """Output schema for CT Log Scanner tool"""
    domain: str
    certificates_found: List[CertificateInfo]
    subdomain_analysis: Dict[str, Any]
    issuer_analysis: Dict[str, Any]
    timeline_analysis: Dict[str, Any]
    security_insights: Dict[str, Any]
    suspicious_patterns: List[str]
    recommendations: List[str]
    total_certificates: int
    search_timestamp: str
    success: bool
    message: str
