from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class PKICertificateManagerInput(BaseModel):
    """Input schema for PKI Certificate Manager tool"""
    domain: Optional[str] = Field(None, description="Domain to analyze certificate")
    certificate_pem: Optional[str] = Field(None, description="PEM encoded certificate to analyze")
    certificate_chain: Optional[str] = Field(None, description="Full certificate chain")
    check_expiration: bool = Field(default=True, description="Check certificate expiration")
    check_revocation: bool = Field(default=True, description="Check certificate revocation status")
    check_key_strength: bool = Field(default=True, description="Check key strength and algorithms")
    check_extensions: bool = Field(default=True, description="Analyze certificate extensions")
    check_ct_logs: bool = Field(default=True, description="Check Certificate Transparency logs")
    validation_mode: str = Field(default="strict", description="Validation mode (strict, normal, permissive)")

class CertificateInfo(BaseModel):
    subject: Dict[str, str]
    issuer: Dict[str, str]
    serial_number: str
    valid_from: datetime
    valid_to: datetime
    signature_algorithm: str
    public_key_algorithm: str
    key_size: int
    fingerprint_sha1: str
    fingerprint_sha256: str
    san_names: List[str]
    is_ca: bool
    is_self_signed: bool

class CertificateValidation(BaseModel):
    is_valid: bool
    issues: List[str]
    warnings: List[str]
    chain_complete: bool
    trusted_root: bool
    revocation_status: str  # Valid, Revoked, Unknown

class SecurityAnalysis(BaseModel):
    key_strength_score: float
    algorithm_security: str  # Strong, Moderate, Weak, Deprecated
    common_name_match: bool
    san_coverage: List[str]
    vulnerabilities: List[str]
    compliance_issues: List[str]

class PKICertificateManagerOutput(BaseModel):
    """Output schema for PKI Certificate Manager tool"""
    certificate_info: CertificateInfo
    validation_results: CertificateValidation
    security_analysis: SecurityAnalysis
    expiration_warnings: List[str]
    ct_log_entries: List[Dict[str, Any]]
    recommendations: List[str]
    overall_score: float
    compliance_status: Dict[str, bool]

# Tool metadata

