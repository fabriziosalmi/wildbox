"""
Schemas for Certificate Authority Analyzer Tool
"""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime


class CAAnalyzerInput(BaseToolInput):
    """Input schema for CA and certificate analysis"""
    target: str = Field(
        description="Domain name or certificate to analyze"
    )
    port: int = Field(
        default=443,
        ge=1,
        le=65535,
        description="Port number for SSL/TLS connection"
    )
    check_certificate_chain: bool = Field(
        default=True,
        description="Analyze the complete certificate chain"
    )
    check_revocation: bool = Field(
        default=True,
        description="Check certificate revocation status"
    )
    check_transparency_logs: bool = Field(
        default=True,
        description="Check Certificate Transparency logs"
    )
    verify_hostname: bool = Field(
        default=True,
        description="Verify hostname matches certificate"
    )
    timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Connection timeout in seconds"
    )


class CertificateInfo(BaseModel):
    """Certificate information"""
    subject: Dict[str, str] = Field(description="Certificate subject")
    issuer: Dict[str, str] = Field(description="Certificate issuer")
    serial_number: str = Field(description="Certificate serial number")
    version: int = Field(description="Certificate version")
    not_before: datetime = Field(description="Certificate valid from")
    not_after: datetime = Field(description="Certificate valid until")
    signature_algorithm: str = Field(description="Signature algorithm")
    public_key_algorithm: str = Field(description="Public key algorithm")
    public_key_size: int = Field(description="Public key size in bits")
    san_domains: List[str] = Field(description="Subject Alternative Names")
    fingerprint_sha256: str = Field(description="SHA256 fingerprint")
    fingerprint_sha1: str = Field(description="SHA1 fingerprint")


class CertificateChainAnalysis(BaseModel):
    """Certificate chain analysis"""
    chain_length: int = Field(description="Number of certificates in chain")
    root_ca: str = Field(description="Root Certificate Authority")
    intermediate_cas: List[str] = Field(description="Intermediate Certificate Authorities")
    is_self_signed: bool = Field(description="Whether certificate is self-signed")
    is_valid_chain: bool = Field(description="Whether chain is valid")
    chain_issues: List[str] = Field(description="Issues found in certificate chain")


class RevocationStatus(BaseModel):
    """Certificate revocation status"""
    crl_checked: bool = Field(description="Whether CRL was checked")
    ocsp_checked: bool = Field(description="Whether OCSP was checked")
    is_revoked: bool = Field(description="Whether certificate is revoked")
    revocation_reason: Optional[str] = Field(description="Reason for revocation if applicable")
    revocation_date: Optional[datetime] = Field(description="Date of revocation if applicable")


class SecurityAnalysis(BaseModel):
    """SSL/TLS security analysis"""
    is_expired: bool = Field(description="Whether certificate is expired")
    days_until_expiry: int = Field(description="Days until certificate expires")
    is_weak_signature: bool = Field(description="Whether signature algorithm is weak")
    is_weak_key: bool = Field(description="Whether public key is weak")
    hostname_matches: bool = Field(description="Whether hostname matches certificate")
    has_security_issues: bool = Field(description="Whether security issues were found")
    security_issues: List[str] = Field(description="List of security issues")
    security_score: float = Field(description="Security score (0-100)")


class CAAnalyzerOutput(BaseToolOutput):
    """Output schema for CA and certificate analysis"""
    success: bool = Field(description="Whether the analysis was successful")
    target: str = Field(description="Target domain analyzed")
    port: int = Field(description="Port used for analysis")
    certificate: CertificateInfo = Field(description="Certificate information")
    chain_analysis: CertificateChainAnalysis = Field(description="Certificate chain analysis")
    revocation_status: Optional[RevocationStatus] = Field(description="Revocation status if checked")
    security_analysis: SecurityAnalysis = Field(description="Security analysis results")
    transparency_logs: Optional[List[str]] = Field(description="Certificate Transparency log entries")
    recommendations: List[str] = Field(description="Security recommendations")
    analysis_timestamp: datetime = Field(description="When analysis was performed")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")



