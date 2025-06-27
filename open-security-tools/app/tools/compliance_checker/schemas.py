from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime

class ComplianceCheckerInput(BaseToolInput):
    """Input schema for Compliance Checker tool"""
    target_url: Optional[str] = Field(None, description="Target website/application URL")
    domain: Optional[str] = Field(None, description="Domain to analyze")
    organization_type: str = Field(default="general", description="Organization type (healthcare, financial, ecommerce, government, general)")
    compliance_frameworks: List[str] = Field(default=["GDPR", "PCI-DSS"], description="Frameworks to check (GDPR, PCI-DSS, HIPAA, SOC2, ISO27001, NIST, CIS)")
    check_web_security: bool = Field(default=True, description="Check web security compliance")
    check_data_protection: bool = Field(default=True, description="Check data protection compliance")
    check_access_controls: bool = Field(default=True, description="Check access control compliance")
    check_audit_logging: bool = Field(default=True, description="Check audit and logging compliance")
    check_encryption: bool = Field(default=True, description="Check encryption compliance")
    check_privacy_policy: bool = Field(default=True, description="Check privacy policy compliance")
    scan_depth: str = Field(default="standard", description="Scan depth (quick, standard, comprehensive)")

class ComplianceRequirement(BaseModel):
    framework: str
    requirement_id: str
    requirement_name: str
    description: str
    category: str
    mandatory: bool
    status: str  # Compliant, Non-Compliant, Partial, Not-Applicable
    confidence: float
    evidence: List[str]
    gaps: List[str]
    recommendations: List[str]

class SecurityControl(BaseModel):
    control_id: str
    control_name: str
    implemented: bool
    effectiveness: str  # Effective, Partially-Effective, Ineffective
    evidence: List[str]
    deficiencies: List[str]
    recommendations: List[str]

class DataProtectionAssessment(BaseModel):
    personal_data_identified: bool
    data_categories: List[str]
    processing_lawful_basis: List[str]
    consent_mechanisms: List[str]
    data_retention_policy: bool
    data_subject_rights: List[str]
    privacy_policy_present: bool
    cookie_consent: bool
    issues: List[str]

class AuditTrailAssessment(BaseModel):
    logging_enabled: bool
    log_coverage: List[str]
    log_retention_period: int
    log_integrity_protection: bool
    monitoring_alerts: bool
    issues: List[str]
    recommendations: List[str]

class EncryptionAssessment(BaseModel):
    data_in_transit_encrypted: bool
    data_at_rest_encrypted: bool
    encryption_algorithms: List[str]
    key_management: str
    certificate_validity: bool
    issues: List[str]
    recommendations: List[str]

class ComplianceGap(BaseModel):
    framework: str
    gap_type: str
    severity: str  # Critical, High, Medium, Low
    description: str
    affected_requirements: List[str]
    business_impact: str
    remediation_effort: str  # Low, Medium, High
    remediation_steps: List[str]
    timeline: str

class ComplianceCheckerOutput(BaseToolOutput):
    """Output schema for Compliance Checker tool"""
    assessment_target: str
    organization_type: str
    frameworks_assessed: List[str]
    assessment_timestamp: datetime
    overall_compliance_score: float
    framework_scores: Dict[str, float]
    compliance_requirements: List[ComplianceRequirement]
    security_controls: List[SecurityControl]
    data_protection: DataProtectionAssessment
    audit_trail: AuditTrailAssessment
    encryption: EncryptionAssessment
    compliance_gaps: List[ComplianceGap]
    priority_actions: List[str]
    compliance_roadmap: List[Dict[str, Any]]
    recommendations: List[str]
    assessment_summary: Dict[str, Any]

# Tool metadata

