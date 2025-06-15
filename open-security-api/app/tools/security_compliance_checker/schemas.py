from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class ComplianceCheckInput(BaseModel):
    framework: str = Field(..., description="Compliance framework (ISO27001, SOC2, PCI_DSS, GDPR, HIPAA, NIST)")
    scope: str = Field(..., description="Assessment scope (infrastructure, applications, policies, all)")
    target_systems: List[str] = Field(..., description="Target systems to assess")
    assessment_type: str = Field("comprehensive", description="Assessment type (quick, comprehensive, detailed)")
    exclude_controls: Optional[List[str]] = Field([], description="Controls to exclude from assessment")

class ControlAssessment(BaseModel):
    control_id: str
    control_name: str
    description: str
    requirement: str
    implementation_status: str
    compliance_score: float
    evidence: List[str]
    gaps: List[str]
    recommendations: List[str]
    risk_level: str

class ComplianceReport(BaseModel):
    framework: str
    assessment_date: datetime
    overall_score: float
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    control_assessments: List[ControlAssessment]
    critical_gaps: List[str]
    high_priority_recommendations: List[str]

class RemediationPlan(BaseModel):
    priority: str
    control_id: str
    action_required: str
    estimated_effort: str
    target_completion: str
    responsible_party: str
    dependencies: List[str]

class SecurityComplianceOutput(BaseModel):
    success: bool
    assessment_id: str
    framework: str
    compliance_report: ComplianceReport
    remediation_plans: List[RemediationPlan]
    executive_summary: str
    next_assessment_date: str
    certification_readiness: str
