from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput, CaseInsensitiveChoice
from typing import List, Literal, Optional, Dict, Any, Union

# Compared regardless of case by main.py (#611).
CloudProvider = CaseInsensitiveChoice("aws", "azure", "gcp")


class CloudSecurityAnalyzerInput(BaseToolInput):
    """Input schema for Cloud Security Analyzer tool"""
    # The providers main.py accepts; "multi" was listed but refused (#611).
    cloud_provider: CloudProvider = Field(..., description="Cloud provider (aws, azure, gcp)")
    assessment_type: str = Field(default="comprehensive", description="Assessment type (quick, standard, comprehensive)")
    access_key: Optional[str] = Field(None, description="Cloud access key/credential")
    secret_key: Optional[str] = Field(None, description="Cloud secret key")
    region: str = Field(default="us-east-1", description="Cloud region to analyze")
    # The services and frameworks main.py has checks for. Another service
    # produced nothing, and a framework without checks (nist, in the
    # default) was reported 100% compliant (#611).
    services_to_check: List[Literal["all", "s3", "ec2", "iam"]] = Field(
        default=["all"], min_length=1, description="Services to check (all, s3, ec2, iam)"
    )
    compliance_frameworks: List[Literal["cis"]] = Field(
        default=["cis"], description="Compliance frameworks to check against (cis)"
    )
    include_cost_analysis: bool = Field(default=True, description="Include cost optimization analysis")
    check_permissions: bool = Field(default=True, description="Check IAM permissions and policies")
    check_encryption: bool = Field(default=True, description="Check encryption configurations")
    check_networking: bool = Field(default=True, description="Check network security configurations")
    check_logging: bool = Field(default=True, description="Check logging and monitoring configurations")

class CloudMisconfiguration(BaseModel):
    service: str
    resource_id: str
    severity: str  # Critical, High, Medium, Low
    category: str
    title: str
    description: str
    current_configuration: Dict[str, Any]
    recommended_configuration: Dict[str, Any]
    compliance_frameworks: List[str]
    remediation_steps: List[str]
    cost_impact: Optional[str] = None

class ComplianceCheck(BaseModel):
    framework: str  # CIS, NIST, SOC2, etc.
    control_id: str
    control_title: str
    status: str  # PASS, FAIL, PARTIAL, UNKNOWN
    description: str
    evidence: List[str]
    remediation: Optional[str] = None

class ResourceInventory(BaseModel):
    service: str
    resource_type: str
    resource_id: str
    region: str
    tags: Dict[str, str]
    security_score: float
    estimated_monthly_cost: Optional[float] = None

class CloudSecurityAnalyzerOutput(BaseToolOutput):
    """Output schema for Cloud Security Analyzer tool"""
    cloud_provider: str
    analysis_timestamp: str
    assessment_type: str
    regions_analyzed: List[str]
    total_resources: int
    total_misconfigurations: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    misconfigurations: List[CloudMisconfiguration]
    compliance_results: List[ComplianceCheck]
    resource_inventory: List[ResourceInventory]
    security_score: float  # 0-100
    compliance_score: Dict[str, float]  # Framework -> Score
    cost_optimization_savings: Optional[float] = None
    recommendations: List[str]
    execution_time: float

# Tool metadata

