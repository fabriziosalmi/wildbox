from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any, Union

class CloudSecurityAnalyzerInput(BaseToolInput):
    """Input schema for Cloud Security Analyzer tool"""
    cloud_provider: str = Field(..., description="Cloud provider (aws, azure, gcp, multi)")
    assessment_type: str = Field(default="comprehensive", description="Assessment type (quick, standard, comprehensive)")
    access_key: Optional[str] = Field(None, description="Cloud access key/credential")
    secret_key: Optional[str] = Field(None, description="Cloud secret key")
    region: str = Field(default="us-east-1", description="Cloud region to analyze")
    services_to_check: List[str] = Field(default=["all"], description="Specific services to check (s3, ec2, iam, etc.)")
    compliance_frameworks: List[str] = Field(default=["cis", "nist"], description="Compliance frameworks to check against")
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

