from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class ContainerSecurityScannerInput(BaseModel):
    """Input schema for Container Security Scanner tool"""
    image_name: Optional[str] = Field(None, description="Docker image name to scan")
    dockerfile_content: Optional[str] = Field(None, description="Dockerfile content to analyze")
    container_id: Optional[str] = Field(None, description="Running container ID to scan")
    scan_type: str = Field(default="comprehensive", description="Scan type (quick, standard, comprehensive)")
    check_vulnerabilities: bool = Field(default=True, description="Scan for known vulnerabilities")
    check_secrets: bool = Field(default=True, description="Scan for exposed secrets")
    check_configuration: bool = Field(default=True, description="Check security configuration")
    check_compliance: bool = Field(default=True, description="Check compliance with security standards")
    check_dependencies: bool = Field(default=True, description="Analyze dependencies for vulnerabilities")
    registry_url: Optional[str] = Field(None, description="Container registry URL")

class Vulnerability(BaseModel):
    cve_id: str
    severity: str  # Critical, High, Medium, Low
    package: str
    version: str
    fixed_version: Optional[str] = None
    description: str
    score: float
    vector: Optional[str] = None

class SecretExposure(BaseModel):
    type: str  # API key, password, token, etc.
    location: str  # file path or environment variable
    pattern_matched: str
    confidence: float
    recommendation: str

class ConfigurationIssue(BaseModel):
    issue_type: str
    severity: str
    description: str
    file_location: Optional[str] = None
    recommendation: str
    compliant: bool

class LayerAnalysis(BaseModel):
    layer_id: str
    size_mb: float
    command: str
    vulnerabilities_introduced: int
    secrets_introduced: int
    recommendations: List[str]

class ComplianceCheck(BaseModel):
    standard: str  # CIS, NIST, PCI-DSS, etc.
    rule_id: str
    rule_description: str
    status: str  # Pass, Fail, Warning
    severity: str
    recommendation: str

class ContainerSecurityScannerOutput(BaseModel):
    """Output schema for Container Security Scanner tool"""
    image_analyzed: str
    scan_timestamp: datetime
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    vulnerabilities: List[Vulnerability]
    secrets_found: List[SecretExposure]
    configuration_issues: List[ConfigurationIssue]
    layer_analysis: List[LayerAnalysis]
    compliance_results: List[ComplianceCheck]
    security_score: float
    recommendations: List[str]
    scan_summary: Dict[str, Any]

# Tool metadata
TOOL_INFO = {
    "name": "Container Security Scanner",
    "description": "Comprehensive security scanner for Docker containers and images including vulnerability detection, secret scanning, and compliance checking",
    "category": "container_security",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["docker", "containers", "vulnerabilities", "secrets", "compliance", "devops"]
}
