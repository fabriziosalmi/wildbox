from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any, Union

class MobileSecurityAnalyzerInput(BaseToolInput):
    """Input schema for Mobile Security Analyzer tool"""
    app_file: Optional[str] = Field(None, description="Base64 encoded APK/IPA file content")
    app_url: Optional[str] = Field(None, description="URL to download mobile app file")
    app_package: Optional[str] = Field(None, description="Package name for store analysis")
    platform: str = Field(default="android", description="Mobile platform (android, ios)")
    analysis_depth: str = Field(default="standard", description="Analysis depth (quick, standard, deep)")
    check_permissions: bool = Field(default=True, description="Analyze app permissions")
    check_network_security: bool = Field(default=True, description="Check network security configurations")
    check_data_storage: bool = Field(default=True, description="Analyze data storage security")
    check_code_quality: bool = Field(default=True, description="Check code quality and vulnerabilities")
    check_malware: bool = Field(default=True, description="Scan for malware signatures")
    extract_urls: bool = Field(default=True, description="Extract hardcoded URLs and endpoints")
    decompile_code: bool = Field(default=False, description="Perform code decompilation analysis")

class SecurityVulnerability(BaseModel):
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    title: str
    description: str
    file_location: Optional[str] = None
    code_snippet: Optional[str] = None
    owasp_mobile_category: Optional[str] = None
    cwe_id: Optional[str] = None
    remediation: str

class PermissionAnalysis(BaseModel):
    permission: str
    risk_level: str  # Critical, High, Medium, Low
    description: str
    justification_needed: bool
    alternatives: List[str]

class NetworkSecurityAnalysis(BaseModel):
    uses_cleartext: bool
    certificate_pinning: bool
    custom_ca_allowed: bool
    network_security_config: Optional[Dict[str, Any]] = None
    cleartext_endpoints: List[str]

class ExtractedAsset(BaseModel):
    asset_type: str  # URL, API_Key, Certificate, etc.
    value: str
    location: str
    risk_level: str
    description: str

class AppMetadata(BaseModel):
    package_name: str
    version_name: str
    version_code: int
    min_sdk_version: int
    target_sdk_version: int
    app_name: str
    file_size: int
    signing_certificate: Optional[Dict[str, Any]] = None
    permissions: List[str]

class MobileSecurityAnalyzerOutput(BaseToolOutput):
    """Output schema for Mobile Security Analyzer tool"""
    platform: str
    analysis_timestamp: str
    analysis_depth: str
    app_metadata: Optional[AppMetadata]
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    vulnerabilities: List[SecurityVulnerability]
    permission_analysis: List[PermissionAnalysis]
    network_security: Optional[NetworkSecurityAnalysis]
    extracted_assets: List[ExtractedAsset]
    owasp_mobile_compliance: Dict[str, str]
    security_score: float  # 0-100
    privacy_score: float  # 0-100
    malware_detected: bool
    recommendations: List[str]
    execution_time: float

# Tool metadata

