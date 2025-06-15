from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class APISecurityAnalyzerInput(BaseModel):
    """Input schema for API Security Analyzer tool"""
    target_url: str = Field(..., description="Target API URL to analyze")
    api_type: str = Field(default="REST", description="API type (REST, GraphQL, SOAP)")
    check_authentication: bool = Field(default=True, description="Check authentication mechanisms")
    check_authorization: bool = Field(default=True, description="Check authorization controls")
    check_rate_limiting: bool = Field(default=True, description="Check rate limiting")
    check_input_validation: bool = Field(default=True, description="Check input validation")
    check_encryption: bool = Field(default=True, description="Check encryption in transit")
    custom_headers: Optional[Dict[str, str]] = Field(default=None, description="Custom headers to include")
    timeout: int = Field(default=30, description="Request timeout in seconds")

class SecurityIssue(BaseModel):
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    title: str
    description: str
    recommendation: str
    cwe_id: Optional[str] = None
    affected_endpoint: Optional[str] = None

class APISecurityAnalyzerOutput(BaseModel):
    """Output schema for API Security Analyzer tool"""
    target_url: str
    api_type: str
    analysis_timestamp: str
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    info_issues: int
    security_issues: List[SecurityIssue]
    api_endpoints_discovered: List[str]
    security_headers: Dict[str, str]
    authentication_methods: List[str]
    encryption_status: Dict[str, Any]
    rate_limiting_status: Dict[str, Any]
    overall_security_score: float  # 0-100
    recommendations: List[str]
    execution_time: float
