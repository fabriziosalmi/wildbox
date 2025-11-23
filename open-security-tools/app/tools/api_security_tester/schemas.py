from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any, Union

class APISecurityTesterInput(BaseToolInput):
    """Input schema for API Security Tester tool"""
    api_base_url: str = Field(..., description="Base URL of the API to test")
    api_specification: Optional[str] = Field(None, description="OpenAPI/Swagger specification URL or content")
    authentication_type: str = Field(default="none", description="Authentication type (none, bearer, basic, api_key)")
    authentication_value: Optional[str] = Field(None, description="Authentication token/key/credentials")
    test_categories: List[str] = Field(default=["all"], description="Test categories to run (injection, broken_auth, sensitive_data, etc.)")
    test_depth: str = Field(default="standard", description="Test depth (quick, standard, comprehensive)")
    include_fuzzing: bool = Field(default=True, description="Include fuzzing tests")
    max_requests: int = Field(default=100, description="Maximum number of requests to send")
    wordlist: str = Field(default="api_common", description="Wordlist to use for endpoint discovery (api_common, etc.)")
    request_delay: float = Field(default=1.0, description="Delay between requests in seconds")
    custom_headers: Optional[Dict[str, str]] = Field(default=None, description="Custom headers to include")

class APIVulnerability(BaseModel):
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    title: str
    description: str
    endpoint: str
    method: str
    request_details: Dict[str, Any]
    response_details: Dict[str, Any]
    proof_of_concept: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: str

class APIEndpoint(BaseModel):
    path: str
    method: str
    parameters: List[str]
    responses: Dict[str, str]
    requires_auth: bool
    rate_limited: bool
    input_validation: str  # Strict, Moderate, Weak, None

class SecurityTest(BaseModel):
    test_name: str
    category: str
    description: str
    executed: bool
    passed: bool
    findings: List[str]
    recommendations: List[str]

class APISecurityTesterOutput(BaseToolOutput):
    """Output schema for API Security Tester tool"""
    api_base_url: str
    test_timestamp: str
    test_depth: str
    total_endpoints_tested: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    vulnerabilities: List[APIVulnerability]
    endpoints_discovered: List[APIEndpoint]
    security_tests: List[SecurityTest]
    owasp_api_top10_compliance: Dict[str, Any]  # Changed from Dict[str, str] to allow complex structure
    security_score: float  # 0-100
    risk_rating: str  # Low, Medium, High, Critical
    recommendations: List[str]
    execution_time: float
