from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from ...input_validation import UrlField
from typing import List, Literal, Optional, Dict, Any, Union

from ..wordlists import list_available_wordlists

class APISecurityTesterInput(BaseToolInput):
    """Input schema for API Security Tester tool"""
    # UrlField: SSRF validation is part of the schema, so it runs before the
    # tool is entered and cannot be missed by a name-based sweep (WILDBO-INPT-01).
    api_base_url: UrlField = Field(..., description="Base URL of the API to test")
    api_specification: Optional[str] = Field(None, description="OpenAPI/Swagger specification URL or content")
    # The schemes main.py sends; another value sent no credentials at all
    # (#611).
    authentication_type: Literal["none", "bearer", "basic", "api_key"] = Field(
        default="none", description="Authentication type (none, bearer, basic, api_key)"
    )
    # The characters and length main.py's validate_auth_value accepts; another
    # value raised out of the tool (#611).
    authentication_value: Optional[str] = Field(
        None,
        max_length=1000,
        pattern=r"^\s*[A-Za-z0-9\-_.=:+/]+\s*$",
        description="Authentication token/key/credentials (A-Z, a-z, 0-9, - _ . = : + /)",
    )
    # The categories main.py runs. The description named broken_auth and
    # sensitive_data, which do not exist; unknown names ran no test and scored
    # the API as low risk (#611).
    test_categories: List[Literal[
        "all",
        "broken_object_level_authorization",
        "broken_user_authentication",
        "excessive_data_exposure",
        "lack_of_resources_rate_limiting",
        "broken_function_level_authorization",
        "mass_assignment",
        "security_misconfiguration",
        "injection",
        "improper_assets_management",
        "insufficient_logging_monitoring",
    ]] = Field(
        default=["all"],
        min_length=1,
        description="OWASP API Top 10 test categories to run, or all",
    )
    test_depth: str = Field(default="standard", description="Test depth (quick, standard, comprehensive)")
    include_fuzzing: bool = Field(default=True, description="Include fuzzing tests")
    max_requests: int = Field(default=100, description="Maximum number of requests to send")
    # The wordlists shipped in app/tools/wordlists; another name fell back to
    # a ten-path list silently (#611).
    wordlist: Literal[tuple(list_available_wordlists())] = Field(
        default="api_common", description="Wordlist to use for endpoint discovery"
    )
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
