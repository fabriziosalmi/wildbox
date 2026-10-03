from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import Dict, List, Literal, Optional
from datetime import datetime

class WAFBypassRequest(BaseToolInput):
    """Request model for WAF bypass testing"""
    target_url: str = Field(..., description="Target URL to test WAF bypass techniques")
    # The payload sets, encodings and obfuscations main.py implements. An
    # unknown payload type was skipped, an unknown encoding or obfuscation
    # sent the payload unchanged, and double_url was not listed (#611). "none"
    # leaves the payload as it is, explicitly.
    payload_types: List[Literal["sql_injection", "xss", "command_injection", "path_traversal", "xxe", "ssrf"]] = Field(
        default=["sql_injection", "xss", "command_injection", "path_traversal"],
        min_length=1,
        description="Types of payloads to test: sql_injection, xss, command_injection, path_traversal, xxe, ssrf"
    )
    encoding_techniques: List[Literal["url_encoding", "double_url", "html_encoding", "unicode", "base64", "hex", "none"]] = Field(
        default=["url_encoding", "html_encoding", "unicode", "base64"],
        min_length=1,
        description="Encoding techniques to apply: url_encoding, double_url, html_encoding, unicode, base64, hex, or none"
    )
    obfuscation_methods: List[Literal["case_variation", "comment_insertion", "whitespace_manipulation", "concatenation", "none"]] = Field(
        default=["case_variation", "comment_insertion", "whitespace_manipulation"],
        description="Obfuscation methods: case_variation, comment_insertion, whitespace_manipulation, concatenation, or none"
    )
    test_depth: str = Field(default="medium", description="Test depth: light, medium, aggressive")
    custom_headers: Optional[Dict[str, str]] = Field(default=None, description="Custom HTTP headers to include")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")

class WAFBypassPayload(BaseModel):
    """WAF bypass payload information"""
    original_payload: str
    modified_payload: str
    technique: str
    encoding: str
    obfuscation: str
    bypass_success: bool
    response_code: int
    response_size: int
    waf_triggered: bool
    detection_signatures: List[str]

class WAFBypassTechnique(BaseModel):
    """WAF bypass technique details"""
    name: str
    description: str
    success_rate: float
    payloads_tested: int
    payloads_successful: int
    examples: List[str]
    recommendations: List[str]

class WAFBypassResponse(BaseToolOutput):
    """Response model for WAF bypass testing"""
    target_url: str
    waf_detected: bool
    waf_type: Optional[str]
    waf_version: Optional[str]
    
    # Test results
    total_payloads_tested: int
    successful_bypasses: int
    bypass_success_rate: float
    
    # Technique analysis
    techniques_tested: List[WAFBypassTechnique]
    most_effective_technique: Optional[str]
    payload_results: List[WAFBypassPayload]
    
    # WAF analysis
    blocked_patterns: List[str]
    allowed_patterns: List[str]
    filtering_rules: List[str]
    
    # Security assessment
    risk_level: str
    vulnerability_summary: str
    bypass_recommendations: List[str]
    waf_improvement_suggestions: List[str]
    
    timestamp: str
    processing_time_ms: int
