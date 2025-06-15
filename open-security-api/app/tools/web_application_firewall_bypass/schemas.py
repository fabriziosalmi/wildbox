from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime

class WAFBypassRequest(BaseModel):
    """Request model for WAF bypass testing"""
    target_url: str = Field(..., description="Target URL to test WAF bypass techniques")
    payload_types: List[str] = Field(
        default=["sql_injection", "xss", "command_injection", "path_traversal"],
        description="Types of payloads to test: sql_injection, xss, command_injection, path_traversal, xxe, ssrf"
    )
    encoding_techniques: List[str] = Field(
        default=["url_encoding", "html_encoding", "unicode", "base64"],
        description="Encoding techniques to apply: url_encoding, html_encoding, unicode, base64, hex"
    )
    obfuscation_methods: List[str] = Field(
        default=["case_variation", "comment_insertion", "whitespace_manipulation"],
        description="Obfuscation methods: case_variation, comment_insertion, whitespace_manipulation, concatenation"
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

class WAFBypassResponse(BaseModel):
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
