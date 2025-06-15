from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union

class SAMLAnalyzerInput(BaseModel):
    """Input schema for SAML Analyzer tool"""
    saml_response: str = Field(..., description="Base64 encoded SAML response to analyze")
    verify_signature: bool = Field(default=True, description="Verify digital signature")
    check_conditions: bool = Field(default=True, description="Check validity conditions")
    analyze_attributes: bool = Field(default=True, description="Analyze user attributes")
    check_encryption: bool = Field(default=True, description="Check encryption status")

class SAMLFinding(BaseModel):
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    title: str
    description: str
    recommendation: str

class SAMLAnalyzerOutput(BaseModel):
    """Output schema for SAML Analyzer tool"""
    is_valid: bool
    issuer: Optional[str]
    subject: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    attributes: Dict[str, Any]
    signature_valid: bool
    encrypted: bool
    findings: List[SAMLFinding]
    security_score: float
    execution_time: float

# Tool metadata

