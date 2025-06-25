"""Pydantic schemas for the JWT analyzer tool."""

from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime

class JWTAnalyzerInput(BaseToolInput):
    jwt_token: str = Field(..., description="JWT token to analyze", example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    secret_wordlist: Optional[List[str]] = Field(None, description="Custom wordlist for secret cracking")
    verify_signature: bool = Field(default=True, description="Whether to attempt signature verification")

class JWTVulnerability(BaseModel):
    name: str = Field(..., description="Vulnerability name")
    severity: str = Field(..., description="Severity level")
    description: str = Field(..., description="Detailed description")
    recommendation: str = Field(..., description="Fix recommendation")

class JWTClaim(BaseModel):
    key: str = Field(..., description="Claim key")
    value: Any = Field(..., description="Claim value")
    description: Optional[str] = Field(None, description="Claim description")

class JWTAnalyzerOutput(BaseToolOutput):
    timestamp: datetime = Field(..., description="Analysis timestamp")
    valid_format: bool = Field(..., description="Whether JWT has valid format")
    header: Optional[Dict[str, Any]] = Field(None, description="Decoded JWT header")
    payload: Optional[Dict[str, Any]] = Field(None, description="Decoded JWT payload")
    signature_verified: Optional[bool] = Field(None, description="Whether signature is verified")
    cracked_secret: Optional[str] = Field(None, description="Cracked secret if found")
    vulnerabilities: List[JWTVulnerability] = Field(default=[], description="Detected vulnerabilities")
    claims: List[JWTClaim] = Field(default=[], description="JWT claims analysis")
    recommendations: List[str] = Field(default=[], description="Security recommendations")
