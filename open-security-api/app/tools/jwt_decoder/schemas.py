"""
Schemas for JWT Decoder Tool
"""

from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime


class JWTDecoderInput(BaseToolInput):
    """Input schema for JWT decoding and analysis"""
    jwt_token: str = Field(
        description="JWT token to decode and analyze"
    )
    verify_signature: bool = Field(
        default=False,
        description="Attempt to verify the JWT signature (requires secret/key)"
    )
    secret_key: Optional[str] = Field(
        default=None,
        description="Secret key for HMAC signature verification"
    )
    public_key: Optional[str] = Field(
        default=None,
        description="Public key for RSA/ECDSA signature verification"
    )
    check_expiration: bool = Field(
        default=True,
        description="Check if the token is expired"
    )
    check_security: bool = Field(
        default=True,
        description="Perform security analysis of the token"
    )


class JWTHeader(BaseModel):
    """JWT header information"""
    algorithm: str = Field(description="Signing algorithm")
    type: str = Field(description="Token type")
    key_id: Optional[str] = Field(description="Key ID if present")
    raw_header: Dict[str, Any] = Field(description="Complete raw header")


class JWTPayload(BaseModel):
    """JWT payload information"""
    issuer: Optional[str] = Field(description="Token issuer (iss)")
    subject: Optional[str] = Field(description="Token subject (sub)")
    audience: Optional[str] = Field(description="Token audience (aud)")
    expiration: Optional[datetime] = Field(description="Expiration time (exp)")
    not_before: Optional[datetime] = Field(description="Not before time (nbf)")
    issued_at: Optional[datetime] = Field(description="Issued at time (iat)")
    jwt_id: Optional[str] = Field(description="JWT ID (jti)")
    custom_claims: Dict[str, Any] = Field(description="Custom claims in the payload")
    raw_payload: Dict[str, Any] = Field(description="Complete raw payload")


class JWTSecurityAnalysis(BaseModel):
    """JWT security analysis results"""
    algorithm_security: str = Field(description="Security level of the algorithm")
    security_issues: List[str] = Field(description="Identified security issues")
    recommendations: List[str] = Field(description="Security recommendations")
    is_expired: bool = Field(description="Whether the token is expired")
    is_premature: bool = Field(description="Whether the token is not yet valid")
    signature_valid: Optional[bool] = Field(description="Whether signature is valid (if verified)")


class JWTDecoderOutput(BaseToolOutput):
    """Output schema for JWT decoding and analysis"""
    success: bool = Field(description="Whether the decoding was successful")
    is_valid_jwt: bool = Field(description="Whether the token is a valid JWT format")
    header: Optional[JWTHeader] = Field(description="Decoded JWT header")
    payload: Optional[JWTPayload] = Field(description="Decoded JWT payload")
    signature: Optional[str] = Field(description="JWT signature (base64url encoded)")
    security_analysis: Optional[JWTSecurityAnalysis] = Field(description="Security analysis results")
    token_length: int = Field(description="Length of the JWT token")
    parts_count: int = Field(description="Number of parts in the token")
    error: Optional[str] = Field(default=None, description="Error message if decoding failed")
