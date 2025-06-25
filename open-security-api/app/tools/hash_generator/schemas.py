"""
Schemas for Hash Generator Tool
"""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any
from datetime import datetime


class HashGeneratorInput(BaseToolInput):
    """Input schema for hash generation"""
    input_text: str = Field(
        description="Text to generate hashes for"
    )
    hash_types: List[str] = Field(
        default=["md5", "sha1", "sha256", "sha512"],
        description="List of hash types to generate (md5, sha1, sha224, sha256, sha384, sha512, blake2b, blake2s)"
    )
    include_salted: bool = Field(
        default=False,
        description="Include salted hashes"
    )
    salt: Optional[str] = Field(
        default=None,
        description="Custom salt for salted hashes (random if not provided)"
    )
    iterations: int = Field(
        default=1,
        ge=1,
        le=1000000,
        description="Number of iterations for PBKDF2 (for salted hashes)"
    )
    output_format: str = Field(
        default="hex",
        description="Output format (hex, base64, raw)"
    )


class HashResult(BaseModel):
    """Individual hash result"""
    algorithm: str = Field(description="Hash algorithm used")
    hash_value: str = Field(description="Generated hash value")
    salt_used: Optional[str] = Field(description="Salt used (if applicable)")
    iterations: Optional[int] = Field(description="Iterations used (if applicable)")
    execution_time: float = Field(description="Execution time in milliseconds")


class HashAnalysis(BaseModel):
    """Hash analysis and security information"""
    input_length: int = Field(description="Length of input text")
    entropy: float = Field(description="Estimated entropy of input")
    strength_analysis: Dict[str, str] = Field(description="Strength analysis for each hash type")
    collision_resistance: Dict[str, str] = Field(description="Collision resistance ratings")
    recommended_algorithms: List[str] = Field(description="Recommended algorithms for security")
    deprecated_algorithms: List[str] = Field(description="Deprecated/weak algorithms detected")


class HashGeneratorOutput(BaseToolOutput):
    """Output schema for hash generation"""
    success: bool = Field(description="Whether hash generation was successful")
    input_text: str = Field(description="Original input text")
    hash_results: List[HashResult] = Field(description="Generated hash results")
    analysis: HashAnalysis = Field(description="Hash analysis and recommendations")
    total_execution_time: float = Field(description="Total execution time in milliseconds")
    timestamp: datetime = Field(description="Generation timestamp")
    error: Optional[str] = Field(default=None, description="Error message if generation failed")
