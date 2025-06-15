"""
Schemas for Password Strength Analyzer Tool
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class PasswordStrengthInput(BaseModel):
    """Input schema for password strength analysis"""
    password: str = Field(
        description="Password to analyze"
    )
    check_common: bool = Field(
        default=True,
        description="Check against common password lists"
    )
    check_patterns: bool = Field(
        default=True,
        description="Check for common patterns (keyboard walks, sequences, etc.)"
    )
    custom_requirements: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Custom password requirements (min_length, require_uppercase, etc.)"
    )


class PasswordAnalysis(BaseModel):
    """Password analysis details"""
    length: int = Field(description="Password length")
    character_sets: Dict[str, int] = Field(description="Count of different character types")
    entropy: float = Field(description="Password entropy in bits")
    estimated_crack_time: Dict[str, str] = Field(description="Estimated crack times for different scenarios")
    patterns_found: List[str] = Field(description="Common patterns detected")
    common_password_match: Optional[str] = Field(description="Matched common password if found")


class PasswordRecommendations(BaseModel):
    """Password improvement recommendations"""
    suggestions: List[str] = Field(description="Specific improvement suggestions")
    example_strong_password: str = Field(description="Example of a strong password")
    policy_compliance: Dict[str, bool] = Field(description="Compliance with common password policies")


class PasswordStrengthOutput(BaseModel):
    """Output schema for password strength analysis"""
    success: bool = Field(description="Whether the analysis was successful")
    password_length: int = Field(description="Length of the analyzed password")
    strength_score: float = Field(description="Overall strength score (0-100)")
    strength_level: str = Field(description="Strength level (very weak, weak, fair, good, strong, very strong)")
    analysis: PasswordAnalysis = Field(description="Detailed password analysis")
    recommendations: PasswordRecommendations = Field(description="Improvement recommendations")
    is_compromised: bool = Field(description="Whether password appears in breach databases")
    meets_standards: Dict[str, bool] = Field(description="Compliance with various security standards")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")
