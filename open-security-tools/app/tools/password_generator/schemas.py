"""
Schemas for Password Generator Tool
"""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import Optional, List


class PasswordGeneratorInput(BaseToolInput):
    """Input schema for password generation"""
    length: int = Field(
        default=12,
        ge=4,
        le=128,
        description="Length of the password (4-128 characters)"
    )
    include_uppercase: bool = Field(
        default=True,
        description="Include uppercase letters (A-Z)"
    )
    include_lowercase: bool = Field(
        default=True,
        description="Include lowercase letters (a-z)"
    )
    include_numbers: bool = Field(
        default=True,
        description="Include numbers (0-9)"
    )
    include_symbols: bool = Field(
        default=True,
        description="Include special symbols (!@#$%^&*)"
    )
    exclude_ambiguous: bool = Field(
        default=False,
        description="Exclude ambiguous characters (0, O, l, 1, I)"
    )
    custom_symbols: Optional[str] = Field(
        default=None,
        description="Custom symbol set to use instead of default"
    )
    count: int = Field(
        default=1,
        ge=1,
        le=50,
        description="Number of passwords to generate (1-50)"
    )
    require_all_types: bool = Field(
        default=True,
        description="Ensure password contains at least one character from each selected type"
    )


class PasswordStrengthAnalysis(BaseModel):
    """Password strength analysis"""
    score: int = Field(description="Strength score (0-100)")
    strength_level: str = Field(description="Strength level (Weak, Fair, Good, Strong, Excellent)")
    entropy: float = Field(description="Password entropy in bits")
    estimated_crack_time: str = Field(description="Estimated time to crack")
    feedback: List[str] = Field(description="Feedback and suggestions")


class PasswordGeneratorOutput(BaseToolOutput):
    """Output schema for password generation"""
    success: bool = Field(description="Whether the generation was successful")
    passwords: List[str] = Field(description="Generated passwords")
    strength_analysis: List[PasswordStrengthAnalysis] = Field(
        description="Strength analysis for each password"
    )
    character_sets_used: List[str] = Field(description="Character sets used in generation")
    total_possible_combinations: str = Field(description="Total possible combinations")
    error: Optional[str] = Field(default=None, description="Error message if generation failed")
