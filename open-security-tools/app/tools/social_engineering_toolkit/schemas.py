from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from standardized_schemas import BaseToolInput, BaseToolOutput


class SocialEngineeringToolkitInput(BaseToolInput):
    """Input schema for Social Engineering Toolkit tool"""
    target: str = Field(..., description="Target email, phone, or domain to analyze")
    analysis_type: str = Field(
        default="comprehensive",
        description="Type of analysis: email, phone, domain, or comprehensive"
    )
    include_breaches: bool = Field(
        default=True,
        description="Include data breach information in analysis"
    )


class SocialEngineeringToolkitOutput(BaseToolOutput):
    """Output schema for Social Engineering Toolkit tool"""
    target: str
    analysis_type: str
    email_analysis: Optional[Dict[str, Any]] = None
    phone_analysis: Optional[Dict[str, Any]] = None
    domain_analysis: Optional[Dict[str, Any]] = None
    breach_data: Optional[List[Dict[str, Any]]] = None
    social_profiles: Optional[List[Dict[str, Any]]] = None
    risk_score: int = Field(..., description="Risk score from 1-100")
    recommendations: List[str]
    timestamp: str
    success: bool
    message: str
