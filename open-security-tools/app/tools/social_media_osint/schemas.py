from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from standardized_schemas import BaseToolInput, BaseToolOutput


class SocialMediaOSINTInput(BaseToolInput):
    """Input schema for Social Media OSINT tool"""
    username: str = Field(..., description="Username to search across social media platforms")
    platforms: List[str] = Field(
        default=["twitter", "instagram", "linkedin", "facebook", "github", "reddit"],
        description="List of platforms to search"
    )
    deep_search: bool = Field(
        default=False,
        description="Perform deep analysis including content and connections"
    )
    include_metadata: bool = Field(
        default=True,
        description="Include metadata analysis (posting patterns, locations, etc.)"
    )


class SocialMediaOSINTOutput(BaseToolOutput):
    """Output schema for Social Media OSINT tool"""
    username: str
    platforms_searched: List[str]
    profiles_found: List[Dict[str, Any]]
    cross_platform_analysis: Dict[str, Any]
    metadata_analysis: Optional[Dict[str, Any]] = None
    risk_indicators: List[str]
    intelligence_summary: Dict[str, Any]
    timestamp: str
    success: bool
    message: str
