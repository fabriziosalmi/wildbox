from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union

class DigitalFootprintAnalyzerInput(BaseModel):
    """Input schema for Digital Footprint Analyzer tool"""
    target_identifier: str = Field(..., description="Target identifier (email, username, phone, domain)")
    identifier_type: str = Field(default="auto", description="Type of identifier (email, username, phone, domain, auto)")
    search_depth: str = Field(default="standard", description="Search depth (quick, standard, deep)")
    include_social_media: bool = Field(default=True, description="Search social media platforms")
    include_data_breaches: bool = Field(default=True, description="Check data breach databases")
    include_domain_info: bool = Field(default=True, description="Include domain/website information")
    include_phone_info: bool = Field(default=True, description="Include phone number information")
    include_public_records: bool = Field(default=False, description="Include public records (where legal)")
    respect_privacy: bool = Field(default=True, description="Respect privacy settings and robots.txt")
    max_results_per_platform: int = Field(default=10, description="Maximum results per platform")

class SocialMediaProfile(BaseModel):
    platform: str
    username: str
    profile_url: str
    display_name: Optional[str] = None
    bio: Optional[str] = None
    followers_count: Optional[int] = None
    following_count: Optional[int] = None
    posts_count: Optional[int] = None
    verified: Optional[bool] = None
    creation_date: Optional[str] = None
    last_activity: Optional[str] = None
    profile_image_url: Optional[str] = None
    privacy_level: str = "unknown"  # public, private, limited, unknown

class DataBreachResult(BaseModel):
    breach_name: str
    breach_date: Optional[str] = None
    description: str
    data_compromised: List[str]
    severity: str  # Low, Medium, High, Critical
    verified: bool = False

class DomainInfo(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    nameservers: List[str] = []
    organization: Optional[str] = None
    email_contacts: List[str] = []
    phone_contacts: List[str] = []
    associated_domains: List[str] = []
    ssl_info: Optional[Dict[str, Any]] = None

class PhoneInfo(BaseModel):
    number: str
    carrier: Optional[str] = None
    location: Optional[str] = None
    line_type: Optional[str] = None  # mobile, landline, voip
    associated_names: List[str] = []
    spam_reports: int = 0

class OSINTFinding(BaseModel):
    category: str
    title: str
    description: str
    source: str
    confidence: str  # High, Medium, Low
    risk_level: str  # Low, Medium, High, Critical
    data_found: Dict[str, Any]
    recommendations: List[str]

class DigitalFootprintAnalyzerOutput(BaseModel):
    """Output schema for Digital Footprint Analyzer tool"""
    target_identifier: str
    identifier_type: str
    analysis_timestamp: str
    search_depth: str
    total_findings: int
    social_media_profiles: List[SocialMediaProfile]
    data_breach_results: List[DataBreachResult]
    domain_information: Optional[DomainInfo]
    phone_information: Optional[PhoneInfo]
    osint_findings: List[OSINTFinding]
    privacy_score: float  # 0-100, higher is more private
    exposure_level: str  # Low, Medium, High, Critical
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    execution_time: float

# Tool metadata
TOOL_INFO = {
    "name": "Digital Footprint Analyzer",
    "description": "Comprehensive OSINT tool for analyzing digital footprints across social media, data breaches, domains, and public records while respecting privacy",
    "category": "osint",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["osint", "social-media", "footprint", "privacy", "reconnaissance", "breach-check"]
}
