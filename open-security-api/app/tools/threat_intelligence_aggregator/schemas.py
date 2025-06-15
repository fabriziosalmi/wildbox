from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime

class ThreatIntelligenceRequest(BaseModel):
    """Request model for threat intelligence aggregation"""
    indicator: str = Field(..., description="Threat indicator (IP, domain, hash, URL)")
    indicator_type: str = Field(..., description="Type of indicator: ip, domain, hash, url, email")
    sources: Optional[List[str]] = Field(
        default=["virustotal", "alienvault", "threatcrowd", "malwarebazaar"],
        description="Threat intelligence sources to query"
    )
    include_historical: bool = Field(default=True, description="Include historical threat data")
    confidence_threshold: int = Field(default=50, description="Minimum confidence score (0-100)")

class ThreatIntelligenceSource(BaseModel):
    """Threat intelligence source information"""
    name: str
    reputation_score: Optional[int] = None
    last_seen: Optional[str] = None
    first_seen: Optional[str] = None
    malware_families: List[str] = []
    threat_types: List[str] = []
    confidence: int
    source_url: Optional[str] = None

class ThreatIntelligenceResponse(BaseModel):
    """Response model for threat intelligence aggregation"""
    indicator: str
    indicator_type: str
    overall_threat_score: int
    confidence_level: str
    threat_classification: str
    
    # Aggregated intelligence
    sources_data: List[ThreatIntelligenceSource]
    malware_families: List[str]
    threat_types: List[str]
    countries: List[str]
    asn_info: Dict[str, str]
    
    # Temporal analysis
    first_seen: Optional[str]
    last_seen: Optional[str]
    activity_timeline: List[Dict[str, str]]
    
    # Risk assessment
    risk_factors: List[str]
    mitigations: List[str]
    
    # Additional context
    related_indicators: List[str]
    campaign_attribution: List[str]
    
    timestamp: str
    processing_time_ms: int
