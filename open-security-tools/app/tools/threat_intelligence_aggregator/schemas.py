from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import Dict, List, Literal, Optional
from datetime import datetime

class ThreatIntelligenceRequest(BaseToolInput):
    """Request model for threat intelligence aggregation"""
    indicator: str = Field(..., description="Threat indicator (IP, domain, hash, URL, email)", examples=["8.8.8.8"])
    # The types main.py validates; another one raised out of execute_tool
    # (#611).
    indicator_type: Literal["ip", "domain", "hash", "url", "email"] = Field(
        ..., description="Type of indicator: ip, domain, hash, url, email", examples=["ip"]
    )
    # The sources main.py queries. The default listed malwarebazaar, which is
    # not implemented and was skipped silently, and null crashed the lookup
    # (#611).
    sources: List[Literal["virustotal", "alienvault", "threatcrowd"]] = Field(
        default=["virustotal", "alienvault", "threatcrowd"],
        min_length=1,
        description="Threat intelligence sources to query (virustotal, alienvault, threatcrowd)"
    )
    include_historical: bool = Field(default=True, description="Include historical threat data")
    confidence_threshold: int = Field(default=50, ge=0, le=100, description="Minimum confidence score (0-100)")

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

class ThreatIntelligenceResponse(BaseToolOutput):
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
