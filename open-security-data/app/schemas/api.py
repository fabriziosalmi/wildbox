"""
API Schema definitions using Pydantic
"""

from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field, field_validator
from enum import Enum
from uuid import UUID

class IndicatorType(str, Enum):
    """Indicator type enumeration"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    ASN = "asn"
    VULNERABILITY = "vulnerability"

class ThreatType(str, Enum):
    """Threat type enumeration"""
    MALWARE = "malware"
    PHISHING = "phishing"
    SPAM = "spam"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    VULNERABILITY = "vulnerability"
    CERTIFICATE = "certificate"
    DNS = "dns"
    NETWORK_SCAN = "network_scan"
    SUSPICIOUS = "suspicious"

class ConfidenceLevel(str, Enum):
    """Confidence level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"

class IndicatorBase(BaseModel):
    """Base indicator schema"""
    indicator_type: str = Field(..., description="Type of indicator")
    value: str = Field(..., description="Indicator value")
    threat_types: List[str] = Field(default=[], description="Associated threat types")
    confidence: str = Field(default="medium", description="Confidence level")
    severity: int = Field(default=5, ge=1, le=10, description="Severity score (1-10)")
    description: Optional[str] = Field(None, description="Human-readable description")
    tags: List[str] = Field(default=[], description="Associated tags")
    
    class Config:
        from_attributes = True

class IndicatorResponse(IndicatorBase):
    """Indicator response schema"""
    id: str = Field(..., description="Unique identifier")
    normalized_value: str = Field(..., description="Normalized indicator value")
    first_seen: Optional[datetime] = Field(None, description="First time this indicator was seen")
    last_seen: Optional[datetime] = Field(None, description="Last time this indicator was seen")
    expires_at: Optional[datetime] = Field(None, description="When this indicator expires")
    active: bool = Field(True, description="Whether this indicator is active")
    source_id: str = Field(..., description="Source that provided this indicator")
    indicator_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    created_at: Optional[datetime] = Field(None, description="When this record was created")
    updated_at: Optional[datetime] = Field(None, description="When this record was last updated")
    
    @field_validator('id', 'source_id', mode='before')
    @classmethod
    def convert_uuid_to_str(cls, v):
        """Convert UUID objects to strings"""
        if isinstance(v, UUID):
            return str(v)
        return v
    
    @field_validator('indicator_metadata', mode='before')
    @classmethod
    def handle_null_metadata(cls, v):
        """Convert None to empty dict for metadata"""
        return v if v is not None else {}

class IndicatorDetail(IndicatorResponse):
    """Detailed indicator information"""
    enrichment: Dict[str, Any] = Field(default={}, description="Enrichment data")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Original raw data")

class IndicatorSearchResponse(BaseModel):
    """Response for indicator search"""
    indicators: List[IndicatorResponse] = Field(..., description="Found indicators")
    total: int = Field(..., description="Total number of matching indicators")
    limit: int = Field(..., description="Limit applied to results")
    offset: int = Field(..., description="Offset applied to results")
    query_time: datetime = Field(..., description="When the query was executed")

class BulkLookupItem(BaseModel):
    """Item for bulk lookup request"""
    indicator_type: IndicatorType = Field(..., description="Type of indicator")
    value: str = Field(..., description="Indicator value to lookup")

class BulkLookupRequest(BaseModel):
    """Bulk lookup request schema"""
    indicators: List[BulkLookupItem] = Field(..., description="Indicators to lookup")

class LookupResult(BaseModel):
    """Result for individual lookup"""
    indicator_type: str = Field(..., description="Type of indicator")
    value: str = Field(..., description="Indicator value")
    found: bool = Field(..., description="Whether indicator was found")
    matches: List[IndicatorResponse] = Field(default=[], description="Matching indicators")

class BulkLookupResponse(BaseModel):
    """Response for bulk lookup"""
    results: List[LookupResult] = Field(..., description="Lookup results")
    total_queried: int = Field(..., description="Total indicators queried")
    total_found: int = Field(..., description="Total indicators found")
    query_time: datetime = Field(..., description="When the query was executed")

class SystemStats(BaseModel):
    """System statistics"""
    total_indicators: int = Field(..., description="Total number of active indicators")
    indicator_types: Dict[str, int] = Field(..., description="Count by indicator type")
    total_sources: int = Field(..., description="Total number of sources")
    active_sources: int = Field(..., description="Number of active sources")
    recent_collections: int = Field(..., description="Collections in last 24 hours")
    timestamp: datetime = Field(..., description="When these stats were generated")

class SourceInfo(BaseModel):
    """Source information"""
    id: str = Field(..., description="Source ID")
    name: str = Field(..., description="Source name")
    description: Optional[str] = Field(None, description="Source description")
    source_type: str = Field(..., description="Type of source")
    enabled: bool = Field(..., description="Whether source is enabled")
    status: str = Field(..., description="Current status")
    last_collection: Optional[datetime] = Field(None, description="Last collection time")
    collection_count: int = Field(..., description="Total collections performed")
    error_count: int = Field(..., description="Number of errors encountered")

class IPIntelligence(BaseModel):
    """IP address intelligence"""
    ip_address: str = Field(..., description="IP address")
    threat_count: int = Field(..., description="Number of threat indicators")
    indicators: List[IndicatorResponse] = Field(..., description="Associated indicators")
    enrichment: Optional[Dict[str, Any]] = Field(None, description="Enrichment data")
    query_time: datetime = Field(..., description="When the query was executed")

class DomainIntelligence(BaseModel):
    """Domain intelligence"""
    domain: str = Field(..., description="Domain name")
    threat_count: int = Field(..., description="Number of threat indicators")
    indicators: List[IndicatorResponse] = Field(..., description="Associated indicators")
    enrichment: Optional[Dict[str, Any]] = Field(None, description="Enrichment data")
    query_time: datetime = Field(..., description="When the query was executed")

class HashIntelligence(BaseModel):
    """File hash intelligence"""
    file_hash: str = Field(..., description="File hash")
    threat_count: int = Field(..., description="Number of threat indicators")
    indicators: List[IndicatorResponse] = Field(..., description="Associated indicators")
    enrichment: Optional[Dict[str, Any]] = Field(None, description="Enrichment data")
    query_time: datetime = Field(..., description="When the query was executed")

class URLIntelligence(BaseModel):
    """URL intelligence"""
    url: str = Field(..., description="URL")
    threat_count: int = Field(..., description="Number of threat indicators")
    indicators: List[IndicatorResponse] = Field(..., description="Associated indicators")
    enrichment: Optional[Dict[str, Any]] = Field(None, description="Enrichment data")
    query_time: datetime = Field(..., description="When the query was executed")

class ThreatFeed(BaseModel):
    """Real-time threat feed item"""
    id: str = Field(..., description="Indicator ID")
    indicator_type: str = Field(..., description="Type of indicator")
    value: str = Field(..., description="Indicator value")
    threat_types: List[str] = Field(..., description="Associated threat types")
    confidence: str = Field(..., description="Confidence level")
    severity: int = Field(..., description="Severity score")
    description: Optional[str] = Field(None, description="Description")
    tags: List[str] = Field(..., description="Tags")
    first_seen: Optional[datetime] = Field(None, description="First seen timestamp")
    last_seen: Optional[datetime] = Field(None, description="Last seen timestamp")
    source_id: str = Field(..., description="Source ID")

class ErrorResponse(BaseModel):
    """Error response schema"""
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    timestamp: datetime = Field(..., description="Error timestamp")

class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Health status")
    timestamp: datetime = Field(..., description="Check timestamp")
    version: str = Field(..., description="API version")

# Telemetry Schemas
class TelemetryEventType(str, Enum):
    """Telemetry event type enumeration"""
    PROCESS_EVENT = "process_event"
    NETWORK_CONNECTION = "network_connection"
    FILE_CHANGE = "file_change"
    USER_EVENT = "user_event"
    SYSTEM_INVENTORY = "system_inventory"
    AUTHENTICATION = "authentication"
    SECURITY_EVENT = "security_event"

class TelemetryEventBase(BaseModel):
    """Base telemetry event schema"""
    sensor_id: str = Field(..., description="Unique sensor identifier")
    event_type: TelemetryEventType = Field(..., description="Type of telemetry event")
    timestamp: datetime = Field(..., description="Event timestamp")
    source_host: Optional[str] = Field(None, description="Source host/system")
    event_data: Dict[str, Any] = Field(..., description="Event-specific data")
    raw_data: Optional[str] = Field(None, description="Raw event data")
    severity: int = Field(default=1, ge=1, le=10, description="Event severity (1-10)")
    tags: List[str] = Field(default=[], description="Event tags")

class TelemetryEventCreate(TelemetryEventBase):
    """Schema for creating telemetry events"""
    pass

class TelemetryEvent(TelemetryEventBase):
    """Schema for telemetry event response"""
    id: str = Field(..., description="Event ID")
    ingested_at: datetime = Field(..., description="Ingestion timestamp")
    processed: bool = Field(..., description="Processing status")
    processed_at: Optional[datetime] = Field(None, description="Processing timestamp")
    
    class Config:
        from_attributes = True

class TelemetryBatch(BaseModel):
    """Schema for batch telemetry ingestion"""
    events: List[TelemetryEventCreate] = Field(..., description="List of telemetry events")
    batch_id: Optional[str] = Field(None, description="Optional batch identifier")

class TelemetryBatchResponse(BaseModel):
    """Response for batch telemetry ingestion"""
    batch_id: str = Field(..., description="Batch identifier")
    events_received: int = Field(..., description="Number of events received")
    events_ingested: int = Field(..., description="Number of events successfully ingested")
    errors: List[str] = Field(default=[], description="Ingestion errors")
    ingested_at: datetime = Field(..., description="Ingestion timestamp")

class SensorMetadataBase(BaseModel):
    """Base sensor metadata schema"""
    sensor_id: str = Field(..., description="Unique sensor identifier")
    hostname: Optional[str] = Field(None, description="Sensor hostname")
    platform: Optional[str] = Field(None, description="Sensor platform")
    sensor_version: Optional[str] = Field(None, description="Sensor version")
    config: Dict[str, Any] = Field(default={}, description="Sensor configuration")

class SensorMetadata(SensorMetadataBase):
    """Schema for sensor metadata response"""
    id: str = Field(..., description="Metadata record ID")
    first_seen: datetime = Field(..., description="First registration time")
    last_seen: datetime = Field(..., description="Last seen time")
    active: bool = Field(..., description="Sensor active status")
    total_events: int = Field(..., description="Total events received")
    last_event_at: Optional[datetime] = Field(None, description="Last event timestamp")
    
    class Config:
        from_attributes = True

# Update exports - only include actually defined classes
__all__ = [
    'IndicatorType',
    'ThreatType', 
    'ConfidenceLevel',
    'IndicatorBase',
    'IndicatorResponse',
    'IndicatorDetail',
    'IndicatorSearchResponse',
    'BulkLookupItem',
    'BulkLookupRequest',
    'LookupResult',
    'BulkLookupResponse',
    'SystemStats',
    'SourceInfo',
    'IPIntelligence',
    'DomainIntelligence',
    'HashIntelligence',
    'URLIntelligence',
    'ThreatFeed',
    'TelemetryEventType',
    'TelemetryEventBase',
    'TelemetryEventCreate',
    'TelemetryEvent',
    'TelemetryBatch',
    'TelemetryBatchResponse',
    'SensorMetadataBase',
    'SensorMetadata',
    'ErrorResponse',
    'HealthResponse'
]
