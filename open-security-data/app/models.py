"""
Data Models and Database Schemas

Defines the core data models for the security data lake platform.
"""

import enum
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, JSON, 
    ForeignKey, Index, UniqueConstraint, CheckConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, INET, CIDR
import uuid

Base = declarative_base()

class IndicatorType(enum.Enum):
    """Types of security indicators"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"  
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    ASN = "asn"
    VULNERABILITY = "vulnerability"

class ThreatType(enum.Enum):
    """Types of threats"""
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

class ConfidenceLevel(enum.Enum):
    """Confidence levels for threat intelligence"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"

class SourceStatus(enum.Enum):
    """Status of data sources"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"

class Source(Base):
    """Data source information"""
    __tablename__ = "sources"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    url = Column(String(1024))
    source_type = Column(String(100), nullable=False)  # feed, api, file, etc.
    
    # Configuration
    config = Column(JSON, default=dict)
    headers = Column(JSON, default=dict)
    auth_config = Column(JSON, default=dict)
    
    # Status and metrics
    status = Column(String(50), default=SourceStatus.ACTIVE.value)
    last_collection = Column(DateTime(timezone=True))
    last_success = Column(DateTime(timezone=True))
    last_error = Column(Text)
    collection_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    
    # Settings
    enabled = Column(Boolean, default=True)
    collection_interval = Column(Integer, default=3600)  # seconds
    rate_limit = Column(Integer, default=100)  # requests per window
    rate_limit_window = Column(Integer, default=3600)  # seconds
    timeout = Column(Integer, default=300)  # seconds
    retry_attempts = Column(Integer, default=3)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), 
                       onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    indicators = relationship("Indicator", back_populates="source")
    
    # Indexes
    __table_args__ = (
        Index("idx_sources_name", "name"),
        Index("idx_sources_status", "status"),
        Index("idx_sources_enabled", "enabled"),
    )

class Indicator(Base):
    """Security indicators (IOCs)"""
    __tablename__ = "indicators"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id = Column(UUID(as_uuid=True), ForeignKey("sources.id"), nullable=False)
    
    # Core indicator data
    indicator_type = Column(String(50), nullable=False)
    value = Column(String(1024), nullable=False)
    normalized_value = Column(String(1024), nullable=False)  # Normalized for deduplication
    
    # Threat classification
    threat_types = Column(JSON, default=list)  # List of threat types
    confidence = Column(String(20), default=ConfidenceLevel.MEDIUM.value)
    severity = Column(Integer, default=5)  # 1-10 scale
    
    # Metadata
    description = Column(Text)
    tags = Column(JSON, default=list)
    indicator_metadata = Column(JSON, default=dict)  # Renamed from metadata to avoid SQLAlchemy conflict
    
    # Temporal information
    first_seen = Column(DateTime(timezone=True), nullable=False,
                       default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), nullable=False,
                      default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True))
    
    # Status
    active = Column(Boolean, default=True)
    false_positive = Column(Boolean, default=False)
    whitelisted = Column(Boolean, default=False)
    
    # Collection info
    raw_data = Column(JSON)  # Original data from source
    collection_date = Column(DateTime(timezone=True), nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                       onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    source = relationship("Source", back_populates="indicators")
    enrichments = relationship("Enrichment", back_populates="indicator")
    
    # Indexes and constraints
    __table_args__ = (
        Index("idx_indicators_type_value", "indicator_type", "normalized_value"),
        Index("idx_indicators_source", "source_id"),
        Index("idx_indicators_first_seen", "first_seen"),
        Index("idx_indicators_last_seen", "last_seen"),
        Index("idx_indicators_active", "active"),
        Index("idx_indicators_confidence", "confidence"),
        Index("idx_indicators_expires", "expires_at"),
        UniqueConstraint("source_id", "indicator_type", "normalized_value", 
                        name="uq_source_indicator"),
        CheckConstraint("severity >= 1 AND severity <= 10", name="ck_severity_range"),
    )

class Enrichment(Base):
    """Enrichment data for indicators"""
    __tablename__ = "enrichments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id"), nullable=False)
    
    # Enrichment details
    enrichment_type = Column(String(100), nullable=False)  # geolocation, asn, whois, etc.
    data = Column(JSON, nullable=False)
    source = Column(String(255))  # Enrichment source
    
    # Quality and status
    confidence = Column(String(20), default=ConfidenceLevel.MEDIUM.value)
    expires_at = Column(DateTime(timezone=True))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                       onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    indicator = relationship("Indicator", back_populates="enrichments")
    
    # Indexes
    __table_args__ = (
        Index("idx_enrichments_indicator", "indicator_id"),
        Index("idx_enrichments_type", "enrichment_type"),
        Index("idx_enrichments_expires", "expires_at"),
        UniqueConstraint("indicator_id", "enrichment_type", "source",
                        name="uq_indicator_enrichment"),
    )

class IPAddress(Base):
    """Specialized table for IP address indicators"""
    __tablename__ = "ip_addresses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id"), nullable=False)
    
    # IP-specific data
    ip_address = Column(INET, nullable=False)
    ip_version = Column(Integer, nullable=False)  # 4 or 6
    
    # Network information
    asn = Column(Integer)
    asn_organization = Column(String(255))
    country_code = Column(String(2))
    city = Column(String(255))
    latitude = Column(String(20))
    longitude = Column(String(20))
    
    # Network ranges
    network_range = Column(CIDR)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                       onupdate=lambda: datetime.now(timezone.utc))
    
    # Indexes
    __table_args__ = (
        Index("idx_ip_addresses_ip", "ip_address"),
        Index("idx_ip_addresses_asn", "asn"),
        Index("idx_ip_addresses_country", "country_code"),
        Index("idx_ip_addresses_network", "network_range"),
        UniqueConstraint("indicator_id", name="uq_ip_indicator"),
    )

class Domain(Base):
    """Specialized table for domain indicators"""
    __tablename__ = "domains"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id"), nullable=False)
    
    # Domain-specific data
    domain = Column(String(255), nullable=False)
    tld = Column(String(50))
    subdomain = Column(String(255))
    apex_domain = Column(String(255))
    
    # DNS information
    dns_resolves = Column(Boolean)
    ip_addresses = Column(JSON, default=list)
    mx_records = Column(JSON, default=list)
    ns_records = Column(JSON, default=list)
    
    # Registration information
    registrar = Column(String(255))
    creation_date = Column(DateTime(timezone=True))
    expiration_date = Column(DateTime(timezone=True))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                       onupdate=lambda: datetime.now(timezone.utc))
    
    # Indexes
    __table_args__ = (
        Index("idx_domains_domain", "domain"),
        Index("idx_domains_tld", "tld"),
        Index("idx_domains_apex", "apex_domain"),
        Index("idx_domains_creation", "creation_date"),
        Index("idx_domains_expiration", "expiration_date"),
        UniqueConstraint("indicator_id", name="uq_domain_indicator"),
    )

class FileHash(Base):
    """Specialized table for file hash indicators"""
    __tablename__ = "file_hashes"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id"), nullable=False)
    
    # Hash-specific data
    hash_value = Column(String(128), nullable=False)
    hash_type = Column(String(10), nullable=False)  # md5, sha1, sha256, etc.
    
    # File information
    file_name = Column(String(1024))
    file_size = Column(Integer)
    file_type = Column(String(100))
    mime_type = Column(String(100))
    
    # Analysis results
    malware_family = Column(String(255))
    signature_names = Column(JSON, default=list)
    detection_ratio = Column(String(20))  # e.g., "45/67"
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                       onupdate=lambda: datetime.now(timezone.utc))
    
    # Indexes
    __table_args__ = (
        Index("idx_file_hashes_hash", "hash_value"),
        Index("idx_file_hashes_type", "hash_type"),
        Index("idx_file_hashes_family", "malware_family"),
        UniqueConstraint("indicator_id", name="uq_filehash_indicator"),
    )

class CollectionRun(Base):
    """Track collection runs and their results"""
    __tablename__ = "collection_runs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id = Column(UUID(as_uuid=True), ForeignKey("sources.id"), nullable=False)
    
    # Run information
    started_at = Column(DateTime(timezone=True), nullable=False,
                       default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)
    
    # Results
    status = Column(String(50), nullable=False)  # running, completed, failed
    items_collected = Column(Integer, default=0)
    items_new = Column(Integer, default=0)
    items_updated = Column(Integer, default=0)
    items_skipped = Column(Integer, default=0)
    items_failed = Column(Integer, default=0)
    
    # Error information
    error_message = Column(Text)
    error_details = Column(JSON)
    
    # Metadata
    metadata = Column(JSON, default=dict)
    
    # Indexes
    __table_args__ = (
        Index("idx_collection_runs_source", "source_id"),
        Index("idx_collection_runs_started", "started_at"),
        Index("idx_collection_runs_status", "status"),
    )
