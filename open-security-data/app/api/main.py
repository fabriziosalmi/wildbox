"""
FastAPI application for serving security data
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Query, Path, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
import uvicorn
import json

from app.config import get_config
from app.models import Source, Indicator, IPAddress, Domain, FileHash, CollectionRun
from app.utils.database import get_db_session, create_tables
from app.schemas.api import *

logger = logging.getLogger(__name__)
config = get_config()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting Open Security Data API")
    create_tables()
    logger.info("Database tables created/verified")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Open Security Data API")

# Create FastAPI app
app = FastAPI(
    title="Open Security Data API",
    description="Security data lake API providing threat intelligence and IOCs",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

if config.api.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Dependency to get database session
def get_db():
    """Get database session"""
    db = get_db_session()
    try:
        yield db
    finally:
        db.close()

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0"
    }

# Statistics endpoint
@app.get("/api/v1/stats", response_model=SystemStats, tags=["Statistics"])
async def get_statistics(db: Session = Depends(get_db)):
    """Get system statistics"""
    
    # Count indicators by type
    indicator_counts = db.query(
        Indicator.indicator_type,
        func.count(Indicator.id).label('count')
    ).filter(
        Indicator.active == True
    ).group_by(Indicator.indicator_type).all()
    
    indicator_stats = {item.indicator_type: item.count for item in indicator_counts}
    
    # Count sources
    active_sources = db.query(func.count(Source.id)).filter(Source.enabled == True).scalar()
    total_sources = db.query(func.count(Source.id)).scalar()
    
    # Total indicators
    total_indicators = db.query(func.count(Indicator.id)).filter(Indicator.active == True).scalar()
    
    # Recent collection runs
    recent_collections = db.query(func.count(CollectionRun.id)).filter(
        CollectionRun.started_at >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).scalar()
    
    return SystemStats(
        total_indicators=total_indicators,
        indicator_types=indicator_stats,
        total_sources=total_sources,
        active_sources=active_sources,
        recent_collections=recent_collections,
        timestamp=datetime.now(timezone.utc)
    )

# Search indicators endpoint
@app.get("/api/v1/indicators/search", response_model=IndicatorSearchResponse, tags=["Indicators"])
async def search_indicators(
    q: Optional[str] = Query(None, description="Search query"),
    indicator_type: Optional[str] = Query(None, description="Filter by indicator type"),
    threat_types: Optional[List[str]] = Query(None, description="Filter by threat types"),
    confidence: Optional[str] = Query(None, description="Filter by confidence level"),
    min_severity: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity"),
    max_severity: Optional[int] = Query(None, ge=1, le=10, description="Maximum severity"),
    source_id: Optional[str] = Query(None, description="Filter by source ID"),
    since: Optional[datetime] = Query(None, description="Show indicators since this date"),
    active_only: bool = Query(True, description="Show only active indicators"),
    limit: int = Query(100, ge=1, le=10000, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db)
):
    """Search security indicators"""
    
    query = db.query(Indicator)
    
    # Apply filters
    if active_only:
        query = query.filter(Indicator.active == True)
    
    if q:
        # Search in value, description, and tags
        search_filter = or_(
            Indicator.value.ilike(f"%{q}%"),
            Indicator.normalized_value.ilike(f"%{q}%"),
            Indicator.description.ilike(f"%{q}%")
        )
        query = query.filter(search_filter)
    
    if indicator_type:
        query = query.filter(Indicator.indicator_type == indicator_type.lower())
    
    if threat_types:
        # Search for indicators with any of the specified threat types
        for threat_type in threat_types:
            query = query.filter(Indicator.threat_types.contains([threat_type.lower()]))
    
    if confidence:
        query = query.filter(Indicator.confidence == confidence.lower())
    
    if min_severity is not None:
        query = query.filter(Indicator.severity >= min_severity)
    
    if max_severity is not None:
        query = query.filter(Indicator.severity <= max_severity)
    
    if source_id:
        query = query.filter(Indicator.source_id == source_id)
    
    if since:
        query = query.filter(Indicator.last_seen >= since)
    
    # Get total count before pagination
    total = query.count()
    
    # Apply pagination and ordering
    indicators = query.order_by(desc(Indicator.last_seen)).offset(offset).limit(limit).all()
    
    return IndicatorSearchResponse(
        indicators=indicators,
        total=total,
        limit=limit,
        offset=offset,
        query_time=datetime.now(timezone.utc)
    )

# Get specific indicator
@app.get("/api/v1/indicators/{indicator_id}", response_model=IndicatorDetail, tags=["Indicators"])
async def get_indicator(
    indicator_id: str = Path(..., description="Indicator ID"),
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific indicator"""
    
    indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Indicator not found"
        )
    
    # Get enrichment data based on type
    enrichment_data = {}
    
    if indicator.indicator_type == 'ip_address':
        ip_data = db.query(IPAddress).filter(IPAddress.indicator_id == indicator.id).first()
        if ip_data:
            enrichment_data = {
                'ip_version': ip_data.ip_version,
                'asn': ip_data.asn,
                'asn_organization': ip_data.asn_organization,
                'country_code': ip_data.country_code,
                'city': ip_data.city,
                'coordinates': {
                    'latitude': ip_data.latitude,
                    'longitude': ip_data.longitude
                } if ip_data.latitude and ip_data.longitude else None
            }
    
    elif indicator.indicator_type == 'domain':
        domain_data = db.query(Domain).filter(Domain.indicator_id == indicator.id).first()
        if domain_data:
            enrichment_data = {
                'tld': domain_data.tld,
                'subdomain': domain_data.subdomain,
                'apex_domain': domain_data.apex_domain,
                'registrar': domain_data.registrar,
                'creation_date': domain_data.creation_date,
                'expiration_date': domain_data.expiration_date,
                'dns_resolves': domain_data.dns_resolves,
                'ip_addresses': domain_data.ip_addresses,
                'mx_records': domain_data.mx_records,
                'ns_records': domain_data.ns_records
            }
    
    elif indicator.indicator_type == 'file_hash':
        hash_data = db.query(FileHash).filter(FileHash.indicator_id == indicator.id).first()
        if hash_data:
            enrichment_data = {
                'hash_type': hash_data.hash_type,
                'file_name': hash_data.file_name,
                'file_size': hash_data.file_size,
                'file_type': hash_data.file_type,
                'mime_type': hash_data.mime_type,
                'malware_family': hash_data.malware_family,
                'signature_names': hash_data.signature_names,
                'detection_ratio': hash_data.detection_ratio
            }
    
    return IndicatorDetail(
        **indicator.__dict__,
        enrichment=enrichment_data
    )

# Bulk lookup endpoint
@app.post("/api/v1/indicators/lookup", response_model=BulkLookupResponse, tags=["Indicators"])
async def bulk_lookup(
    request: BulkLookupRequest,
    db: Session = Depends(get_db)
):
    """Perform bulk lookup of indicators"""
    
    if len(request.indicators) > config.security.max_batch_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many indicators. Maximum allowed: {config.security.max_batch_size}"
        )
    
    results = []
    
    for item in request.indicators:
        # Find matching indicators
        query = db.query(Indicator).filter(
            and_(
                Indicator.indicator_type == item.indicator_type.lower(),
                or_(
                    Indicator.value == item.value,
                    Indicator.normalized_value == item.value.lower().strip()
                ),
                Indicator.active == True
            )
        )
        
        matches = query.all()
        
        results.append(LookupResult(
            indicator_type=item.indicator_type,
            value=item.value,
            found=len(matches) > 0,
            matches=matches
        ))
    
    return BulkLookupResponse(
        results=results,
        total_queried=len(request.indicators),
        total_found=sum(1 for r in results if r.found),
        query_time=datetime.now(timezone.utc)
    )

# IP-specific endpoints
@app.get("/api/v1/ips/{ip_address}", response_model=IPIntelligence, tags=["IP Intelligence"])
async def get_ip_intelligence(
    ip_address: str = Path(..., description="IP address"),
    db: Session = Depends(get_db)
):
    """Get intelligence about an IP address"""
    
    # Find IP indicators
    indicators = db.query(Indicator).filter(
        and_(
            Indicator.indicator_type == 'ip_address',
            or_(
                Indicator.value == ip_address,
                Indicator.normalized_value == ip_address
            ),
            Indicator.active == True
        )
    ).all()
    
    if not indicators:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IP address not found in threat intelligence"
        )
    
    # Get enrichment data
    enrichment = None
    if indicators:
        ip_data = db.query(IPAddress).filter(
            IPAddress.indicator_id == indicators[0].id
        ).first()
        
        if ip_data:
            enrichment = {
                'asn': ip_data.asn,
                'asn_organization': ip_data.asn_organization,
                'country_code': ip_data.country_code,
                'city': ip_data.city,
                'coordinates': {
                    'latitude': ip_data.latitude,
                    'longitude': ip_data.longitude
                } if ip_data.latitude and ip_data.longitude else None
            }
    
    return IPIntelligence(
        ip_address=ip_address,
        threat_count=len(indicators),
        indicators=indicators,
        enrichment=enrichment,
        query_time=datetime.now(timezone.utc)
    )

# Domain-specific endpoints
@app.get("/api/v1/domains/{domain}", response_model=DomainIntelligence, tags=["Domain Intelligence"])
async def get_domain_intelligence(
    domain: str = Path(..., description="Domain name"),
    db: Session = Depends(get_db)
):
    """Get intelligence about a domain"""
    
    # Normalize domain for search
    normalized_domain = domain.lower().strip()
    
    # Find domain indicators
    indicators = db.query(Indicator).filter(
        and_(
            Indicator.indicator_type == 'domain',
            or_(
                Indicator.value == domain,
                Indicator.normalized_value == normalized_domain
            ),
            Indicator.active == True
        )
    ).all()
    
    if not indicators:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found in threat intelligence"
        )
    
    # Get enrichment data
    enrichment = None
    if indicators:
        domain_data = db.query(Domain).filter(
            Domain.indicator_id == indicators[0].id
        ).first()
        
        if domain_data:
            enrichment = {
                'tld': domain_data.tld,
                'registrar': domain_data.registrar,
                'creation_date': domain_data.creation_date,
                'expiration_date': domain_data.expiration_date,
                'ip_addresses': domain_data.ip_addresses,
                'mx_records': domain_data.mx_records,
                'ns_records': domain_data.ns_records
            }
    
    return DomainIntelligence(
        domain=domain,
        threat_count=len(indicators),
        indicators=indicators,
        enrichment=enrichment,
        query_time=datetime.now(timezone.utc)
    )

# Hash-specific endpoints
@app.get("/api/v1/hashes/{file_hash}", response_model=HashIntelligence, tags=["File Intelligence"])
async def get_hash_intelligence(
    file_hash: str = Path(..., description="File hash"),
    db: Session = Depends(get_db)
):
    """Get intelligence about a file hash"""
    
    # Normalize hash
    normalized_hash = file_hash.lower().strip()
    
    # Find hash indicators
    indicators = db.query(Indicator).filter(
        and_(
            Indicator.indicator_type == 'file_hash',
            or_(
                Indicator.value == file_hash,
                Indicator.normalized_value == normalized_hash
            ),
            Indicator.active == True
        )
    ).all()
    
    if not indicators:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File hash not found in threat intelligence"
        )
    
    # Get enrichment data
    enrichment = None
    if indicators:
        hash_data = db.query(FileHash).filter(
            FileHash.indicator_id == indicators[0].id
        ).first()
        
        if hash_data:
            enrichment = {
                'hash_type': hash_data.hash_type,
                'file_name': hash_data.file_name,
                'file_size': hash_data.file_size,
                'file_type': hash_data.file_type,
                'malware_family': hash_data.malware_family,
                'signature_names': hash_data.signature_names,
                'detection_ratio': hash_data.detection_ratio
            }
    
    return HashIntelligence(
        file_hash=file_hash,
        threat_count=len(indicators),
        indicators=indicators,
        enrichment=enrichment,
        query_time=datetime.now(timezone.utc)
    )

# Sources endpoint
@app.get("/api/v1/sources", response_model=List[SourceInfo], tags=["Sources"])
async def list_sources(
    enabled_only: bool = Query(True, description="Show only enabled sources"),
    db: Session = Depends(get_db)
):
    """List data sources"""
    
    query = db.query(Source)
    
    if enabled_only:
        query = query.filter(Source.enabled == True)
    
    sources = query.order_by(Source.name).all()
    
    return [SourceInfo(
        id=str(source.id),
        name=source.name,
        description=source.description,
        source_type=source.source_type,
        enabled=source.enabled,
        status=source.status,
        last_collection=source.last_collection,
        collection_count=source.collection_count,
        error_count=source.error_count
    ) for source in sources]

# Real-time feed endpoint
@app.get("/api/v1/feeds/realtime", tags=["Feeds"])
async def realtime_feed(
    indicator_types: Optional[List[str]] = Query(None, description="Filter by indicator types"),
    threat_types: Optional[List[str]] = Query(None, description="Filter by threat types"),
    min_severity: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity"),
    since_minutes: int = Query(60, ge=1, le=1440, description="Minutes to look back"),
    db: Session = Depends(get_db)
):
    """Real-time threat intelligence feed"""
    
    since_time = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    
    query = db.query(Indicator).filter(
        and_(
            Indicator.last_seen >= since_time,
            Indicator.active == True
        )
    )
    
    if indicator_types:
        query = query.filter(Indicator.indicator_type.in_([t.lower() for t in indicator_types]))
    
    if threat_types:
        for threat_type in threat_types:
            query = query.filter(Indicator.threat_types.contains([threat_type.lower()]))
    
    if min_severity is not None:
        query = query.filter(Indicator.severity >= min_severity)
    
    indicators = query.order_by(desc(Indicator.last_seen)).limit(1000).all()
    
    def generate_feed():
        for indicator in indicators:
            yield json.dumps({
                'id': str(indicator.id),
                'indicator_type': indicator.indicator_type,
                'value': indicator.value,
                'threat_types': indicator.threat_types,
                'confidence': indicator.confidence,
                'severity': indicator.severity,
                'description': indicator.description,
                'tags': indicator.tags,
                'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else None,
                'last_seen': indicator.last_seen.isoformat() if indicator.last_seen else None,
                'source_id': str(indicator.source_id)
            }) + '\n'
    
    return StreamingResponse(
        generate_feed(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }
    )

if __name__ == "__main__":
    uvicorn.run(
        "app.api.main:app",
        host=config.api.host,
        port=config.api.port,
        workers=1,  # Use 1 worker for development
        reload=config.debug,
        log_level="info"
    )
