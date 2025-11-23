"""
Data Collection Framework

Core framework for collecting security data from various public sources.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Iterator, Union
from dataclasses import dataclass
from enum import Enum

import aiohttp
import feedparser
from sqlalchemy.orm import Session

from app.config import get_config
from app.models import Source, Indicator, CollectionRun
from app.utils.database import get_db_session
from app.utils.rate_limiter import RateLimiter
from app.utils.validators import validate_indicator
from app.utils.normalizers import normalize_indicator

logger = logging.getLogger(__name__)
config = get_config()

class CollectionStatus(Enum):
    """Collection status enumeration"""
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"

@dataclass
class CollectionResult:
    """Result of a collection operation"""
    status: CollectionStatus
    items_collected: int = 0
    items_new: int = 0
    items_updated: int = 0
    items_skipped: int = 0
    items_failed: int = 0
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    duration_seconds: Optional[float] = None

class BaseCollector(ABC):
    """Base class for all data collectors"""
    
    def __init__(self, source: Source):
        self.source = source
        self.config = source.config or {}
        self.rate_limiter = RateLimiter(
            max_requests=source.rate_limit,
            time_window=source.rate_limit_window
        )
        self.session: Optional[aiohttp.ClientSession] = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        timeout = aiohttp.ClientTimeout(total=self.source.timeout)
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        
        headers = {
            'User-Agent': 'Open-Security-Data/1.0 (+https://github.com/wildbox/open-security-data)',
            **self.source.headers
        }
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def collect_data(self):
        """Collect data from the source - async generator"""
        pass
    
    @abstractmethod
    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a raw item into standardized format"""
        pass
    
    async def run_collection(self) -> CollectionResult:
        """Run the complete collection process"""
        start_time = time.time()
        result = CollectionResult(status=CollectionStatus.RUNNING)
        
        # Create collection run record
        db_session = get_db_session()
        collection_run = CollectionRun(
            source_id=self.source.id,
            status=CollectionStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc)
        )
        db_session.add(collection_run)
        db_session.commit()
        
        try:
            async with self:
                logger.info(f"Starting collection for source: {self.source.name}")
                
                async for raw_item in self.collect_data():
                    try:
                        # Apply rate limiting
                        await self.rate_limiter.acquire()
                        
                        # Parse the item
                        parsed_item = self.parse_item(raw_item)
                        if not parsed_item:
                            result.items_skipped += 1
                            continue
                        
                        # Validate the indicator
                        if not validate_indicator(parsed_item):
                            logger.warning(f"Invalid indicator from {self.source.name}: {parsed_item}")
                            result.items_failed += 1
                            continue
                        
                        # Normalize the indicator
                        normalized_item = normalize_indicator(parsed_item)
                        
                        # Store in database
                        stored = await self._store_indicator(db_session, normalized_item, raw_item)
                        if stored == 'new':
                            result.items_new += 1
                        elif stored == 'updated':
                            result.items_updated += 1
                        else:
                            result.items_skipped += 1
                        
                        result.items_collected += 1
                        
                    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                        logger.error(f"Error processing item from {self.source.name}: {e}")
                        result.items_failed += 1
                        continue
                
                result.status = CollectionStatus.COMPLETED
                result.duration_seconds = time.time() - start_time
                
                logger.info(f"Collection completed for {self.source.name}: "
                          f"{result.items_collected} items, {result.items_new} new, "
                          f"{result.items_updated} updated, {result.items_failed} failed")
                
        except asyncio.TimeoutError:
            result.status = CollectionStatus.TIMEOUT
            result.error_message = "Collection timed out"
            logger.error(f"Collection timeout for source: {self.source.name}")
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            result.status = CollectionStatus.FAILED
            result.error_message = str(e)
            result.error_details = {"exception_type": type(e).__name__}
            logger.error(f"Collection failed for source {self.source.name}: {e}", exc_info=True)
        
        finally:
            # Update collection run record
            collection_run.completed_at = datetime.now(timezone.utc)
            collection_run.status = result.status.value
            collection_run.items_collected = result.items_collected
            collection_run.items_new = result.items_new
            collection_run.items_updated = result.items_updated
            collection_run.items_skipped = result.items_skipped
            collection_run.items_failed = result.items_failed
            collection_run.error_message = result.error_message
            collection_run.error_details = result.error_details
            collection_run.duration_seconds = int(result.duration_seconds or 0)
            
            db_session.commit()
            db_session.close()
        
        return result
    
    async def _store_indicator(self, db_session: Session, indicator_data: Dict[str, Any], 
                             raw_data: Dict[str, Any]) -> str:
        """Store indicator in database, return 'new', 'updated', or 'skipped'"""
        try:
            # Check if indicator already exists
            existing = db_session.query(Indicator).filter(
                Indicator.source_id == self.source.id,
                Indicator.indicator_type == indicator_data['indicator_type'],
                Indicator.normalized_value == indicator_data['normalized_value']
            ).first()
            
            current_time = datetime.now(timezone.utc)
            
            if existing:
                # Update existing indicator
                existing.last_seen = current_time
                existing.description = indicator_data.get('description', existing.description)
                existing.threat_types = indicator_data.get('threat_types', existing.threat_types)
                existing.confidence = indicator_data.get('confidence', existing.confidence)
                existing.severity = indicator_data.get('severity', existing.severity)
                existing.tags = indicator_data.get('tags', existing.tags)
                existing.indicator_metadata = indicator_data.get('metadata', existing.indicator_metadata)
                existing.raw_data = raw_data
                existing.updated_at = current_time
                
                # Reactivate if it was expired
                if existing.expires_at and existing.expires_at <= current_time:
                    existing.active = True
                    existing.expires_at = indicator_data.get('expires_at')
                
                return 'updated'
            else:
                # Create new indicator
                indicator = Indicator(
                    source_id=self.source.id,
                    indicator_type=indicator_data['indicator_type'],
                    value=indicator_data['value'],
                    normalized_value=indicator_data['normalized_value'],
                    threat_types=indicator_data.get('threat_types', []),
                    confidence=indicator_data.get('confidence', 'medium'),
                    severity=indicator_data.get('severity', 5),
                    description=indicator_data.get('description'),
                    tags=indicator_data.get('tags', []),
                    indicator_metadata=indicator_data.get('metadata', {}),
                    first_seen=current_time,
                    last_seen=current_time,
                    expires_at=indicator_data.get('expires_at'),
                    raw_data=raw_data,
                    collection_date=current_time
                )
                
                db_session.add(indicator)
                return 'new'
                
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error storing indicator: {e}")
            db_session.rollback()
            raise

class HTTPCollector(BaseCollector):
    """Collector for HTTP-based sources (REST APIs, JSON feeds, etc.)"""
    
    async def collect_data(self):
        """Collect data from HTTP endpoint"""
        url = self.source.url
        if not url:
            raise ValueError(f"No URL configured for source: {self.source.name}")
        
        auth_config = self.source.auth_config
        auth = None
        
        # Setup authentication if configured
        if auth_config:
            if auth_config.get('type') == 'basic':
                auth = aiohttp.BasicAuth(
                    auth_config['username'],
                    auth_config['password']
                )
            elif auth_config.get('type') == 'bearer':
                self.session.headers['Authorization'] = f"Bearer {auth_config['token']}"
            elif auth_config.get('type') == 'api_key':
                header_name = auth_config.get('header', 'X-API-Key')
                self.session.headers[header_name] = auth_config['key']
        
        try:
            async with self.session.get(url, auth=auth) as response:
                response.raise_for_status()
                content_type = response.headers.get('content-type', '').lower()
                
                if 'application/json' in content_type:
                    data = await response.json()
                    for item in self._process_json_data(data):
                        yield item
                elif 'text/plain' in content_type or 'text/csv' in content_type:
                    text = await response.text()
                    for item in self._process_text_data(text):
                        yield item
                else:
                    logger.warning(f"Unsupported content type: {content_type}")
                    
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error collecting from {url}: {e}")
            raise
    
    def _process_json_data(self, data: Union[Dict, List]):
        """Process JSON data and yield individual items"""
        if isinstance(data, list):
            for item in data:
                yield item
        elif isinstance(data, dict):
            # Handle different JSON structures
            if 'results' in data:
                for item in data['results']:
                    yield item
            elif 'data' in data:
                for item in data['data']:
                    yield item
            elif 'indicators' in data:
                for item in data['indicators']:
                    yield item
            else:
                yield data
    
    def _process_text_data(self, text: str):
        """Process text data (line-based formats)"""
        for line_num, line in enumerate(text.strip().split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Handle CSV-like formats
            parts = [part.strip() for part in line.split(',')]
            yield {
                'value': parts[0],
                'line_number': line_num,
                'raw_line': line,
                'parts': parts
            }

class RSSCollector(BaseCollector):
    """Collector for RSS/Atom feeds"""
    
    async def collect_data(self):
        """Collect data from RSS feed"""
        url = self.source.url
        if not url:
            raise ValueError(f"No URL configured for source: {self.source.name}")
        
        try:
            async with self.session.get(url) as response:
                response.raise_for_status()
                content = await response.text()
                
                # Parse RSS feed
                feed = feedparser.parse(content)
                
                if feed.bozo:
                    logger.warning(f"RSS feed has issues: {feed.bozo_exception}")
                
                for entry in feed.entries:
                    yield {
                        'title': entry.get('title'),
                        'link': entry.get('link'),
                        'description': entry.get('description'),
                        'published': entry.get('published'),
                        'updated': entry.get('updated'),
                        'content': entry.get('content'),
                        'tags': [tag.term for tag in entry.get('tags', [])],
                        'raw_entry': entry
                    }
                    
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error collecting RSS from {url}: {e}")
            raise

class CollectorRegistry:
    """Registry for managing different collector types"""
    
    _collectors = {
        'http': HTTPCollector,
        'https': HTTPCollector,
        'json': HTTPCollector,
        'csv': HTTPCollector,
        'txt': HTTPCollector,
        'rss': RSSCollector,
        'atom': RSSCollector,
    }
    
    @classmethod
    def register_collector(cls, source_type: str, collector_class: type):
        """Register a new collector type"""
        cls._collectors[source_type] = collector_class
    
    @classmethod
    def get_collector(cls, source: Source) -> BaseCollector:
        """Get appropriate collector for source"""
        source_type = source.source_type.lower()
        
        if source_type not in cls._collectors:
            raise ValueError(f"Unknown source type: {source_type}")
        
        collector_class = cls._collectors[source_type]
        return collector_class(source)
    
    @classmethod
    def list_supported_types(cls) -> List[str]:
        """List all supported collector types"""
        return list(cls._collectors.keys())
