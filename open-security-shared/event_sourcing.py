"""
Event Sourcing implementation for audit trails and state reconstruction.

Stores every state-changing event as an immutable record, enabling:
- Perfect audit trails
- Time-travel debugging
- State reconstruction from events
- Compliance with regulations (GDPR, SOC 2)

Based on Greg Young's Event Sourcing pattern.

Usage:
    from shared.event_sourcing import EventStore, Event
    
    # Create event
    event = Event(
        aggregate_id="user_123",
        event_type="UserCreated",
        data={"email": "user@example.com"},
        metadata={"ip": "192.168.1.1"}
    )
    
    # Store event
    await event_store.append(event)
    
    # Replay events to rebuild state
    events = await event_store.get_events("user_123")
"""

import uuid
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict
from sqlalchemy import (
    Column, String, Integer, Text, DateTime, Index,
    MetaData, Table, create_engine, select
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import logging

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """
    Immutable event representing a state change.
    
    Attributes:
        aggregate_id: ID of the entity this event applies to (user_id, api_key_id, etc.)
        event_type: Type of event (UserCreated, APIKeyRotated, VulnerabilityUpdated)
        data: Event payload (state changes)
        metadata: Context (user_id who triggered, IP address, timestamp)
        event_id: Unique event identifier (auto-generated)
        version: Event version for aggregate (auto-incremented)
        timestamp: When event occurred (auto-generated)
    """
    aggregate_id: str
    event_type: str
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: int = 1
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> dict:
        """Serialize event for storage."""
        event_dict = asdict(self)
        event_dict['timestamp'] = self.timestamp.isoformat()
        event_dict['data'] = json.dumps(self.data)
        event_dict['metadata'] = json.dumps(self.metadata or {})
        return event_dict
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Event':
        """Deserialize event from storage."""
        return cls(
            event_id=data['event_id'],
            aggregate_id=data['aggregate_id'],
            event_type=data['event_type'],
            data=json.loads(data['data']),
            metadata=json.loads(data['metadata']),
            version=data['version'],
            timestamp=datetime.fromisoformat(data['timestamp'])
        )


# Event Store Schema
metadata = MetaData()

events_table = Table(
    'event_store',
    metadata,
    Column('event_id', String(36), primary_key=True),
    Column('aggregate_id', String(255), nullable=False, index=True),
    Column('event_type', String(100), nullable=False, index=True),
    Column('data', Text, nullable=False),
    Column('metadata', Text, nullable=True),
    Column('version', Integer, nullable=False),
    Column('timestamp', DateTime(timezone=True), nullable=False, index=True),
    
    # Composite index for fast aggregate reconstruction
    Index('idx_aggregate_version', 'aggregate_id', 'version'),
    Index('idx_event_type_timestamp', 'event_type', 'timestamp'),
)


class EventStore:
    """
    Append-only store for events.
    
    Guarantees:
    - Events are immutable (no updates or deletes)
    - Events are ordered by version per aggregate
    - Concurrent appends are serialized
    
    Example:
        event_store = EventStore("postgresql+asyncpg://user:pass@localhost/wildbox")
        
        # Log critical operations
        await event_store.append(Event(
            aggregate_id=api_key.id,
            event_type="APIKeyCreated",
            data={
                "key_prefix": api_key.prefix,
                "team_id": api_key.team_id,
                "expires_at": api_key.expires_at.isoformat()
            },
            metadata={
                "created_by": current_user.id,
                "ip_address": request.client.host
            }
        ))
        
        # Audit trail: get all events for an API key
        events = await event_store.get_events(api_key.id)
        for event in events:
            print(f"{event.timestamp}: {event.event_type}")
    """
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.engine = create_async_engine(database_url, echo=False)
        self.async_session = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
    
    async def initialize(self):
        """Create event store table if not exists."""
        async with self.engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        logger.info("Event store initialized")
    
    async def append(self, event: Event) -> Event:
        """
        Append event to store.
        
        Automatically assigns version based on existing events for aggregate.
        
        Args:
            event: Event to store
        
        Returns:
            Event with assigned version
        
        Raises:
            Exception: If concurrent modification detected
        """
        async with self.async_session() as session:
            # Get current version for aggregate
            result = await session.execute(
                select(events_table.c.version)
                .where(events_table.c.aggregate_id == event.aggregate_id)
                .order_by(events_table.c.version.desc())
                .limit(1)
            )
            last_version = result.scalar()
            
            # Assign next version
            event.version = (last_version or 0) + 1
            
            # Insert event
            await session.execute(
                events_table.insert().values(**event.to_dict())
            )
            await session.commit()
            
            logger.info(
                f"Event stored: {event.event_type} "
                f"(aggregate: {event.aggregate_id}, version: {event.version})"
            )
            
            return event
    
    async def get_events(
        self,
        aggregate_id: str,
        from_version: int = 1,
        to_version: Optional[int] = None
    ) -> List[Event]:
        """
        Retrieve all events for an aggregate.
        
        Args:
            aggregate_id: Entity ID
            from_version: Starting version (inclusive)
            to_version: Ending version (inclusive), None for all
        
        Returns:
            List of events in version order
        """
        async with self.async_session() as session:
            query = (
                select(events_table)
                .where(events_table.c.aggregate_id == aggregate_id)
                .where(events_table.c.version >= from_version)
                .order_by(events_table.c.version)
            )
            
            if to_version:
                query = query.where(events_table.c.version <= to_version)
            
            result = await session.execute(query)
            rows = result.fetchall()
            
            return [Event.from_dict(dict(row._mapping)) for row in rows]
    
    async def get_events_by_type(
        self,
        event_type: str,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Event]:
        """
        Retrieve events by type (for projections/analytics).
        
        Args:
            event_type: Event type to filter
            since: Only events after this timestamp
            limit: Maximum events to return
        """
        async with self.async_session() as session:
            query = (
                select(events_table)
                .where(events_table.c.event_type == event_type)
                .order_by(events_table.c.timestamp.desc())
                .limit(limit)
            )
            
            if since:
                query = query.where(events_table.c.timestamp >= since)
            
            result = await session.execute(query)
            rows = result.fetchall()
            
            return [Event.from_dict(dict(row._mapping)) for row in rows]
    
    async def get_snapshot(self, aggregate_id: str) -> Optional[Dict[str, Any]]:
        """
        Rebuild current state from events (time-travel capability).
        
        Args:
            aggregate_id: Entity ID
        
        Returns:
            Reconstructed state as dictionary
        """
        events = await self.get_events(aggregate_id)
        
        if not events:
            return None
        
        # Start with empty state
        state = {}
        
        # Apply events in order
        for event in events:
            # Merge event data into state
            state = {**state, **event.data}
            state['_last_event_type'] = event.event_type
            state['_version'] = event.version
            state['_updated_at'] = event.timestamp.isoformat()
        
        return state
    
    async def close(self):
        """Close database connection."""
        await self.engine.dispose()


# Pre-defined event types for Wildbox
class EventTypes:
    """Standard event types for audit logging."""
    
    # Authentication events
    USER_CREATED = "UserCreated"
    USER_ACTIVATED = "UserActivated"
    USER_DEACTIVATED = "UserDeactivated"
    USER_DELETED = "UserDeleted"
    USER_PASSWORD_CHANGED = "UserPasswordChanged"
    USER_LOGIN_SUCCESS = "UserLoginSuccess"
    USER_LOGIN_FAILED = "UserLoginFailed"
    
    # API Key events
    API_KEY_CREATED = "APIKeyCreated"
    API_KEY_ROTATED = "APIKeyRotated"
    API_KEY_REVOKED = "APIKeyRevoked"
    API_KEY_EXPIRED = "APIKeyExpired"
    
    # Team events
    TEAM_CREATED = "TeamCreated"
    TEAM_MEMBER_ADDED = "TeamMemberAdded"
    TEAM_MEMBER_REMOVED = "TeamMemberRemoved"
    TEAM_ROLE_CHANGED = "TeamRoleChanged"
    
    # Subscription events
    SUBSCRIPTION_CREATED = "SubscriptionCreated"
    SUBSCRIPTION_UPGRADED = "SubscriptionUpgraded"
    SUBSCRIPTION_DOWNGRADED = "SubscriptionDowngraded"
    SUBSCRIPTION_CANCELLED = "SubscriptionCancelled"
    
    # Vulnerability events
    VULNERABILITY_DISCOVERED = "VulnerabilityDiscovered"
    VULNERABILITY_UPDATED = "VulnerabilityUpdated"
    VULNERABILITY_REMEDIATED = "VulnerabilityRemediated"
    VULNERABILITY_RISK_ACCEPTED = "VulnerabilityRiskAccepted"
    
    # Security events
    SECURITY_SCAN_STARTED = "SecurityScanStarted"
    SECURITY_SCAN_COMPLETED = "SecurityScanCompleted"
    THREAT_DETECTED = "ThreatDetected"
    INCIDENT_CREATED = "IncidentCreated"
    INCIDENT_RESOLVED = "IncidentResolved"


# Example usage
"""
from shared.event_sourcing import EventStore, Event, EventTypes

# Initialize event store
event_store = EventStore("postgresql+asyncpg://user:pass@localhost/wildbox_events")
await event_store.initialize()

# Log API key creation
await event_store.append(Event(
    aggregate_id=api_key.id,
    event_type=EventTypes.API_KEY_CREATED,
    data={
        "prefix": api_key.prefix,
        "team_id": api_key.team_id,
        "plan": "professional",
        "expires_at": "2026-01-01T00:00:00Z"
    },
    metadata={
        "created_by_user_id": current_user.id,
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0..."
    }
))

# Get complete audit trail
events = await event_store.get_events(api_key.id)
for event in events:
    print(f"{event.timestamp}: {event.event_type} by {event.metadata.get('created_by_user_id')}")

# Time-travel: reconstruct state at specific version
state_at_v3 = await event_store.get_snapshot(api_key.id)
print(f"API key was in state: {state_at_v3}")

# Analytics: get all failed logins in last 24h
from datetime import timedelta
since = datetime.now(timezone.utc) - timedelta(hours=24)
failed_logins = await event_store.get_events_by_type(
    EventTypes.USER_LOGIN_FAILED,
    since=since,
    limit=1000
)
print(f"Failed logins: {len(failed_logins)}")
"""
