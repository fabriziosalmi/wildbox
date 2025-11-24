"""
Command Query Responsibility Segregation (CQRS) pattern.

Separates read and write operations for performance optimization:
- Commands: Mutate state (writes to PostgreSQL)
- Queries: Read optimized data (materialized views + Redis cache)

Based on Martin Fowler's CQRS pattern and Netflix's architecture.

Usage:
    from shared.cqrs import CommandBus, QueryBus, Command, Query
    
    # Write operation (command)
    class CreateUserCommand(Command):
        email: str
        password: str
    
    @command_handler(CreateUserCommand)
    async def handle_create_user(cmd: CreateUserCommand):
        user = User(email=cmd.email, ...)
        await db.save(user)
        await event_store.append(UserCreatedEvent(...))
        return user.id
    
    # Read operation (query)
    class GetUserStatsQuery(Query):
        user_id: str
    
    @query_handler(GetUserStatsQuery)
    async def handle_get_stats(query: GetUserStatsQuery):
        # Read from materialized view + cache
        return await cache.get_or_compute(f"stats:{query.user_id}")
"""

from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Callable, Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import logging
import asyncio
from functools import wraps

# Redis for query caching
import redis.asyncio as redis

logger = logging.getLogger(__name__)


# Base classes
class Command(ABC):
    """Base class for commands (state-changing operations)."""
    pass


class Query(ABC):
    """Base class for queries (read-only operations)."""
    pass


TCommand = TypeVar('TCommand', bound=Command)
TQuery = TypeVar('TQuery', bound=Query)
TResult = TypeVar('TResult')


# Command Bus
class CommandHandler(ABC, Generic[TCommand, TResult]):
    """Base class for command handlers."""
    
    @abstractmethod
    async def handle(self, command: TCommand) -> TResult:
        """Execute command and return result."""
        pass


class CommandBus:
    """
    Dispatches commands to handlers.
    
    Ensures:
    - Commands mutate state consistently
    - Events are emitted after successful mutations
    - Failures are logged with full context
    
    Example:
        command_bus = CommandBus()
        
        @command_bus.register(CreateAPIKeyCommand)
        async def create_api_key(cmd: CreateAPIKeyCommand) -> str:
            # Validate
            if await api_key_exists(cmd.team_id):
                raise ConflictError("API key already exists")
            
            # Execute
            api_key = APIKey(team_id=cmd.team_id, ...)
            await db.save(api_key)
            
            # Emit event
            await event_store.append(APIKeyCreatedEvent(...))
            
            return api_key.id
        
        # Dispatch
        api_key_id = await command_bus.execute(
            CreateAPIKeyCommand(team_id="team_123")
        )
    """
    
    def __init__(self):
        self._handlers: Dict[type, Callable] = {}
    
    def register(self, command_type: type[TCommand]) -> Callable:
        """Register command handler (decorator)."""
        def decorator(handler: Callable[[TCommand], TResult]) -> Callable:
            self._handlers[command_type] = handler
            logger.info(f"Registered command handler: {command_type.__name__}")
            return handler
        return decorator
    
    async def execute(self, command: TCommand) -> TResult:
        """
        Execute command.
        
        Args:
            command: Command instance
        
        Returns:
            Handler result
        
        Raises:
            ValueError: If no handler registered
            Exception: If handler fails
        """
        command_type = type(command)
        
        if command_type not in self._handlers:
            raise ValueError(f"No handler registered for {command_type.__name__}")
        
        handler = self._handlers[command_type]
        
        logger.info(f"Executing command: {command_type.__name__}")
        start_time = datetime.now()
        
        try:
            result = await handler(command)
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(
                f"Command succeeded: {command_type.__name__} ({duration:.3f}s)"
            )
            return result
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(
                f"Command failed: {command_type.__name__} ({duration:.3f}s) - {str(e)}",
                exc_info=True
            )
            raise


# Query Bus
class QueryHandler(ABC, Generic[TQuery, TResult]):
    """Base class for query handlers."""
    
    @abstractmethod
    async def handle(self, query: TQuery) -> TResult:
        """Execute query and return result."""
        pass


class QueryCache:
    """
    Redis-based cache for query results.
    
    Strategies:
    - Cache-aside: Check cache, compute if miss, store result
    - TTL-based expiration
    - Key namespacing by query type
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379/10"):
        self.redis_url = redis_url
        self._client: Optional[redis.Redis] = None
    
    async def connect(self):
        """Initialize Redis connection."""
        self._client = await redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True
        )
        logger.info("Query cache connected")
    
    async def get(self, key: str) -> Optional[Any]:
        """Get cached query result."""
        if not self._client:
            return None
        
        value = await self._client.get(key)
        if value:
            logger.debug(f"Cache HIT: {key}")
            return json.loads(value)
        
        logger.debug(f"Cache MISS: {key}")
        return None
    
    async def set(self, key: str, value: Any, ttl: int = 300):
        """Cache query result with TTL."""
        if not self._client:
            return
        
        await self._client.setex(
            key,
            ttl,
            json.dumps(value, default=str)
        )
        logger.debug(f"Cache SET: {key} (TTL: {ttl}s)")
    
    async def invalidate(self, pattern: str):
        """Invalidate cache entries matching pattern."""
        if not self._client:
            return
        
        keys = await self._client.keys(pattern)
        if keys:
            await self._client.delete(*keys)
            logger.info(f"Cache invalidated: {len(keys)} keys ({pattern})")
    
    async def close(self):
        """Close Redis connection."""
        if self._client:
            await self._client.close()


class QueryBus:
    """
    Dispatches queries to handlers with automatic caching.
    
    Features:
    - Automatic cache-aside pattern
    - Configurable TTL per query type
    - Cache invalidation on command execution
    
    Example:
        query_bus = QueryBus(cache)
        
        @query_bus.register(GetTeamStatsQuery, ttl=60)
        async def get_team_stats(query: GetTeamStatsQuery) -> dict:
            # Query materialized view
            stats = await db.execute(
                "SELECT * FROM team_stats_mv WHERE team_id = $1",
                query.team_id
            )
            return stats
        
        # Execute (cached for 60s)
        stats = await query_bus.execute(GetTeamStatsQuery(team_id="team_123"))
    """
    
    def __init__(self, cache: Optional[QueryCache] = None):
        self._handlers: Dict[type, tuple[Callable, int]] = {}
        self.cache = cache
    
    def register(
        self,
        query_type: type[TQuery],
        ttl: int = 300,
        cache_key_fn: Optional[Callable[[TQuery], str]] = None
    ) -> Callable:
        """
        Register query handler with caching.
        
        Args:
            query_type: Query class
            ttl: Cache TTL in seconds (default: 5 minutes)
            cache_key_fn: Custom cache key function
        """
        def decorator(handler: Callable[[TQuery], TResult]) -> Callable:
            self._handlers[query_type] = (handler, ttl, cache_key_fn)
            logger.info(f"Registered query handler: {query_type.__name__} (TTL: {ttl}s)")
            return handler
        return decorator
    
    def _default_cache_key(self, query: TQuery) -> str:
        """Generate cache key from query attributes."""
        query_type = type(query).__name__
        query_data = json.dumps(query.__dict__, sort_keys=True, default=str)
        return f"query:{query_type}:{hash(query_data)}"
    
    async def execute(self, query: TQuery) -> TResult:
        """
        Execute query with caching.
        
        Flow:
        1. Check cache
        2. If miss, execute handler
        3. Store result in cache
        4. Return result
        """
        query_type = type(query)
        
        if query_type not in self._handlers:
            raise ValueError(f"No handler registered for {query_type.__name__}")
        
        handler, ttl, cache_key_fn = self._handlers[query_type]
        
        # Generate cache key
        cache_key_func = cache_key_fn or self._default_cache_key
        cache_key = cache_key_func(query)
        
        # Check cache
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                return cached
        
        # Execute query
        logger.info(f"Executing query: {query_type.__name__}")
        start_time = datetime.now()
        
        try:
            result = await handler(query)
            duration = (datetime.now() - start_time).total_seconds()
            
            # Cache result
            if self.cache:
                await self.cache.set(cache_key, result, ttl)
            
            logger.info(
                f"Query succeeded: {query_type.__name__} ({duration:.3f}s)"
            )
            return result
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(
                f"Query failed: {query_type.__name__} ({duration:.3f}s) - {str(e)}",
                exc_info=True
            )
            raise


# Wildbox-specific commands and queries

# --- Identity Service Commands ---

@dataclass
class CreateUserCommand(Command):
    """Create new user account."""
    email: str
    password: str
    full_name: str
    team_id: Optional[str] = None


@dataclass
class RotateAPIKeyCommand(Command):
    """Rotate API key for team."""
    team_id: str
    old_key_id: str
    requested_by_user_id: str


@dataclass
class UpdateSubscriptionCommand(Command):
    """Change team subscription plan."""
    team_id: str
    new_plan: str  # free, professional, enterprise
    requested_by_user_id: str


# --- Identity Service Queries ---

@dataclass
class GetUserByEmailQuery(Query):
    """Retrieve user by email (login)."""
    email: str


@dataclass
class GetTeamStatsQuery(Query):
    """Get team usage statistics (cached)."""
    team_id: str


@dataclass
class GetActiveUsersQuery(Query):
    """Get count of active users (dashboard widget)."""
    since_hours: int = 24


# --- Guardian Service Commands ---

@dataclass
class CreateVulnerabilityCommand(Command):
    """Record new vulnerability from scan."""
    cve_id: str
    severity: str
    affected_asset: str
    team_id: str


@dataclass
class RemediateVulnerabilityCommand(Command):
    """Mark vulnerability as remediated."""
    vulnerability_id: str
    remediated_by_user_id: str
    remediation_notes: str


# --- Guardian Service Queries ---

@dataclass
class GetOpenVulnerabilitiesQuery(Query):
    """Get open vulnerabilities for dashboard (cached)."""
    team_id: str
    severity_filter: Optional[List[str]] = None


@dataclass
class GetVulnerabilityTrendsQuery(Query):
    """Get vulnerability trends over time (analytics)."""
    team_id: str
    days: int = 30


# --- Data Service Queries ---

@dataclass
class SearchIOCsQuery(Query):
    """Search IOCs with filters (cached)."""
    query: str
    ioc_type: Optional[str] = None
    limit: int = 100


@dataclass
class GetThreatIntelFeedQuery(Query):
    """Get latest threat intel (cached heavily)."""
    feed_name: str
    hours: int = 24


# Example integration
"""
# Initialize buses
command_bus = CommandBus()
cache = QueryCache("redis://localhost:6379/10")
await cache.connect()
query_bus = QueryBus(cache)

# Register handlers
@command_bus.register(CreateUserCommand)
async def create_user_handler(cmd: CreateUserCommand) -> str:
    # Validate
    existing = await db.user_by_email(cmd.email)
    if existing:
        raise ValueError("User already exists")
    
    # Create
    user = User(
        id=str(uuid.uuid4()),
        email=cmd.email,
        password_hash=hash_password(cmd.password),
        full_name=cmd.full_name,
        team_id=cmd.team_id
    )
    await db.save_user(user)
    
    # Emit event
    await event_store.append(Event(
        aggregate_id=user.id,
        event_type="UserCreated",
        data={"email": user.email, "team_id": user.team_id}
    ))
    
    # Invalidate related queries
    await cache.invalidate(f"query:GetActiveUsersQuery:*")
    
    return user.id

@query_bus.register(GetTeamStatsQuery, ttl=60)
async def get_team_stats_handler(query: GetTeamStatsQuery) -> dict:
    # Read from materialized view (updated every 5 minutes)
    stats = await db.execute(
        "SELECT * FROM team_stats_mv WHERE team_id = $1",
        query.team_id
    )
    return {
        "api_calls_24h": stats['api_calls'],
        "vulnerabilities_open": stats['vulns_open'],
        "last_scan": stats['last_scan']
    }

# Usage in API endpoint
@app.post("/api/v1/users")
async def create_user_endpoint(request: CreateUserRequest):
    user_id = await command_bus.execute(
        CreateUserCommand(
            email=request.email,
            password=request.password,
            full_name=request.full_name
        )
    )
    return {"user_id": user_id}

@app.get("/api/v1/teams/{team_id}/stats")
async def get_team_stats_endpoint(team_id: str):
    stats = await query_bus.execute(
        GetTeamStatsQuery(team_id=team_id)
    )
    return stats
"""
