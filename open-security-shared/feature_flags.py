"""
Feature flags for gradual rollouts and A/B testing.

Enables:
- Percentage-based rollouts (enable for 10% of users)
- User targeting (enable for specific emails/teams)
- Environment-based flags (enable in staging only)
- Kill switches (disable feature instantly)

Based on LaunchDarkly and Unleash patterns.

Usage:
    from shared.feature_flags import FeatureFlagService, flag_enabled
    
    # Initialize
    flags = FeatureFlagService()
    await flags.initialize()
    
    # Check flag
    if await flags.is_enabled("ai_analysis", user_id="user_123"):
        result = await analyze_with_ai(data)
    else:
        result = await analyze_with_rules(data)
    
    # Decorator
    @flag_enabled("new_dashboard")
    async def get_new_dashboard():
        return {"data": "new_ui"}
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging

from sqlalchemy import (
    Column, String, Boolean, Integer, Text, DateTime,
    MetaData, Table, create_engine, select, update
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import redis.asyncio as redis

logger = logging.getLogger(__name__)


class RolloutStrategy(str, Enum):
    """Feature flag rollout strategies."""
    ALL = "all"  # Enable for all users
    NONE = "none"  # Disable for all users
    PERCENTAGE = "percentage"  # Enable for X% of users
    USERS = "users"  # Enable for specific user IDs
    TEAMS = "teams"  # Enable for specific teams
    ENVIRONMENT = "environment"  # Enable in specific environments


@dataclass
class FeatureFlag:
    """
    Feature flag configuration.
    
    Attributes:
        key: Unique flag identifier (e.g., "ai_analysis", "new_dashboard")
        enabled: Master switch (overrides all strategies)
        strategy: Rollout strategy
        percentage: Rollout percentage (0-100) for PERCENTAGE strategy
        target_users: User IDs for USERS strategy
        target_teams: Team IDs for TEAMS strategy
        environments: Environments for ENVIRONMENT strategy (staging, production)
        description: Human-readable description
    """
    key: str
    enabled: bool = False
    strategy: RolloutStrategy = RolloutStrategy.NONE
    percentage: int = 0
    target_users: List[str] = field(default_factory=list)
    target_teams: List[str] = field(default_factory=list)
    environments: List[str] = field(default_factory=list)
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> dict:
        """Serialize for storage."""
        data = asdict(self)
        data['strategy'] = self.strategy.value
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        data['target_users'] = json.dumps(self.target_users)
        data['target_teams'] = json.dumps(self.target_teams)
        data['environments'] = json.dumps(self.environments)
        return data
    
    @classmethod
    def from_dict(cls, data: dict) -> 'FeatureFlag':
        """Deserialize from storage."""
        return cls(
            key=data['key'],
            enabled=data['enabled'],
            strategy=RolloutStrategy(data['strategy']),
            percentage=data['percentage'],
            target_users=json.loads(data['target_users']),
            target_teams=json.loads(data['target_teams']),
            environments=json.loads(data['environments']),
            description=data.get('description', ''),
            created_at=datetime.fromisoformat(data['created_at']),
            updated_at=datetime.fromisoformat(data['updated_at'])
        )


# Database schema
metadata = MetaData()

feature_flags_table = Table(
    'feature_flags',
    metadata,
    Column('key', String(100), primary_key=True),
    Column('enabled', Boolean, nullable=False, default=False),
    Column('strategy', String(50), nullable=False),
    Column('percentage', Integer, nullable=False, default=0),
    Column('target_users', Text, nullable=False, default='[]'),
    Column('target_teams', Text, nullable=False, default='[]'),
    Column('environments', Text, nullable=False, default='[]'),
    Column('description', Text, nullable=True),
    Column('created_at', DateTime(timezone=True), nullable=False),
    Column('updated_at', DateTime(timezone=True), nullable=False),
)


class FeatureFlagService:
    """
    Feature flag evaluation service.
    
    Features:
    - PostgreSQL storage for flag definitions
    - Redis caching for fast evaluation
    - Deterministic percentage rollout (consistent per user)
    - Admin API for flag management
    
    Example:
        # Initialize
        flags = FeatureFlagService(
            database_url="postgresql+asyncpg://user:pass@localhost/wildbox",
            redis_url="redis://localhost:6379/7"
        )
        await flags.initialize()
        
        # Create flag
        await flags.create_flag(FeatureFlag(
            key="ai_analysis",
            enabled=True,
            strategy=RolloutStrategy.PERCENTAGE,
            percentage=25,  # 25% rollout
            description="AI-powered threat analysis"
        ))
        
        # Evaluate flag
        if await flags.is_enabled("ai_analysis", user_id="user_123"):
            # User in 25% rollout
            result = await ai_analyze()
        else:
            # User not in rollout
            result = await rule_based_analyze()
    """
    
    def __init__(
        self,
        database_url: str,
        redis_url: str = "redis://localhost:6379/7",
        cache_ttl: int = 60
    ):
        self.database_url = database_url
        self.redis_url = redis_url
        self.cache_ttl = cache_ttl
        
        self.engine = create_async_engine(database_url, echo=False)
        self.async_session = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        self._redis: Optional[redis.Redis] = None
    
    async def initialize(self):
        """Initialize database and Redis."""
        # Create tables
        async with self.engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        
        # Connect to Redis
        self._redis = await redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True
        )
        
        logger.info("Feature flag service initialized")
    
    async def create_flag(self, flag: FeatureFlag):
        """Create or update feature flag."""
        async with self.async_session() as session:
            # Check if exists
            result = await session.execute(
                select(feature_flags_table).where(
                    feature_flags_table.c.key == flag.key
                )
            )
            existing = result.fetchone()
            
            if existing:
                # Update
                await session.execute(
                    update(feature_flags_table)
                    .where(feature_flags_table.c.key == flag.key)
                    .values(
                        enabled=flag.enabled,
                        strategy=flag.strategy.value,
                        percentage=flag.percentage,
                        target_users=json.dumps(flag.target_users),
                        target_teams=json.dumps(flag.target_teams),
                        environments=json.dumps(flag.environments),
                        description=flag.description,
                        updated_at=datetime.now(timezone.utc)
                    )
                )
            else:
                # Insert
                await session.execute(
                    feature_flags_table.insert().values(**flag.to_dict())
                )
            
            await session.commit()
        
        # Invalidate cache
        if self._redis:
            await self._redis.delete(f"flag:{flag.key}")
        
        logger.info(f"Feature flag created/updated: {flag.key}")
    
    async def get_flag(self, key: str) -> Optional[FeatureFlag]:
        """Get feature flag by key."""
        # Check cache
        if self._redis:
            cached = await self._redis.get(f"flag:{key}")
            if cached:
                return FeatureFlag.from_dict(json.loads(cached))
        
        # Query database
        async with self.async_session() as session:
            result = await session.execute(
                select(feature_flags_table).where(
                    feature_flags_table.c.key == key
                )
            )
            row = result.fetchone()
            
            if not row:
                return None
            
            flag = FeatureFlag.from_dict(dict(row._mapping))
            
            # Cache result
            if self._redis:
                await self._redis.setex(
                    f"flag:{key}",
                    self.cache_ttl,
                    json.dumps(flag.to_dict())
                )
            
            return flag
    
    async def is_enabled(
        self,
        key: str,
        user_id: Optional[str] = None,
        team_id: Optional[str] = None,
        environment: str = "production"
    ) -> bool:
        """
        Evaluate feature flag.
        
        Args:
            key: Flag key
            user_id: Current user ID
            team_id: Current team ID
            environment: Current environment (staging, production)
        
        Returns:
            True if flag enabled for context
        
        Example:
            # Simple check
            if await flags.is_enabled("new_feature"):
                # Feature enabled globally
                ...
            
            # User-specific
            if await flags.is_enabled("beta_ui", user_id="user_123"):
                # User in beta rollout
                ...
            
            # Team-specific
            if await flags.is_enabled("enterprise_features", team_id="team_abc"):
                # Team has enterprise features
                ...
        """
        flag = await self.get_flag(key)
        
        if not flag:
            logger.warning(f"Feature flag not found: {key}")
            return False
        
        # Master switch
        if not flag.enabled:
            return False
        
        # Evaluate strategy
        if flag.strategy == RolloutStrategy.ALL:
            return True
        
        if flag.strategy == RolloutStrategy.NONE:
            return False
        
        if flag.strategy == RolloutStrategy.PERCENTAGE:
            if not user_id:
                return False
            return self._is_in_percentage_rollout(flag.key, user_id, flag.percentage)
        
        if flag.strategy == RolloutStrategy.USERS:
            if not user_id:
                return False
            return user_id in flag.target_users
        
        if flag.strategy == RolloutStrategy.TEAMS:
            if not team_id:
                return False
            return team_id in flag.target_teams
        
        if flag.strategy == RolloutStrategy.ENVIRONMENT:
            return environment in flag.environments
        
        return False
    
    def _is_in_percentage_rollout(self, flag_key: str, user_id: str, percentage: int) -> bool:
        """
        Deterministic percentage rollout.
        
        Uses hash of (flag_key + user_id) to ensure:
        - Same user always gets same result for a flag
        - Different flags have different rollout groups
        - Percentage is evenly distributed
        """
        # Hash flag + user
        hash_input = f"{flag_key}:{user_id}".encode()
        hash_value = int(hashlib.sha256(hash_input).hexdigest(), 16)
        
        # Map to 0-100 range
        bucket = hash_value % 100
        
        # Check if in rollout
        return bucket < percentage
    
    async def list_flags(self) -> List[FeatureFlag]:
        """List all feature flags."""
        async with self.async_session() as session:
            result = await session.execute(select(feature_flags_table))
            rows = result.fetchall()
            return [FeatureFlag.from_dict(dict(row._mapping)) for row in rows]
    
    async def delete_flag(self, key: str):
        """Delete feature flag."""
        async with self.async_session() as session:
            await session.execute(
                feature_flags_table.delete().where(
                    feature_flags_table.c.key == key
                )
            )
            await session.commit()
        
        # Invalidate cache
        if self._redis:
            await self._redis.delete(f"flag:{key}")
        
        logger.info(f"Feature flag deleted: {key}")
    
    async def close(self):
        """Close connections."""
        if self._redis:
            await self._redis.close()
        await self.engine.dispose()


# Wildbox feature flags
WILDBOX_FLAGS = [
    FeatureFlag(
        key="ai_threat_analysis",
        enabled=True,
        strategy=RolloutStrategy.PERCENTAGE,
        percentage=50,
        description="GPT-4 powered threat analysis (50% rollout)"
    ),
    FeatureFlag(
        key="cspm_azure_support",
        enabled=True,
        strategy=RolloutStrategy.TEAMS,
        target_teams=["team_enterprise_1", "team_enterprise_2"],
        description="Azure CSPM checks (enterprise only)"
    ),
    FeatureFlag(
        key="new_vulnerability_ui",
        enabled=True,
        strategy=RolloutStrategy.PERCENTAGE,
        percentage=10,
        description="Redesigned vulnerability dashboard (10% beta)"
    ),
    FeatureFlag(
        key="incident_response_automation",
        enabled=True,
        strategy=RolloutStrategy.ENVIRONMENT,
        environments=["staging"],
        description="Automated incident response (staging only)"
    ),
    FeatureFlag(
        key="api_rate_limit_increase",
        enabled=False,
        strategy=RolloutStrategy.USERS,
        target_users=["user_vip_1", "user_vip_2"],
        description="10x rate limits for VIP users (kill switch)"
    ),
]


# Example usage
"""
# 1. Initialize service
from shared.feature_flags import FeatureFlagService, WILDBOX_FLAGS

flags = FeatureFlagService(
    database_url="postgresql+asyncpg://user:pass@localhost/wildbox",
    redis_url="redis://localhost:6379/7"
)
await flags.initialize()

# 2. Create default flags
for flag in WILDBOX_FLAGS:
    await flags.create_flag(flag)

# 3. Use in API endpoints
@app.post("/api/v1/threats/analyze")
async def analyze_threat(data: dict, current_user: User):
    # Check if user in AI analysis rollout
    if await flags.is_enabled("ai_threat_analysis", user_id=current_user.id):
        # Use GPT-4 (50% of users)
        result = await ai_analyze(data)
    else:
        # Use rule-based (50% of users)
        result = await rule_analyze(data)
    
    return result

# 4. Admin API for flag management
@app.put("/admin/feature-flags/{key}")
async def update_flag(key: str, request: UpdateFlagRequest):
    flag = await flags.get_flag(key)
    if not flag:
        raise HTTPException(404, "Flag not found")
    
    flag.percentage = request.percentage
    await flags.create_flag(flag)
    return {"status": "updated"}

# 5. Kill switch (instant disable)
@app.post("/admin/feature-flags/{key}/disable")
async def disable_flag(key: str):
    flag = await flags.get_flag(key)
    flag.enabled = False
    await flags.create_flag(flag)
    return {"status": "disabled"}

# 6. Monitoring (track rollout metrics)
@app.get("/admin/feature-flags/{key}/metrics")
async def flag_metrics(key: str):
    # Track how many users see each variant
    return {
        "enabled_count": 1234,
        "disabled_count": 8766,
        "rollout_percentage": 12.5
    }
"""
