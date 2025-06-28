"""
Database models for Open Security Identity service.

Defines User, Team, TeamMembership, Subscription, and ApiKey models
with proper relationships and constraints.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, String, Text, 
    UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.sql import func
from fastapi_users_db_sqlalchemy import SQLAlchemyBaseUserTableUUID

Base = declarative_base()


class TeamRole(str, Enum):
    """Team membership roles."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class SubscriptionPlan(str, Enum):
    """Available subscription plans."""
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"


class SubscriptionStatus(str, Enum):
    """Subscription status values."""
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    UNPAID = "unpaid"


class User(SQLAlchemyBaseUserTableUUID, Base):
    """User model representing individual users in the system."""
    
    __tablename__ = "users"
    
    # I campi standard (id, email, hashed_password, is_active, is_superuser, is_verified)
    # sono già forniti da SQLAlchemyBaseUserTableUUID.
    # Non serve ridefinirli.
    
    # Timestamps (fastapi-users non li gestisce automaticamente)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Stripe integration
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True, index=True)
    
    # Relationships (aggiornate con sintassi moderna)
    team_memberships: Mapped[list["TeamMembership"]] = relationship("TeamMembership", back_populates="user", cascade="all, delete-orphan")
    owned_teams: Mapped[list["Team"]] = relationship("Team", back_populates="owner")
    api_keys: Mapped[list["ApiKey"]] = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.email}>"


class Team(Base):
    """Team (Organization) model representing groups of users."""
    
    __tablename__ = "teams"
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    
    # Ownership
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    owner = relationship("User", back_populates="owned_teams")
    memberships = relationship("TeamMembership", back_populates="team", cascade="all, delete-orphan")
    subscription = relationship("Subscription", back_populates="team", uselist=False, cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="team", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Team {self.name}>"


class TeamMembership(Base):
    """Many-to-many relationship between Users and Teams with roles."""
    
    __tablename__ = "team_memberships"
    
    # Composite primary key
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)
    team_id = Column(UUID(as_uuid=True), ForeignKey("teams.id"), primary_key=True)
    
    # Role information
    role = Column(String(50), nullable=False, default=TeamRole.MEMBER.value)
    
    # Timestamps
    joined_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="team_memberships")
    team = relationship("Team", back_populates="memberships")
    
    def __repr__(self):
        return f"<TeamMembership user={self.user_id} team={self.team_id} role={self.role}>"


class Subscription(Base):
    """Subscription model for team billing."""
    
    __tablename__ = "subscriptions"
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Team relationship (one-to-one)
    team_id = Column(UUID(as_uuid=True), ForeignKey("teams.id"), unique=True, nullable=False)
    
    # Stripe integration
    stripe_subscription_id = Column(String(255), unique=True, nullable=True, index=True)
    
    # Subscription details
    plan_id = Column(String(50), nullable=False, default=SubscriptionPlan.FREE.value)
    status = Column(String(50), nullable=False, default=SubscriptionStatus.ACTIVE.value)
    
    # Billing period
    current_period_end = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    team = relationship("Team", back_populates="subscription")
    
    def __repr__(self):
        return f"<Subscription team={self.team_id} plan={self.plan_id} status={self.status}>"


class ApiKey(Base):
    """API Key model for service-to-service authentication."""
    
    __tablename__ = "api_keys"
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Key data
    hashed_key = Column(String(255), unique=True, nullable=False, index=True)
    prefix = Column(String(10), nullable=False, index=True)  # e.g., "wsk_abc1"
    
    # Ownership
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    team_id = Column(UUID(as_uuid=True), ForeignKey("teams.id"), nullable=False)
    
    # Metadata
    name = Column(String(255), nullable=False)  # User-provided description
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Expiration and usage tracking
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    team = relationship("Team", back_populates="api_keys")
    
    # Indexes
    __table_args__ = (
        Index("ix_api_keys_team_active", "team_id", "is_active"),
        Index("ix_api_keys_prefix_active", "prefix", "is_active"),
    )
    
    def __repr__(self):
        return f"<ApiKey {self.prefix} team={self.team_id} active={self.is_active}>"
