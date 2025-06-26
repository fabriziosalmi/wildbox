"""
Pydantic schemas for request/response models.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from .models import TeamRole, SubscriptionPlan, SubscriptionStatus


# Base schemas
class UserBase(BaseModel):
    email: EmailStr


class TeamBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class ApiKeyBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


# User schemas
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


class UserLogin(BaseModel):
    username: EmailStr  # OAuth2PasswordRequestForm expects 'username'
    password: str


class UserResponse(UserBase):
    id: UUID
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
    stripe_customer_id: Optional[str] = None
    
    class Config:
        from_attributes = True


class UserWithTeams(UserResponse):
    team_memberships: List['TeamMembershipResponse'] = []


# Team schemas
class TeamCreate(TeamBase):
    pass


class TeamResponse(TeamBase):
    id: UUID
    owner_id: UUID
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class TeamWithSubscription(TeamResponse):
    subscription: Optional['SubscriptionResponse'] = None


# Team membership schemas
class TeamMembershipResponse(BaseModel):
    user_id: UUID
    team_id: UUID
    role: TeamRole
    joined_at: datetime
    team: TeamResponse
    
    class Config:
        from_attributes = True


# Subscription schemas
class SubscriptionResponse(BaseModel):
    id: UUID
    team_id: UUID
    stripe_subscription_id: Optional[str] = None
    plan_id: SubscriptionPlan
    status: SubscriptionStatus
    current_period_end: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# API Key schemas
class ApiKeyCreate(ApiKeyBase):
    expires_at: Optional[datetime] = None


class ApiKeyResponse(ApiKeyBase):
    id: UUID
    prefix: str
    user_id: UUID
    team_id: UUID
    is_active: bool
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class ApiKeyWithSecret(ApiKeyResponse):
    """Only returned once when creating a new API key."""
    key: str


# Authentication schemas
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    team_id: Optional[str] = None
    role: Optional[str] = None


# Billing schemas
class CreateCheckoutSessionRequest(BaseModel):
    plan_id: SubscriptionPlan
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None


class CheckoutSessionResponse(BaseModel):
    checkout_url: str


class CustomerPortalResponse(BaseModel):
    portal_url: str


# Authorization response for internal API
class AuthorizationResponse(BaseModel):
    is_authenticated: bool
    user_id: Optional[str] = None
    team_id: Optional[str] = None
    role: Optional[str] = None
    plan: Optional[str] = None
    permissions: List[str] = []
    rate_limits: dict = {}


# Update forward references
UserWithTeams.model_rebuild()
TeamWithSubscription.model_rebuild()

# Additional schemas for extended user management
class UserProfileUpdate(BaseModel):
    email: Optional[EmailStr] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class AccountDeletionRequest(BaseModel):
    password: str
    confirm_deletion: bool = Field(..., description="Must be True to confirm deletion")


class UserStatusUpdate(BaseModel):
    is_active: bool


class TeamRoleUpdate(BaseModel):
    new_role: TeamRole


class UserActivityResponse(BaseModel):
    user_id: str
    email: str
    created_at: datetime
    last_login: Optional[datetime] = None
    team_memberships: List[dict] = []
    active_api_keys: int
    account_status: str


class TeamMembershipInfo(BaseModel):
    team_id: str
    team_name: str
    my_role: str
    subscription_plan: str
    subscription_status: str
    joined_at: datetime


class UserListQuery(BaseModel):
    skip: int = Field(0, ge=0)
    limit: int = Field(100, ge=1, le=1000)
    email_filter: Optional[str] = None
    is_active: Optional[bool] = None
