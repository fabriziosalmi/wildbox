"""
Pydantic schemas for request/response models.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator

from .models import TeamRole
from .password_policy import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH


"""
Pydantic schemas for request/response models.
"""

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator
from fastapi_users import schemas

from .models import TeamRole


# FastAPI Users schemas
class UserRead(schemas.BaseUser[uuid.UUID]):
    """Schema for reading user data (responses)."""
    created_at: datetime
    updated_at: datetime
    # True until the user changes the initial password a team admin set
    # (#573); the dashboard sends such a user to change it first.
    must_change_password: bool = False
    
    class Config:
        from_attributes = True


class UserCreate(schemas.BaseUserCreate):
    """Schema for creating new users.

    BaseUserCreate does not check the password. The policy is applied by
    UserManager.validate_password() (#583), which registration runs, so a
    refused password answers 400 REGISTER_INVALID_PASSWORD with the reason.
    """


class UserUpdate(schemas.BaseUserUpdate):
    """Schema for updating existing users.

    ``current_password`` is not a field of the user: it re-authenticates a
    change of the caller's own email address (#569), and UserManager.update()
    removes it before anything is written.
    """
    current_password: Optional[str] = None


# Legacy schemas (per compatibilità durante la transizione)
class UserBase(BaseModel):
    email: EmailStr


class TeamBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class ApiKeyBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class UserLogin(BaseModel):
    username: EmailStr  # OAuth2PasswordRequestForm expects 'username'
    password: str


class UserResponse(UserBase):
    id: uuid.UUID
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
    
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


# Team membership schemas
class TeamMembershipResponse(BaseModel):
    user_id: UUID
    team_id: UUID
    role: TeamRole
    joined_at: datetime
    team: TeamResponse

    class Config:
        from_attributes = True


# API Key schemas

# Canonical scope vocabulary (must match the dashboard's availableScopes).
# A key may only be granted scopes from this set; the gateway maps each request
# to a required scope and rejects keys that don't hold an equal-or-greater one.
VALID_API_KEY_SCOPES = frozenset({
    "read", "write", "admin",
    "tools:read", "tools:execute", "tools:admin",
    "data:read", "data:write", "data:delete",
    # Telemetry ingest only: POST /api/v1/data/ingest and nothing else. The
    # key a sensor is given (#628).
    "data:ingest",
    "reports:read", "reports:write",
    "team:read", "team:manage",
})


class ApiKeyCreate(ApiKeyBase):
    expires_at: Optional[datetime] = None
    # Optional for back-compat: omitted/None => unrestricted (legacy behaviour).
    # A list restricts the key to those scopes (enforced at the gateway).
    scopes: Optional[List[str]] = None

    @field_validator("scopes")
    @classmethod
    def _validate_scopes(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        unknown = sorted(set(v) - VALID_API_KEY_SCOPES)
        if unknown:
            raise ValueError(f"Unknown API key scope(s): {', '.join(unknown)}")
        # De-duplicate while preserving order.
        seen: set[str] = set()
        return [s for s in v if not (s in seen or seen.add(s))]


class ApiKeyResponse(ApiKeyBase):
    id: UUID
    prefix: str
    user_id: UUID
    team_id: UUID
    is_active: bool
    scopes: Optional[List[str]] = None
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


# Authorization response for internal API
class AuthorizationResponse(BaseModel):
    is_authenticated: bool
    user_id: Optional[str] = None
    team_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = []
    # API-key scopes for least-privilege enforcement at the gateway.
    # None => unrestricted (interactive/JWT auth, or a legacy key with no scopes).
    scopes: Optional[List[str]] = None
    # The account must change the initial password a team admin chose
    # (#573): the gateway answers 403 PASSWORD_CHANGE_REQUIRED to every
    # request it authenticates for it.
    password_change_required: bool = False
    # The API key this decision is for (#593). The gateway refuses the
    # decision, cached or not, once identity has revoked the key by this id.
    api_key_id: Optional[str] = None
    # When the credential stops being valid, in epoch seconds: the API key's
    # expires_at, or the session token's exp. The gateway does not serve a
    # cached decision past it (#593).
    credential_expires_at: Optional[float] = None


# Update forward references
UserWithTeams.model_rebuild()

# Additional schemas for extended user management
class UserProfileUpdate(BaseModel):
    email: Optional[EmailStr] = None
    # Required to change the email (#569).
    current_password: Optional[str] = None
    # Refused: a password is changed through change-password (#569). Kept in
    # the schema so a request that sends one is told so instead of having the
    # field silently dropped.
    new_password: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    # An early 422 for the length; UserManager.validate_password() applies
    # the whole policy (#583).
    new_password: str = Field(
        ..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH
    )


class AccountDeletionRequest(BaseModel):
    password: str
    confirm_deletion: bool = Field(..., description="Must be True to confirm deletion")


class UserStatusUpdate(BaseModel):
    is_active: bool


class TeamRoleUpdate(BaseModel):
    new_role: TeamRole


class TeamMemberCreate(BaseModel):
    """A new account, created directly in a team by its owner or admin (#573)."""
    email: EmailStr
    # The initial password; the account must change it at its first login.
    password: str = Field(
        ..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH
    )
    role: TeamRole = TeamRole.MEMBER


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
    joined_at: datetime


class UserListQuery(BaseModel):
    skip: int = Field(0, ge=0)
    limit: int = Field(100, ge=1, le=1000)
    email_filter: Optional[str] = None
    is_active: Optional[bool] = None
