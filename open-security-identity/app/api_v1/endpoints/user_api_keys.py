"""
User-friendly API Key endpoints that don't require team_id in path.
These endpoints automatically use the user's primary team, and act on the
caller's own keys only: a team's keys as a whole are managed through the
team routes (api_keys.py), which check the caller's role.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from typing import List

from ...database import get_db
from ...models import User, Team, TeamMembership, ApiKey, TeamRole
from ...schemas import ApiKeyCreate, ApiKeyResponse, ApiKeyWithSecret
from ...auth import generate_api_key
from ...access_revocation import revoke_api_keys_or_503
from ...user_manager import current_active_user

router = APIRouter()


async def get_user_primary_team(
    current_user: User,
    db: AsyncSession
) -> Team:
    """
    Get user's primary team (first team they own or are a member of).
    """
    # First, try to find a team they own
    result = await db.execute(
        select(Team)
        .join(TeamMembership, Team.id == TeamMembership.team_id)
        .where(
            and_(
                TeamMembership.user_id == current_user.id,
                TeamMembership.role == TeamRole.OWNER
            )
        )
        .limit(1)
    )
    team = result.scalar_one_or_none()

    if team:
        return team

    # If not an owner, get first team they're a member of
    result = await db.execute(
        select(Team)
        .join(TeamMembership, Team.id == TeamMembership.team_id)
        .where(TeamMembership.user_id == current_user.id)
        .limit(1)
    )
    team = result.scalar_one_or_none()

    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User is not a member of any team. Please join or create a team first."
        )

    return team


@router.post("/api-keys", response_model=ApiKeyWithSecret)
async def create_user_api_key(
    key_data: ApiKeyCreate,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new API key for the current user's primary team.

    Returns the full API key only once - it cannot be retrieved later.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)

    # Generate API key
    full_key, prefix, hashed_key = generate_api_key()

    # Create API key record
    api_key = ApiKey(
        hashed_key=hashed_key,
        prefix=prefix,
        user_id=current_user.id,
        team_id=team.id,
        name=key_data.name,
        # Never store JSON null. The column is NOT NULL with a [] default
        # (alembic f5a6b7c8d9e0) precisely so that "unrestricted" is a value
        # somebody wrote rather than an absence somebody inferred -- but
        # SQLAlchemy serialises a Python None into a JSON column as JSON null,
        # which satisfies NOT NULL and reinstates the ambiguity. An omitted
        # scopes list means unrestricted, and that is written as ["*"], the same
        # value the migration gave legacy rows and the one the gateway checks
        # for. Clients cannot request "*" themselves; the schema vocabulary
        # rejects it.
        scopes=key_data.scopes if key_data.scopes is not None else ["*"],
        expires_at=key_data.expires_at
    )

    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    # Return the key with the secret (only time it's shown)
    return ApiKeyWithSecret(
        id=api_key.id,
        prefix=api_key.prefix,
        user_id=api_key.user_id,
        team_id=api_key.team_id,
        name=api_key.name,
        scopes=api_key.scopes,
        is_active=api_key.is_active,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        key=full_key  # The secret key - only shown once
    )


@router.get("/api-keys", response_model=List[ApiKeyResponse])
async def list_user_api_keys(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List the current user's own API keys in their primary team.

    Does not return the actual key values, only metadata. A team's
    other keys are listed by the team route, GET /teams/{team_id}/api-keys.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)

    # The caller's own active keys (#664): these routes are self-service,
    # and the revoke below acts on the caller's keys only, so the list
    # shows the keys it can revoke. Revoked keys are soft-deleted
    # (is_active=False) and are inert, so they're excluded from the listing.
    result = await db.execute(
        select(ApiKey)
        .where(
            ApiKey.team_id == team.id,
            ApiKey.user_id == current_user.id,
            ApiKey.is_active == True,
        )
        .order_by(ApiKey.created_at.desc())
    )
    api_keys = result.scalars().all()

    return api_keys


@router.delete("/api-keys/{key_prefix}")
async def revoke_user_api_key(
    key_prefix: str,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke (deactivate) one of the current user's own API keys.

    Team owners and admins revoke another member's key through the team
    route, DELETE /teams/{team_id}/api-keys/{key_prefix}, which checks
    their role.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)

    # The caller's own key only (#664). This selected by team and prefix,
    # so any member could revoke a teammate's or the owner's key. Another
    # user's key answers 404, as a key that does not exist does.
    result = await db.execute(
        select(ApiKey)
        .where(
            and_(
                ApiKey.team_id == team.id,
                ApiKey.user_id == current_user.id,
                ApiKey.prefix == key_prefix,
                ApiKey.is_active == True
            )
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )

    # The gateway first (#593): it caches the decision for a key, and would
    # go on accepting a key that is only marked inactive here until that
    # decision expired. If it cannot confirm, the key stays active and the
    # revocation answers 503, to be repeated.
    await revoke_api_keys_or_503([api_key.id], "The API key revocation")

    # Deactivate the key
    api_key.is_active = False
    await db.commit()

    return {"message": "API key revoked successfully"}


@router.get("/api-keys/{key_prefix}", response_model=ApiKeyResponse)
async def get_user_api_key(
    key_prefix: str,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of one of the current user's own API keys.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)

    # The caller's own key only, as for the list and the revoke (#664).
    result = await db.execute(
        select(ApiKey)
        .where(
            and_(
                ApiKey.team_id == team.id,
                ApiKey.user_id == current_user.id,
                ApiKey.prefix == key_prefix
            )
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )

    return api_key
