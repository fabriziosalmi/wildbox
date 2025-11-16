"""
User-friendly API Key endpoints that don't require team_id in path.
These endpoints automatically use the user's primary team.
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
    List all API keys for the current user's primary team.

    Does not return the actual key values, only metadata.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)

    # Get all API keys for the team
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.team_id == team.id)
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
    Revoke (deactivate) an API key from the user's primary team.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)

    # Find the API key
    result = await db.execute(
        select(ApiKey)
        .where(
            and_(
                ApiKey.team_id == team.id,
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
    Get details of a specific API key from the user's primary team.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)

    # Find the API key
    result = await db.execute(
        select(ApiKey)
        .where(
            and_(
                ApiKey.team_id == team.id,
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
