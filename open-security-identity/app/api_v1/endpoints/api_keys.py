"""
API Key management endpoints.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
from typing import List

from ...database import get_db
from ...models import User, Team, TeamMembership, ApiKey, TeamRole
from ...schemas import ApiKeyCreate, ApiKeyResponse, ApiKeyWithSecret
from ...auth import generate_api_key
from ...user_manager import current_active_user

router = APIRouter()


async def get_team_and_check_permission(
    team_id: str,
    current_user: User,
    db: AsyncSession,
    required_role: TeamRole = TeamRole.ADMIN
) -> Team:
    """
    Get team and check if user has required permissions.
    """
    # Get team and user's membership
    result = await db.execute(
        select(Team, TeamMembership)
        .join(TeamMembership, Team.id == TeamMembership.team_id)
        .where(
            and_(
                Team.id == team_id,
                TeamMembership.user_id == current_user.id
            )
        )
    )
    row = result.first()
    
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found or user not a member"
        )
    
    team, membership = row
    
    # Check permissions (owner can do anything, admin can manage keys)
    if membership.role not in [TeamRole.OWNER, required_role]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    return team


@router.post("/{team_id}/api-keys", response_model=ApiKeyWithSecret)
async def create_api_key(
    key_data: ApiKeyCreate,
    team_id: str = Path(..., description="Team ID"),
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new API key for the team.
    
    Returns the full API key only once - it cannot be retrieved later.
    """
    # Check permissions
    team = await get_team_and_check_permission(team_id, current_user, db, TeamRole.ADMIN)
    
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


@router.get("/{team_id}/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    team_id: str = Path(..., description="Team ID"),
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all API keys for the team.
    
    Does not return the actual key values, only metadata.
    """
    # Check permissions (members can view keys)
    team = await get_team_and_check_permission(team_id, current_user, db, TeamRole.MEMBER)
    
    # Get all API keys for the team
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.team_id == team.id)
        .order_by(ApiKey.created_at.desc())
    )
    api_keys = result.scalars().all()
    
    return api_keys


@router.delete("/{team_id}/api-keys/{key_prefix}")
async def revoke_api_key(
    team_id: str = Path(..., description="Team ID"),
    key_prefix: str = Path(..., description="API key prefix (e.g., wsk_abc1)"),
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke (deactivate) an API key.
    """
    # Check permissions
    team = await get_team_and_check_permission(team_id, current_user, db, TeamRole.ADMIN)
    
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


@router.get("/{team_id}/api-keys/{key_prefix}", response_model=ApiKeyResponse)
async def get_api_key(
    team_id: str = Path(..., description="Team ID"),
    key_prefix: str = Path(..., description="API key prefix"),
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific API key.
    """
    # Check permissions
    team = await get_team_and_check_permission(team_id, current_user, db, TeamRole.MEMBER)
    
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
