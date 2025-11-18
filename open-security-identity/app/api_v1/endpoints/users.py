"""
User management endpoints - Admin functionality only.
"""

from datetime import timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ...database import get_db
from ...models import User, Team, TeamMembership, Subscription, TeamRole, SubscriptionPlan, SubscriptionStatus, ApiKey
from ...schemas import (
    UserResponse, UserWithTeams,
    UserProfileUpdate, PasswordChangeRequest, AccountDeletionRequest,
    UserStatusUpdate, TeamRoleUpdate, UserActivityResponse, TeamMembershipInfo
)
from ...user_manager import current_superuser, current_active_user, get_user_manager, UserManager
from ...auth import verify_password, get_password_hash
from ...config import settings

router = APIRouter()


# =============================================================================
# ADMIN USER MANAGEMENT ENDPOINTS
# =============================================================================

@router.get("/users", response_model=List[UserResponse])
async def list_all_users(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    email_filter: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None)
):
    """
    Admin endpoint: List all users in the system.
    
    Requires: Admin role or higher
    """
    # Check if user is admin (owner/admin of any team or superuser)
    if not current_user.is_superuser:
        # Check if user has admin role in any team
        admin_memberships = await db.execute(
            select(TeamMembership)
            .where(
                TeamMembership.user_id == current_user.id,
                TeamMembership.role.in_([TeamRole.OWNER, TeamRole.ADMIN])
            )
        )
        if not admin_memberships.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
    
    # Build query with relationships to get team and subscription data
    query = select(User).options(
        selectinload(User.team_memberships).selectinload(TeamMembership.team).selectinload(Team.subscription)
    )
    
    if email_filter:
        query = query.where(User.email.ilike(f"%{email_filter}%"))
    
    if is_active is not None:
        query = query.where(User.is_active == is_active)
    
    query = query.offset(skip).limit(limit).order_by(User.created_at.desc())
    
    result = await db.execute(query)
    users = result.scalars().all()
    
    # Format response with subscription information
    user_responses = []
    for user in users:
        user_data = {
            "id": str(user.id),
            "email": user.email,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat(),
            "stripe_customer_id": user.stripe_customer_id,
            "team_memberships": []
        }
        
        # Add team memberships with subscription data
        for membership in user.team_memberships:
            membership_data = {
                "user_id": str(membership.user_id),
                "team_id": str(membership.team_id),
                "team_name": membership.team.name,
                "role": membership.role if isinstance(membership.role, str) else membership.role.value,
                "joined_at": membership.joined_at.isoformat()
            }
            
            # Add subscription information if available
            if membership.team.subscription:
                membership_data["subscription"] = {
                    "plan_id": membership.team.subscription.plan_id,
                    "status": membership.team.subscription.status,
                    "current_period_end": membership.team.subscription.current_period_end.isoformat() if membership.team.subscription.current_period_end else None
                }
            
            user_data["team_memberships"].append(membership_data)
        
        user_responses.append(user_data)
    
    return user_responses


@router.get("/users/{user_id}/can-delete")
async def check_user_deletable(
    user_id: str,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Admin endpoint: Check if a user can be safely deleted.
    
    Requires: Superuser role
    """
    # Only superusers can check delete permissions
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    
    # Get user with relationships
    result = await db.execute(
        select(User)
        .options(
            selectinload(User.owned_teams),
            selectinload(User.team_memberships),
            selectinload(User.api_keys)
        )
        .where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check various conditions
    can_delete = True
    can_force_delete = True
    reasons = []
    force_delete_reasons = []
    
    # Cannot delete self
    if user_id == str(current_user.id):
        can_delete = False
        can_force_delete = False
        reasons.append("Cannot delete your own account")
        force_delete_reasons.append("Cannot delete your own account")
    
    # Cannot delete superusers (but can force delete)
    if user.is_superuser:
        can_delete = False
        reasons.append("User is a superuser - use force delete to override")
        force_delete_reasons.append("Will remove superuser privileges and delete")
    
    # Cannot delete users who own teams (but can force delete)
    if user.owned_teams:
        can_delete = False
        team_names = [team.name for team in user.owned_teams]
        reasons.append(f"User owns {len(user.owned_teams)} team(s): {', '.join(team_names)} - use force delete to automatically handle")
        force_delete_reasons.append(f"Will transfer/delete {len(user.owned_teams)} owned team(s): {', '.join(team_names)}")
    
    return {
        "can_delete": can_delete,
        "can_force_delete": can_force_delete,
        "reasons": reasons,
        "force_delete_info": force_delete_reasons if force_delete_reasons else ["User can be safely deleted"],
        "user_info": {
            "email": user.email,
            "is_superuser": user.is_superuser,
            "is_active": user.is_active
        },
        "owned_teams": len(user.owned_teams) if user.owned_teams else 0,
        "team_memberships": len(user.team_memberships) if user.team_memberships else 0,
        "api_keys": len(user.api_keys) if user.api_keys else 0
    }


@router.get("/users/{user_id}", response_model=UserWithTeams)
async def get_user_by_id(
    user_id: str,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Admin endpoint: Get detailed user information by ID.
    
    Requires: Admin role or higher
    """
    # Check admin permissions
    if not current_user.is_superuser:
        admin_memberships = await db.execute(
            select(TeamMembership)
            .where(
                TeamMembership.user_id == current_user.id,
                TeamMembership.role.in_([TeamRole.OWNER, TeamRole.ADMIN])
            )
        )
        if not admin_memberships.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
    
    # Get user with relationships
    result = await db.execute(
        select(User)
        .options(
            selectinload(User.team_memberships)
            .selectinload(TeamMembership.team)
        )
        .where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.patch("/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    is_active: bool,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Admin endpoint: Activate or deactivate a user account.
    
    Requires: Admin role or higher
    """
    # Check admin permissions
    if not current_user.is_superuser:
        admin_memberships = await db.execute(
            select(TeamMembership)
            .where(
                TeamMembership.user_id == current_user.id,
                TeamMembership.role.in_([TeamRole.OWNER, TeamRole.ADMIN])
            )
        )
        if not admin_memberships.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
    
    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent deactivating self
    if user_id == str(current_user.id) and not is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )
    
    # Update status
    user.is_active = is_active
    await db.commit()
    
    return {"message": f"User {'activated' if is_active else 'deactivated'} successfully"}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    force: bool = Query(False, description="Force delete even if user owns teams"),
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Admin endpoint: Delete a user account (hard delete).
    
    Requires: Superuser role
    
    If force=True, superadmins can delete team owners by:
    - Transferring ownership to another admin/member if available
    - Deleting the team if no other members exist
    """
    print(f"DEBUG: Delete user called with user_id={user_id}, force={force}, current_user={current_user.email}")
    
    # Only superusers can delete accounts
    if not current_user.is_superuser:
        print(f"DEBUG: Non-superuser attempted delete: is_superuser={current_user.is_superuser}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    
    # Get user with relationships
    result = await db.execute(
        select(User)
        .options(
            selectinload(User.owned_teams).selectinload(Team.memberships).selectinload(TeamMembership.user),
            selectinload(User.team_memberships),
            selectinload(User.api_keys)
        )
        .where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent deleting self
    if user_id == str(current_user.id):
        print(f"DEBUG: Attempted to delete self: user_id={user_id}, current_user.id={current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    # Prevent deleting superusers (extra protection) - but allow force deletion by superadmin
    if user.is_superuser and not force:
        print(f"DEBUG: Attempted to delete superuser without force: user.is_superuser={user.is_superuser}, force={force}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete superuser accounts. Use force=true to override or remove superuser privileges first."
        )
    
    deleted_teams = []
    transferred_teams = []
    
    # Handle team ownership if user owns teams
    if user.owned_teams:
        if not force:
            team_names = [team.name for team in user.owned_teams]
            print(f"DEBUG: User owns teams and no force flag: owned_teams={len(user.owned_teams)}, force={force}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete user who owns {len(user.owned_teams)} team(s): {', '.join(team_names)}. Use force=true to automatically handle team ownership."
            )
        
        # Force deletion - handle each owned team
        for team in user.owned_teams:
            # Get other team members (excluding the user being deleted)
            other_members = [m for m in team.memberships if m.user_id != user.id]
            
            if not other_members:
                # No other members - delete the team
                deleted_teams.append(team.name)
                await db.delete(team)
            else:
                # Find the best candidate for new ownership (admins first, then members)
                admin_members = [m for m in other_members if m.role == TeamRole.ADMIN]
                
                if admin_members:
                    # Transfer to first admin
                    new_owner = admin_members[0].user
                    team.owner_id = new_owner.id
                    # Update their membership to owner
                    admin_members[0].role = TeamRole.OWNER
                    transferred_teams.append(f"{team.name} -> {new_owner.email}")
                else:
                    # No admins, transfer to first member and promote them
                    new_owner = other_members[0].user
                    team.owner_id = new_owner.id
                    # Update their membership to owner
                    other_members[0].role = TeamRole.OWNER
                    transferred_teams.append(f"{team.name} -> {new_owner.email}")
    
    try:
        # First, explicitly remove the user from all team memberships
        # This must be done before deleting the user to avoid foreign key issues
        for membership in user.team_memberships:
            await db.delete(membership)
        
        # Delete user's API keys
        for api_key in user.api_keys:
            await db.delete(api_key)
        
        # Hard delete user - now safe since relationships are cleaned up
        await db.delete(user)
        await db.commit()
        
        # Build success message
        message = f"User {user.email} deleted successfully"
        if deleted_teams:
            message += f". Deleted {len(deleted_teams)} team(s): {', '.join(deleted_teams)}"
        if transferred_teams:
            message += f". Transferred ownership of {len(transferred_teams)} team(s): {'; '.join(transferred_teams)}"
        
        return {"message": message}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {str(e)}"
        )


@router.patch("/users/{user_id}/superuser")
async def update_user_superuser_status(
    user_id: str,
    superuser_data: dict,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Admin endpoint: Promote or demote a user to/from superuser status.
    
    Requires: Superuser role
    """
    # Only superusers can change superuser status
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    
    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent changing own superuser status
    if user_id == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own superuser status"
        )
    
    # Get the new superuser status from request data
    is_superuser = superuser_data.get("is_superuser", False)
    
    # Update superuser status
    user.is_superuser = is_superuser
    await db.commit()
    
    action = "promoted to" if is_superuser else "demoted from"
    return {"message": f"User {action} superuser successfully"}


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    role_data: dict,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Admin endpoint: Update user role (promote/demote superuser).
    
    Requires: Superuser role
    """
    # Only superusers can change user roles
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    
    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent changing own superuser status
    if user_id == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own role"
        )
    
    # Prevent changing the main superadmin account
    if user.email == 'superadmin@wildbox.com':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change the main superadmin account role"
        )
    
    # Get the new superuser status from request data
    is_superuser = role_data.get("is_superuser", False)
    
    # Update superuser status
    user.is_superuser = is_superuser
    await db.commit()
    
    action = "promoted to" if is_superuser else "demoted from"
    return {"message": f"User {action} superuser successfully"}


# =============================================================================
# USER SELF-MANAGEMENT ENDPOINTS
# =============================================================================

@router.patch("/me/profile", response_model=UserResponse)
async def update_my_profile(
    profile_update: UserProfileUpdate,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User endpoint: Update own profile information.
    """
    updates_made = False
    
    # Update email if provided
    if profile_update.email and profile_update.email != current_user.email:
        # Check if email is already taken
        result = await db.execute(
            select(User).where(User.email == profile_update.email, User.id != current_user.id)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use"
            )
        
        current_user.email = profile_update.email
        updates_made = True
    
    # Update password if provided
    if profile_update.new_password:
        if not profile_update.current_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password required to set new password"
            )
        
        # Verify current password
        if not verify_password(profile_update.current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect current password"
            )
        
        # Hash and set new password
        current_user.hashed_password = get_password_hash(profile_update.new_password)
        updates_made = True
    
    if updates_made:
        await db.commit()
        await db.refresh(current_user)
    
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_my_profile_put(
    profile_update: UserProfileUpdate,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User endpoint: Update own profile information (PUT version).
    """
    return await update_my_profile(profile_update, current_user, db)


@router.put("/me/password")
async def change_my_password_put(
    password_change: PasswordChangeRequest,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User endpoint: Change own password (PUT version).
    """
    return await change_my_password(password_change, current_user, db)


@router.post("/me/change-password")
async def change_my_password(
    password_change: PasswordChangeRequest,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User endpoint: Change own password.
    """
    # Verify current password
    if not verify_password(password_change.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password"
        )
    
    # Hash and set new password
    current_user.hashed_password = get_password_hash(password_change.new_password)
    await db.commit()
    
    return {"message": "Password changed successfully"}


@router.delete("/me/account")
async def delete_my_account(
    deletion_request: AccountDeletionRequest,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User endpoint: Delete own account (requires password confirmation).
    """
    if not deletion_request.confirm_deletion:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account deletion must be confirmed"
        )
    
    # Verify password
    if not verify_password(deletion_request.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password"
        )
    
    # Check if user is the only owner of any teams
    owned_teams = await db.execute(
        select(TeamMembership)
        .join(Team)
        .where(
            TeamMembership.user_id == current_user.id,
            TeamMembership.role == TeamRole.OWNER
        )
    )
    
    for membership in owned_teams.scalars():
        # Check if there are other owners
        other_owners = await db.execute(
            select(TeamMembership)
            .where(
                TeamMembership.team_id == membership.team_id,
                TeamMembership.role == TeamRole.OWNER,
                TeamMembership.user_id != current_user.id
            )
        )
        
        if not other_owners.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete account while being the sole owner of a team. Transfer ownership first."
            )
    
    # Soft delete - deactivate and mark email as deleted
    current_user.is_active = False
    current_user.email = f"deleted_{current_user.id}@example.com"
    await db.commit()
    
    return {"message": "Account deleted successfully"}


@router.get("/me/activity", response_model=UserActivityResponse)
async def get_my_activity_log(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200)
):
    """
    User endpoint: Get own activity/audit log.
    
    Note: This would typically integrate with an audit logging system.
    For now, returns basic account information.
    """
    # Get user's team memberships and API keys
    memberships = await db.execute(
        select(TeamMembership)
        .options(selectinload(TeamMembership.team))
        .where(TeamMembership.user_id == current_user.id)
    )
    
    api_keys = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == current_user.id, ApiKey.is_active == True)
    )
    
    return UserActivityResponse(
        user_id=str(current_user.id),
        email=current_user.email,
        created_at=current_user.created_at,
        last_login=None,  # Would come from audit system
        team_memberships=[
            {
                "team_id": str(m.team_id),
                "team_name": m.team.name,
                "role": m.role.value,
                "joined_at": m.created_at
            }
            for m in memberships.scalars()
        ],
        active_api_keys=len(api_keys.scalars().all()),
        account_status="active" if current_user.is_active else "inactive"
    )


# =============================================================================
# API KEY MANAGEMENT ENDPOINTS  
# =============================================================================

@router.get("/me/api-keys", response_model=List[dict])
async def get_my_api_keys(
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User endpoint: Get all my API keys.
    """
    api_keys = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == current_user.id)
        .order_by(ApiKey.created_at.desc())
    )
    
    keys = []
    for key in api_keys.scalars():
        keys.append({
            "id": str(key.id),
            "name": key.name,
            "prefix": key.prefix,
            "is_active": key.is_active,
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
            "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
            "created_at": key.created_at.isoformat(),
        })
    
    return keys


@router.post("/me/api-keys")
async def create_my_api_key(
    key_data: dict,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User endpoint: Create a new API key.
    """
    import uuid
    from datetime import datetime
    import secrets
    
    # Generate API key
    api_key = secrets.token_urlsafe(32)
    prefix = api_key[:8]
    
    # Get user's primary team
    team_membership = await db.execute(
        select(TeamMembership)
        .where(TeamMembership.user_id == current_user.id)
        .order_by(TeamMembership.created_at.asc())
    )
    primary_membership = team_membership.scalar_one_or_none()
    
    if not primary_membership:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must be a member of a team"
        )
    
    # Create API key record
    new_key = ApiKey(
        id=str(uuid.uuid4()),
        name=key_data.get("name", "API Key"),
        prefix=prefix,
        user_id=str(current_user.id),
        team_id=str(primary_membership.team_id),
        is_active=True,
        expires_at=datetime.fromisoformat(key_data["expires_at"]) if key_data.get("expires_at") else None,
    )
    
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)
    
    return {
        "id": str(new_key.id),
        "name": new_key.name,
        "prefix": new_key.prefix,
        "key": api_key,  # Only returned on creation
        "is_active": new_key.is_active,
        "expires_at": new_key.expires_at.isoformat() if new_key.expires_at else None,
        "created_at": new_key.created_at.isoformat(),
    }


@router.delete("/me/api-keys/{key_id}")
async def delete_my_api_key(
    key_id: str,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User endpoint: Delete an API key.
    """
    # Find the API key
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.id == key_id, ApiKey.user_id == current_user.id)
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    await db.delete(api_key)
    await db.commit()
    
    return {"message": "API key deleted successfully"}


# =============================================================================
# TEAM MANAGEMENT ENDPOINTS (EXTENDED)
# =============================================================================

@router.get("/teams/{team_id}/members")
async def get_team_members(
    team_id: str,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all members of a team.
    """
    # Check if user is a member of this team
    membership_check = await db.execute(
        select(TeamMembership)
        .where(
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == current_user.id
        )
    )
    
    if not membership_check.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Get all team members
    memberships = await db.execute(
        select(TeamMembership)
        .options(selectinload(TeamMembership.user))
        .where(TeamMembership.team_id == team_id)
        .order_by(TeamMembership.created_at.asc())
    )
    
    members = []
    for membership in memberships.scalars():
        members.append({
            "user_id": str(membership.user_id),
            "team_id": str(membership.team_id),
            "role": membership.role.value,
            "joined_at": membership.created_at.isoformat(),
            "user": {
                "id": str(membership.user.id),
                "email": membership.user.email,
                "is_active": membership.user.is_active,
                "created_at": membership.user.created_at.isoformat(),
            }
        })
    
    return members


@router.post("/teams/{team_id}/invite")
async def invite_team_member(
    team_id: str,
    invite_data: dict,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Invite a new member to the team.
    """
    # Check if user has permission to invite
    membership_check = await db.execute(
        select(TeamMembership)
        .where(
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == current_user.id,
            TeamMembership.role.in_([TeamRole.OWNER, TeamRole.ADMIN])
        )
    )
    
    if not membership_check.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner or Admin role required"
        )
    
    # For now, just return success - in a real implementation,
    # this would send an email invitation
    return {"message": "Invitation sent successfully"}


@router.put("/teams/{team_id}")
async def update_team(
    team_id: str,
    team_data: dict,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update team information.
    """
    # Check if user has permission to update team
    membership_check = await db.execute(
        select(TeamMembership)
        .where(
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == current_user.id,
            TeamMembership.role.in_([TeamRole.OWNER, TeamRole.ADMIN])
        )
    )
    
    if not membership_check.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner or Admin role required"
        )
    
    # Get team
    result = await db.execute(select(Team).where(Team.id == team_id))
    team = result.scalar_one_or_none()
    
    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )
    
    # Update team name if provided
    if "name" in team_data:
        team.name = team_data["name"]
    
    await db.commit()
    await db.refresh(team)
    
    return {"message": "Team updated successfully"}


@router.delete("/teams/{team_id}/members/{user_id}")
async def remove_team_member(
    team_id: str,
    user_id: str,
    current_user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Remove a member from the team.
    """
    # Check if user has permission
    membership_check = await db.execute(
        select(TeamMembership)
        .where(
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == current_user.id,
            TeamMembership.role.in_([TeamRole.OWNER, TeamRole.ADMIN])
        )
    )
    
    if not membership_check.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner or Admin role required"
        )
    
    # Find target membership
    target_membership = await db.execute(
        select(TeamMembership)
        .where(
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == user_id
        )
    )
    target = target_membership.scalar_one_or_none()
    
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team member not found"
        )
    
    # Cannot remove yourself
    if user_id == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself from the team"
        )
    
    # Cannot remove the last owner
    if target.role == TeamRole.OWNER:
        other_owners = await db.execute(
            select(TeamMembership)
            .where(
                TeamMembership.team_id == team_id,
                TeamMembership.role == TeamRole.OWNER,
                TeamMembership.user_id != user_id
            )
        )
        
        if not other_owners.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last owner from a team"
            )
    
    await db.delete(target)
    await db.commit()
    
    return {"message": "Member removed successfully"}
