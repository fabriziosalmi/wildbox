"""
User authentication endpoints.
"""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ...database import get_db
from ...models import User, Team, TeamMembership, Subscription, TeamRole, SubscriptionPlan, SubscriptionStatus
from ...schemas import UserCreate, UserResponse, UserWithTeams, Token
from ...auth import (
    verify_password, get_password_hash, create_access_token, 
    get_current_active_user
)
from ...billing import billing_service
from ...config import settings

router = APIRouter()


@router.post("/register", response_model=Token)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user account.
    
    Creates a new user, team (with user as owner), and free subscription.
    Returns an access token for immediate authentication.
    """
    # Check if user already exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    hashed_password = get_password_hash(user_data.password)
    user = User(
        email=user_data.email,
        hashed_password=hashed_password
    )
    db.add(user)
    await db.flush()  # Get user.id without committing
    
    # Create Stripe customer
    try:
        stripe_customer_id = await billing_service.create_customer(user)
        user.stripe_customer_id = stripe_customer_id
    except Exception as e:
        # Log error but don't fail registration
        print(f"Failed to create Stripe customer: {e}")
    
    # Create team with user as owner
    team = Team(
        name=f"{user_data.email}'s Team",
        owner_id=user.id
    )
    db.add(team)
    await db.flush()  # Get team.id
    
    # Create team membership
    membership = TeamMembership(
        user_id=user.id,
        team_id=team.id,
        role=TeamRole.OWNER
    )
    db.add(membership)
    
    # Create free subscription
    subscription = Subscription(
        team_id=team.id,
        plan_id=SubscriptionPlan.FREE,
        status=SubscriptionStatus.ACTIVE
    )
    db.add(subscription)
    
    await db.commit()
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.jwt_access_token_expire_minutes)
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "team_id": str(team.id),
            "role": TeamRole.OWNER.value
        },
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.jwt_access_token_expire_minutes * 60
    }


@router.post("/login", response_model=Token)
async def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return access token.
    """
    # Find user by email
    result = await db.execute(
        select(User)
        .options(selectinload(User.team_memberships).selectinload(TeamMembership.team))
        .where(User.email == form_data.username)
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    # Get primary team (first team or owned team)
    primary_membership = None
    for membership in user.team_memberships:
        if membership.role == TeamRole.OWNER:
            primary_membership = membership
            break
    
    if not primary_membership and user.team_memberships:
        primary_membership = user.team_memberships[0]
    
    if not primary_membership:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User has no team membership"
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.jwt_access_token_expire_minutes)
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "team_id": str(primary_membership.team_id),
            "role": primary_membership.role.value
        },
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer", 
        "expires_in": settings.jwt_access_token_expire_minutes * 60
    }


@router.get("/me", response_model=UserWithTeams)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user information with team memberships.
    """
    # Refresh user data with relationships
    result = await db.execute(
        select(User)
        .options(
            selectinload(User.team_memberships)
            .selectinload(TeamMembership.team)
        )
        .where(User.id == current_user.id)
    )
    user = result.scalar_one()
    
    return user
