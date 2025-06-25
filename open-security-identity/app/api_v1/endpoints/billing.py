"""
Billing and subscription management endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ...database import get_db
from ...models import User, Team, TeamMembership, Subscription, TeamRole
from ...schemas import (
    CreateCheckoutSessionRequest, CheckoutSessionResponse, 
    CustomerPortalResponse
)
from ...auth import get_current_active_user
from ...billing import billing_service
from ...config import settings

router = APIRouter()


async def get_user_primary_team(user: User, db: AsyncSession) -> Team:
    """
    Get the user's primary team (owned team or first team).
    """
    # Refresh user with team memberships
    result = await db.execute(
        select(User)
        .options(
            selectinload(User.team_memberships)
            .selectinload(TeamMembership.team)
        )
        .where(User.id == user.id)
    )
    user = result.scalar_one()
    
    # Find owned team first
    for membership in user.team_memberships:
        if membership.role == TeamRole.OWNER:
            return membership.team
    
    # Fall back to first team
    if user.team_memberships:
        return user.team_memberships[0].team
    
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="User has no team"
    )


@router.post("/create-checkout-session", response_model=CheckoutSessionResponse)
async def create_checkout_session(
    request: CreateCheckoutSessionRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a Stripe Checkout session for subscription upgrade.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)
    
    # Check if user is team owner
    result = await db.execute(
        select(TeamMembership)
        .where(
            TeamMembership.user_id == current_user.id,
            TeamMembership.team_id == team.id,
            TeamMembership.role == TeamRole.OWNER
        )
    )
    membership = result.scalar_one_or_none()
    
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team owners can manage subscriptions"
        )
    
    # Set default URLs if not provided
    success_url = request.success_url or f"{settings.frontend_url}/billing/success"
    cancel_url = request.cancel_url or f"{settings.frontend_url}/billing/cancel"
    
    # Create checkout session
    checkout_url = await billing_service.create_checkout_session(
        team=team,
        plan_id=request.plan_id,
        success_url=success_url,
        cancel_url=cancel_url
    )
    
    return CheckoutSessionResponse(checkout_url=checkout_url)


@router.post("/create-portal-session", response_model=CustomerPortalResponse)
async def create_customer_portal_session(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a Stripe Customer Portal session for subscription management.
    """
    # Get user's primary team
    team = await get_user_primary_team(current_user, db)
    
    # Check if user is team owner
    result = await db.execute(
        select(TeamMembership)
        .where(
            TeamMembership.user_id == current_user.id,
            TeamMembership.team_id == team.id,
            TeamMembership.role == TeamRole.OWNER
        )
    )
    membership = result.scalar_one_or_none()
    
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team owners can manage subscriptions"
        )
    
    # Create portal session
    return_url = f"{settings.frontend_url}/billing"
    portal_url = await billing_service.create_customer_portal_session(
        team=team,
        return_url=return_url
    )
    
    return CustomerPortalResponse(portal_url=portal_url)
