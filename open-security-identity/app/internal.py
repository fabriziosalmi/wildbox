"""
Internal API endpoints for service-to-service communication.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import Optional
from pydantic import BaseModel

from .database import get_db
from .models import User, Team, TeamMembership, ApiKey, Subscription
from .schemas import AuthorizationResponse
from .auth import authenticate_api_key, verify_access_token
from datetime import datetime

router = APIRouter()


class TokenAuthRequest(BaseModel):
    """Request model for token authorization."""
    token: str
    token_type: str  # "bearer" or "api_key"
    request_path: Optional[str] = None
    request_method: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[int] = None


@router.post("/authorize", response_model=AuthorizationResponse)
async def authorize_request(
    request_data: TokenAuthRequest,
    db: AsyncSession = Depends(get_db),
    x_gateway_secret: Optional[str] = Header(None, alias="X-Gateway-Secret")
):
    """
    Internal endpoint for API Gateway to authorize requests.
    
    Validates both JWT tokens and API keys, returns user/team information
    with permissions and rate limits for the API Gateway to make decisions.
    
    Args:
        request_data: Token and request metadata
        db: Database session
        x_gateway_secret: Secret for gateway authentication (optional for now)
    
    Returns:
        Authorization response with user info, permissions, and rate limits
    """
    # Debug logging at endpoint entry
    print(f"[AUTH-DEBUG] ========== AUTHORIZE REQUEST ==========")
    print(f"[AUTH-DEBUG] Token type: {request_data.token_type}")
    print(f"[AUTH-DEBUG] Token preview: {request_data.token[:30] if request_data.token else 'NONE'}...")
    
    # TODO: Validate x_gateway_secret in production
    
    try:
        if request_data.token_type == "bearer":
            # Validate JWT token
            payload = verify_access_token(request_data.token)
            user_id = payload.get("sub")
            
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload"
                )
            
            # Get user with team and subscription info
            result = await db.execute(
                select(User, Team, TeamMembership, Subscription)
                .join(TeamMembership, TeamMembership.user_id == User.id)
                .join(Team, TeamMembership.team_id == Team.id)
                .outerjoin(Subscription, Subscription.team_id == Team.id)
                .where(User.id == user_id)
                .where(User.is_active == True)
            )
            
            row = result.first()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )
            
            user, team, membership, subscription = row
            
            # Get subscription plan
            plan = subscription.plan_id if subscription else "free"
            
            # Build authorization response
            return AuthorizationResponse(
                is_authenticated=True,
                user_id=str(user.id),
                team_id=str(team.id),
                role=membership.role,
                plan=plan,
                permissions=_get_permissions_for_plan_and_role(plan, membership.role),
                rate_limits=_get_rate_limits_for_plan(plan)
            )
            
        elif request_data.token_type == "api_key":
            # Validate API key (existing logic)
            if not request_data.token.startswith("wsk_"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key format"
                )
            
            # Use same hash function as API key generation (HMAC-SHA256)
            from .auth import hash_api_key
            hashed_key = hash_api_key(request_data.token)
            
            # Debug logging
            print(f"[AUTH-DEBUG] Looking for API key with hash: {hashed_key[:20]}...")
            print(f"[AUTH-DEBUG] Full token received: {request_data.token[:30]}...")
            
            result = await db.execute(
                select(ApiKey, User, Team, TeamMembership, Subscription)
                .join(User, ApiKey.user_id == User.id)
                .join(Team, ApiKey.team_id == Team.id)
                .join(TeamMembership,
                      (TeamMembership.user_id == User.id) &
                      (TeamMembership.team_id == Team.id))
                .outerjoin(Subscription, Subscription.team_id == Team.id)
                .where(
                    ApiKey.hashed_key == hashed_key,
                    ApiKey.is_active == True,
                    User.is_active == True
                )
            )
            
            row = result.first()
            print(f"[AUTH-DEBUG] Query result exists: {row is not None}")
            
            if not row:
                print(f"[AUTH-DEBUG] API key NOT FOUND in database")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or inactive API key"
                )
            
            print(f"[AUTH-DEBUG] API key FOUND! User ID: {row[1].id if len(row) > 1 else 'N/A'}")
            
            api_key_obj, user, team, membership, subscription = row
            
            # Check if key is expired
            if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key has expired"
                )
            
            # Update last used timestamp
            api_key_obj.last_used_at = datetime.utcnow()
            await db.commit()
            
            # Get subscription plan
            plan = subscription.plan_id if subscription else "free"
            
            return AuthorizationResponse(
                is_authenticated=True,
                user_id=str(user.id),
                team_id=str(team.id),
                role=membership.role,
                plan=plan,
                permissions=_get_permissions_for_plan_and_role(plan, membership.role),
                rate_limits=_get_rate_limits_for_plan(plan)
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported token type: {request_data.token_type}"
            )
    
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authorization failed: {str(e)}"
        )


def _get_permissions_for_plan_and_role(plan: str, role: str) -> list[str]:
    """Get permissions based on subscription plan and team role."""
    base_permissions = ["tool:basic"]
    
    if plan == "pro":
        base_permissions.extend(["tool:advanced", "feed:basic", "cspm:basic"])
    elif plan == "business":
        base_permissions.extend([
            "tool:advanced", "tool:premium", "feed:premium",
            "cspm:advanced", "api:unlimited"
        ])
    
    if role in ["owner", "admin"]:
        base_permissions.extend(["team:manage", "billing:manage", "keys:manage"])
    
    return list(set(base_permissions))


def _get_rate_limits_for_plan(plan: str) -> dict[str, str]:
    """Get rate limits based on subscription plan."""
    limits = {
        "free": {"default": "100/hour", "api": "50/hour"},
        "pro": {"default": "1000/hour", "api": "500/hour"},
        "business": {"default": "10000/hour", "api": "unlimited"}
    }
    return limits.get(plan, {"default": "10/hour", "api": "5/hour"})

