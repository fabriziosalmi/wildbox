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
from .models import User, Team, TeamMembership, ApiKey
from .schemas import AuthorizationResponse
from .auth import verify_access_token
from .config import settings
from datetime import datetime
import hmac
import logging

logger = logging.getLogger(__name__)

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
    # Validate gateway secret: only the gateway should call this endpoint
    if not settings.gateway_internal_secret:
        logger.error("GATEWAY_INTERNAL_SECRET not configured - rejecting /authorize call")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service misconfigured"
        )
    if not x_gateway_secret or not hmac.compare_digest(
        x_gateway_secret, settings.gateway_internal_secret
    ):
        logger.warning("Unauthorized /authorize call: invalid or missing gateway secret")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid gateway secret"
        )
    
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

            # Revocation applies to gateway traffic.
            #
            # is_token_blacklisted() existed and was consulted only by identity's
            # own get_current_user dependency -- which gateway-mediated requests
            # never reach -- so a revoked token was still authorised for every
            # service in the system (WILDBO-AUTH-01).
            from .token_blacklist import is_token_blacklisted

            jti = payload.get("jti")
            if jti and await is_token_blacklisted(jti):
                logger.info(f"Rejected revoked token (jti={jti})")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                )
            
            # Get user with team info.
            #
            # ORDER BY makes the selection deterministic. Without it, a user who
            # belongs to more than one team got whichever row PostgreSQL happened
            # to return first, so the tenant their request ran against -- and the
            # role its permissions derived from -- could vary between two
            # requests with the same token (WILDBO-AUTH-05).
            #
            # The team is preferred from the token when it carries one, so a
            # session is bound to the team it was issued for; otherwise the
            # oldest membership wins, which is stable.
            token_team_id = payload.get("team_id")
            query = (
                select(User, Team, TeamMembership)
                .join(TeamMembership, TeamMembership.user_id == User.id)
                .join(Team, TeamMembership.team_id == Team.id)
                .where(User.id == user_id)
                .where(User.is_active == True)
            )
            if token_team_id:
                query = query.where(TeamMembership.team_id == token_team_id)
            query = query.order_by(TeamMembership.joined_at.asc(), Team.id.asc())
            result = await db.execute(query)

            row = result.first()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )

            user, team, membership = row

            # Build authorization response. Bearer (interactive) auth is not
            # scope-limited — scopes=None means unrestricted at the gateway.
            return AuthorizationResponse(
                is_authenticated=True,
                user_id=str(user.id),
                team_id=str(team.id),
                role=membership.role,
                permissions=_get_permissions_for_role(membership.role),
                scopes=None
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
            
            result = await db.execute(
                select(ApiKey, User, Team, TeamMembership)
                .join(User, ApiKey.user_id == User.id)
                .join(Team, ApiKey.team_id == Team.id)
                .join(TeamMembership,
                      (TeamMembership.user_id == User.id) &
                      (TeamMembership.team_id == Team.id))
                .where(
                    ApiKey.hashed_key == hashed_key,
                    ApiKey.is_active == True,
                    User.is_active == True
                )
            )

            row = result.first()

            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or inactive API key"
                )

            api_key_obj, user, team, membership = row
            
            # Check if key is expired
            if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key has expired"
                )
            
            # Update last used timestamp
            api_key_obj.last_used_at = datetime.utcnow()
            await db.commit()

            # API keys carry least-privilege scopes. NULL (legacy key created
            # before scoping) => unrestricted; a list is enforced at the gateway.
            return AuthorizationResponse(
                is_authenticated=True,
                user_id=str(user.id),
                team_id=str(team.id),
                role=membership.role,
                permissions=_get_permissions_for_role(membership.role),
                scopes=api_key_obj.scopes
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
            detail="Authorization failed"
        )


def _get_permissions_for_role(role: str) -> list[str]:
    """Get permissions for a team role.

    With billing/subscriptions removed there are no plan tiers: every
    authenticated user gets the full feature set; owners/admins additionally
    get team and key management.
    """
    permissions = ["tool:basic", "tool:advanced", "feed", "cspm"]
    if role in ["owner", "admin"]:
        permissions.extend(["team:manage", "keys:manage"])
    return permissions

