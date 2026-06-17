"""
Gateway Authentication for Responder Service

This module provides authentication by trusting headers injected by the gateway.
The gateway validates API keys and JWT tokens, then injects trusted headers
that this service uses to identify and authorize users.

Security Model:
- Gateway performs authentication (API key or JWT validation)
- Gateway injects X-Wildbox-* headers after successful auth
- This service trusts these headers (they're never exposed externally)
- Legacy Bearer token support maintained during migration period

Migration Strategy:
- Priority 1: Check for gateway headers (X-Wildbox-User-ID, etc.)
- Priority 2: Fall back to Bearer token (legacy authentication)
- This allows gradual migration without breaking existing clients
"""

import hmac
import logging
import os
from typing import Optional
from uuid import UUID

from fastapi import Header, HTTPException, status, Depends

# Try to import shared gateway_auth module (if available)
try:
    from open_security_shared.gateway_auth import GatewayUser, get_user_from_gateway_headers
    SHARED_AUTH_AVAILABLE = True
except ImportError:
    SHARED_AUTH_AVAILABLE = False
    
    # Fallback: Define GatewayUser locally if shared module not available
    from pydantic import BaseModel, Field
    
    class GatewayUser(BaseModel):
        """User model populated from gateway-injected headers"""
        user_id: UUID = Field(..., description="User's unique identifier")
        team_id: UUID = Field(..., description="User's team identifier")
        role: str = Field(default="member", description="User role (owner, admin, member)")
        
        class Config:
            frozen = True  # Immutable for security

logger = logging.getLogger(__name__)


def _verify_gateway_origin(provided_secret: Optional[str]) -> None:
    """Reject forged X-Wildbox-* headers: only the gateway holds the shared
    secret. The service port is reachable directly, so without this a client
    could forge identity headers. Enforced when the secret is configured."""
    expected = os.getenv("GATEWAY_INTERNAL_SECRET")
    if not expected:
        logger.warning("GATEWAY_INTERNAL_SECRET not set — cannot verify gateway origin")
        return
    if not provided_secret or not hmac.compare_digest(provided_secret, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Direct access is not permitted; requests must traverse the gateway.",
        )


async def get_current_user(
    x_wildbox_user_id: Optional[str] = Header(None),
    x_wildbox_team_id: Optional[str] = Header(None),
    x_wildbox_role: Optional[str] = Header(None),
    x_gateway_secret: Optional[str] = Header(None, alias="X-Gateway-Secret"),
) -> GatewayUser:
    """
    Get current user from gateway headers or legacy Bearer token.
    
    Authentication Priority:
    1. Gateway headers (X-Wildbox-*) - PREFERRED
    2. Bearer token - LEGACY (for backward compatibility during migration)
    
    Args:
        x_wildbox_user_id: User ID injected by gateway
        x_wildbox_team_id: Team ID injected by gateway
        x_wildbox_role: User role injected by gateway
        authorization: Legacy Bearer token (optional)
    
    Returns:
        GatewayUser: Authenticated user information
    
    Raises:
        HTTPException: 401 if authentication fails
        HTTPException: 403 if gateway bypass attempt detected
    """
    
    # Priority 1: Check for gateway headers
    if x_wildbox_user_id and x_wildbox_team_id:
        _verify_gateway_origin(x_gateway_secret)
        try:
            # Validate UUIDs
            user_id = UUID(x_wildbox_user_id)
            team_id = UUID(x_wildbox_team_id)
            
            # Create gateway user
            user = GatewayUser(
                user_id=user_id,
                team_id=team_id,
                role=x_wildbox_role or "member"
            )
            
            logger.info(f"🔐 Gateway auth successful - User: {user_id}, Team: {team_id}")
            return user
            
        except ValueError as e:
            logger.error(f"❌ Invalid gateway header format: {e}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authentication headers - possible bypass attempt"
            )
    
    # No valid authentication found
    logger.error("Authentication failed - no gateway headers provided")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Use X-API-Key header or contact support.",
        headers={"WWW-Authenticate": "Bearer"}
    )


# Dependency factory for role-based access control


def require_role(*allowed_roles: str):
    """
    Dependency factory for role-based access control.
    
    Usage:
        @app.delete("/admin/users/{user_id}")
        async def delete_user(
            user_id: str,
            user: GatewayUser = Depends(require_role("owner", "admin"))
        ):
            # Only owners and admins can delete users
            pass
    
    Args:
        *allowed_roles: Variable number of allowed role names
    
    Returns:
        Dependency function that validates user's role
    """
    async def _check_role(user: GatewayUser = Depends(get_current_user)) -> GatewayUser:
        if user.role not in allowed_roles:
            logger.warning(f"⚠️ Role restriction violation - User role: {user.role}, Required: {allowed_roles}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of these roles: {', '.join(allowed_roles)}"
            )
        return user
    
    return _check_role
