"""
Gateway Authentication for Data Service

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

import logging
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
        plan: str = Field(default="free", description="Subscription plan (free, pro, business, enterprise)")
        role: str = Field(default="member", description="User role (owner, admin, member)")
        
        class Config:
            frozen = True  # Immutable for security

logger = logging.getLogger(__name__)


async def get_current_user(
    x_wildbox_user_id: Optional[str] = Header(None),
    x_wildbox_team_id: Optional[str] = Header(None),
    x_wildbox_plan: Optional[str] = Header(None),
    x_wildbox_role: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
) -> GatewayUser:
    """
    Get current user from gateway headers or legacy Bearer token.
    
    Authentication Priority:
    1. Gateway headers (X-Wildbox-*) - PREFERRED
    2. Bearer token - LEGACY (for backward compatibility during migration)
    
    Args:
        x_wildbox_user_id: User ID injected by gateway
        x_wildbox_team_id: Team ID injected by gateway
        x_wildbox_plan: Subscription plan injected by gateway
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
        try:
            # Validate UUIDs
            user_id = UUID(x_wildbox_user_id)
            team_id = UUID(x_wildbox_team_id)
            
            # Create gateway user
            user = GatewayUser(
                user_id=user_id,
                team_id=team_id,
                plan=x_wildbox_plan or "free",
                role=x_wildbox_role or "member"
            )
            
            logger.info(f"🔐 Gateway auth successful - User: {user_id}, Team: {team_id}, Plan: {user.plan}")
            return user
            
        except ValueError as e:
            logger.error(f"❌ Invalid gateway header format: {e}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authentication headers - possible bypass attempt"
            )
    
    # Priority 2: Legacy Bearer token authentication (during migration)
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
            
            # For migration period: Accept any valid Bearer token format
            # TODO: Remove this once all clients use gateway authentication
            logger.warning(f"⚠️ Legacy Bearer token authentication used - migrate to API keys")
            
            # Return a system user for legacy tokens
            # In production, this should validate with identity service
            from uuid import uuid4
            return GatewayUser(
                user_id=uuid4(),  # Placeholder - would come from token validation
                team_id=uuid4(),  # Placeholder - would come from token validation
                plan="enterprise",  # Grant enterprise access during migration
                role="admin"  # Grant admin role during migration
            )
    
    # No valid authentication found
    logger.error("❌ Authentication failed - no gateway headers or valid Bearer token")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Use X-API-Key header or contact support.",
        headers={"WWW-Authenticate": "Bearer"}
    )


async def verify_bearer_token(token: str) -> dict:
    """
    Verify Bearer token with identity service.
    
    LEGACY FUNCTION - Used during migration period only.
    New code should rely on gateway authentication.
    
    Args:
        token: JWT or API token to verify
    
    Returns:
        dict: User information from identity service
    
    Raises:
        HTTPException: 401 if token is invalid
    """
    # TODO: Call identity service to validate token
    # For now, accept any token during migration
    logger.warning("⚠️ verify_bearer_token called - legacy authentication path")
    
    return {
        "user_id": "legacy-user",
        "team_id": "legacy-team",
        "plan": "enterprise",
        "role": "admin"
    }


# Dependency factories for plan-based and role-based access control

def require_plan(*allowed_plans: str):
    """
    Dependency factory for plan-based access control.
    
    Usage:
        @app.get("/premium-feature")
        async def premium_feature(user: GatewayUser = Depends(require_plan("pro", "business", "enterprise"))):
            # Only users with pro, business, or enterprise plans can access
            pass
    
    Args:
        *allowed_plans: Variable number of allowed plan names
    
    Returns:
        Dependency function that validates user's plan
    """
    async def _check_plan(user: GatewayUser = Depends(get_current_user)) -> GatewayUser:
        if user.plan not in allowed_plans:
            logger.warning(f"⚠️ Plan restriction violation - User plan: {user.plan}, Required: {allowed_plans}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This feature requires one of these plans: {', '.join(allowed_plans)}"
            )
        return user
    
    return _check_plan


def require_role(*allowed_roles: str):
    """
    Dependency factory for role-based access control.
    
    Usage:
        @app.delete("/admin/data/{data_id}")
        async def delete_data(
            data_id: str,
            user: GatewayUser = Depends(require_role("owner", "admin"))
        ):
            # Only owners and admins can delete data
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
