"""Security implementation for Tools service authentication.

The Tools service accepts authentication in two ways:
1. **Gateway Authentication** (recommended): Requests coming through the API gateway
   with X-Wildbox-* headers injected after user auth validation
2. **Direct API Key** (legacy/development): Direct access with API key for testing

In production, all requests should go through the gateway.
"""

from fastapi import HTTPException, Depends, status, Request, Header
from typing import Optional
import sys
import os

# Add parent directory to path to import shared modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'open-security-shared'))

try:
    from gateway_auth import get_user_from_gateway_headers, GatewayUser
    GATEWAY_AUTH_AVAILABLE = True
except ImportError:
    GATEWAY_AUTH_AVAILABLE = False
    GatewayUser = None
    
    # Fallback if shared module not available
    class _FallbackGatewayUser:
        def __init__(self, user_id: str, team_id: str, plan: str = "free", role: str = "member"):
            self.user_id = user_id
            self.team_id = team_id
            self.plan = plan
            self.role = role
    
    GatewayUser = _FallbackGatewayUser

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


async def get_current_user(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_plan: Optional[str] = Header(None, alias="X-Wildbox-Plan"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    request: Request = None
) -> GatewayUser:
    """
    Unified authentication dependency for Tools service.
    
    Accepts authentication from:
    1. Gateway headers (X-Wildbox-*) - production path
    2. API key (X-API-Key) - legacy/dev path
    
    Args:
        x_wildbox_user_id: User ID from gateway
        x_wildbox_team_id: Team ID from gateway
        x_wildbox_plan: Subscription plan from gateway
        x_wildbox_role: User role from gateway
        x_api_key: Direct API key (fallback)
        request: FastAPI request object
        
    Returns:
        GatewayUser with user information
        
    Raises:
        HTTPException 401: If authentication fails
    """
    
    # Prefer gateway authentication
    if x_wildbox_user_id and x_wildbox_team_id:
        logger.info(f"Gateway-authenticated request: user={x_wildbox_user_id}, team={x_wildbox_team_id}")
        
        if GATEWAY_AUTH_AVAILABLE:
            # Use shared dependency for proper validation
            return await get_user_from_gateway_headers(
                x_wildbox_user_id=x_wildbox_user_id,
                x_wildbox_team_id=x_wildbox_team_id,
                x_wildbox_plan=x_wildbox_plan,
                x_wildbox_role=x_wildbox_role
            )
        else:
            # Fallback without validation (for development)
            logger.warning("Gateway auth module not available, using fallback")
            return GatewayUser(
                user_id=x_wildbox_user_id,
                team_id=x_wildbox_team_id,
                plan=x_wildbox_plan or "free",
                role=x_wildbox_role or "member"
            )
    
    # Fallback to direct API key (legacy/development)
    if x_api_key:
        if x_api_key != settings.get_api_key():
            logger.warning(f"Invalid API key attempt from {request.client.host if request and request.client else 'unknown'}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        logger.info("Direct API key authentication (legacy mode)")
        # Return a generic user for API key auth
        return GatewayUser(
            user_id="00000000-0000-0000-0000-000000000000",  # System user
            team_id="00000000-0000-0000-0000-000000000000",  # System team
            plan="free",
            role="admin"
        )
    
    # No authentication provided
    logger.warning(f"Unauthenticated request from {request.client.host if request and request.client else 'unknown'}")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide X-API-Key header or access via gateway.",
        headers={"WWW-Authenticate": "Bearer"}
    )


# Alias for backward compatibility
verify_api_key = get_current_user
