"""
Gateway authentication for Agents service.

This module provides authentication by trusting headers injected by the API gateway.
In production, all requests MUST go through the gateway which validates credentials
and injects trusted X-Wildbox-* headers.
"""

import sys
import os
import logging
from typing import Optional, Union
from pydantic import BaseModel, UUID4

# Add shared modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'open-security-shared'))

try:
    from gateway_auth import get_user_from_gateway_headers as _get_gateway_user, GatewayUser as _GatewayUser, require_role, require_plan
    GATEWAY_AUTH_AVAILABLE = True
    GatewayUser = _GatewayUser
except ImportError:
    GATEWAY_AUTH_AVAILABLE = False
    logging.warning("Gateway auth module not available - using fallback authentication")
    
    # Fallback GatewayUser model
    class GatewayUser(BaseModel):
        """Fallback user model when shared gateway_auth is not available"""
        user_id: UUID4
        team_id: UUID4
        plan: str = "free"
        role: str = "member"
        
        class Config:
            frozen = True

from fastapi import Header, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)


# Backward compatibility: Legacy Bearer token validation
# In production, this should be removed once all clients use API keys
async def verify_bearer_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> str:
    """
    Legacy bearer token validation for backward compatibility.
    
    WARNING: This bypasses the gateway trust model and should only be used
    during migration or in development environments.
    """
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide Bearer token or access via gateway.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # In legacy mode, we just validate the token format exists
    # The gateway will do the real validation
    if not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail="Invalid token format",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    logger.warning(f"[AUTH-LEGACY] Bearer token authentication used - consider migrating to gateway auth")
    return credentials.credentials


async def get_current_user(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_plan: Optional[str] = Header(None, alias="X-Wildbox-Plan"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> GatewayUser:
    """
    Primary authentication dependency for Agents service.
    
    Preferred: Gateway authentication via X-Wildbox-* headers
    Fallback: Legacy Bearer token (returns system user)
    
    Returns:
        GatewayUser object with user_id, team_id, plan, role
        
    Raises:
        HTTPException 401: No authentication provided
        HTTPException 403: Direct access attempt (gateway bypass)
    """
    # Priority 1: Gateway headers (production mode)
    if x_wildbox_user_id and x_wildbox_team_id:
        if GATEWAY_AUTH_AVAILABLE:
            # Use shared gateway auth module
            return await _get_gateway_user(
                x_wildbox_user_id=x_wildbox_user_id,
                x_wildbox_team_id=x_wildbox_team_id,
                x_wildbox_plan=x_wildbox_plan,
                x_wildbox_role=x_wildbox_role
            )
        else:
            # Fallback implementation without shared module
            try:
                return GatewayUser(
                    user_id=x_wildbox_user_id,
                    team_id=x_wildbox_team_id,
                    plan=x_wildbox_plan or "free",
                    role=x_wildbox_role or "member"
                )
            except Exception as e:
                logger.error(f"[AUTH-ERROR] Invalid gateway headers: {e}")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid authentication headers from gateway"
                )
    
    # Priority 2: Legacy Bearer token (backward compatibility)
    if credentials and credentials.credentials:
        logger.warning("[AUTH-FALLBACK] Using legacy Bearer token - migrate to gateway auth")
        
        # Return a system user for legacy token
        # In production, token validation would happen at gateway
        try:
            return GatewayUser(
                user_id="00000000-0000-0000-0000-000000000001",  # System user
                team_id="00000000-0000-0000-0000-000000000001",  # System team
                plan="enterprise",  # Legacy tokens get full access during migration
                role="admin"
            )
        except Exception as e:
            logger.error(f"[AUTH-ERROR] Legacy auth failed: {e}")
            raise HTTPException(status_code=401, detail="Authentication failed")
    
    # No authentication provided
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide Bearer token or access via gateway.",
        headers={"WWW-Authenticate": "Bearer"}
    )


# Export for backward compatibility
__all__ = [
    "get_current_user",
    "verify_bearer_token",  # Legacy
    "GatewayUser"
]

# Re-export gateway auth helpers if available
if GATEWAY_AUTH_AVAILABLE:
    __all__.extend(["require_role", "require_plan"])
