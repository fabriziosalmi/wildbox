"""
Gateway authentication for Agents service.

This module provides authentication by trusting headers injected by the API gateway.
In production, all requests MUST go through the gateway which validates credentials
and injects trusted X-Wildbox-* headers.
"""

import sys
import os
import logging
from typing import Optional
from pydantic import BaseModel, UUID4

# Add shared modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'open-security-shared'))

try:
    from gateway_auth import get_user_from_gateway_headers as _get_gateway_user, GatewayUser as _GatewayUser, require_role
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
        role: str = "member"
        
        class Config:
            frozen = True

from fastapi import Header, HTTPException, Depends


logger = logging.getLogger(__name__)


def _verify_gateway_origin(provided_secret: Optional[str]) -> None:
    """Reject forged X-Wildbox-* headers: only the gateway holds the shared
    secret. The service port is reachable directly, so without this a client
    could forge identity headers. Enforced when the secret is configured."""
    import hmac
    expected = os.getenv("GATEWAY_INTERNAL_SECRET")
    if not expected:
        logger.error(
            "GATEWAY_INTERNAL_SECRET not configured — refusing to trust gateway "
            "headers (fail-closed)."
        )
        raise HTTPException(
            status_code=503,
            detail="Service misconfigured: GATEWAY_INTERNAL_SECRET is not set.",
        )
    if not provided_secret or not hmac.compare_digest(provided_secret, expected):
        raise HTTPException(status_code=403, detail="Direct access is not permitted; requests must traverse the gateway.")


async def get_current_user(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
    x_gateway_secret: Optional[str] = Header(None, alias="X-Gateway-Secret"),
) -> GatewayUser:
    """
    Primary authentication dependency for Agents service.

    Authenticates via X-Wildbox-* headers injected by the API gateway.

    Returns:
        GatewayUser object with user_id, team_id, role

    Raises:
        HTTPException 401: No authentication provided
    """
    # Priority 1: Gateway headers (production mode)
    if x_wildbox_user_id and x_wildbox_team_id:
        _verify_gateway_origin(x_gateway_secret)
        if GATEWAY_AUTH_AVAILABLE:
            # Use shared gateway auth module
            return await _get_gateway_user(
                x_wildbox_user_id=x_wildbox_user_id,
                x_wildbox_team_id=x_wildbox_team_id,
                x_wildbox_role=x_wildbox_role
            )
        else:
            # Fallback implementation without shared module
            try:
                return GatewayUser(
                    user_id=x_wildbox_user_id,
                    team_id=x_wildbox_team_id,
                    role=x_wildbox_role or "member"
                )
            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                logger.error(f"[AUTH-ERROR] Invalid gateway headers: {e}")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid authentication headers from gateway"
                )
    
    # No authentication provided
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Access via gateway with X-Wildbox-* headers.",
        headers={"WWW-Authenticate": "Bearer"}
    )


__all__ = [
    "get_current_user",
    "GatewayUser"
]

# Re-export gateway auth helpers if available
if GATEWAY_AUTH_AVAILABLE:
    __all__.extend(["require_role"])
