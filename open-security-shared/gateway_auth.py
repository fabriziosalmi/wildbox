"""
Gateway Authentication Module

This module provides authentication dependencies for backend services that trust
the Wildbox API Gateway's authentication headers.

Architecture:
    Browser/Client → Gateway (validates JWT/API key) → Backend Service (trusts gateway)
    
The gateway validates authentication and injects these headers:
    - X-Wildbox-User-ID: UUID of authenticated user
    - X-Wildbox-Team-ID: UUID of user's team

    - X-Wildbox-Role: User's role in team (owner, admin, member)

Security Model:
    - Backend services MUST only be accessible through the gateway
    - Direct access to backend services should be blocked at network level
    - If headers are missing, request bypassed the gateway (security violation)
    
Usage:
    from open_security_shared.gateway_auth import get_user_from_gateway_headers, GatewayUser
    
    @app.get("/api/tools/whois")
    async def whois_lookup(
        domain: str,
        user: GatewayUser = Depends(get_user_from_gateway_headers)
    ):
        # user.user_id, user.team_id, user.role are available
        return {"domain": domain, "user_id": user.user_id}
"""

import hmac
import os
from typing import Optional
from fastapi import Header, HTTPException, status, Depends
from pydantic import BaseModel, UUID4
import logging

logger = logging.getLogger(__name__)


class GatewayUser(BaseModel):
    """
    User information extracted from gateway headers.
    
    This represents a user that has been authenticated by the gateway.
    Backend services can trust this data without re-validating credentials.
    """
    user_id: UUID4
    team_id: UUID4
    role: str = "member"
    
    class Config:
        frozen = True  # Immutable for security


async def get_user_from_gateway_headers(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
    x_gateway_secret: Optional[str] = Header(None, alias="X-Gateway-Secret"),
) -> GatewayUser:
    """
    FastAPI dependency that extracts and validates user info from gateway headers.
    
    This dependency should be used in all backend service endpoints that require
    authentication. It trusts that the gateway has already validated the user's
    credentials (JWT or API key).
    
    Security Notes:
        - These headers should NEVER be exposed to external clients
        - The gateway must clear any X-Wildbox-* headers from incoming requests
        - Backend services should only be accessible via the gateway (network isolation)
        
    Args:
        x_wildbox_user_id: User UUID injected by gateway
        x_wildbox_team_id: Team UUID injected by gateway
        x_wildbox_role: User's role in team injected by gateway
        
    Returns:
        GatewayUser: Validated user information
        
    Raises:
        HTTPException 403: If headers are missing (request bypassed gateway)
        HTTPException 400: If headers are malformed
        
    Example:
        ```python
        @router.post("/api/tools/scan")
        async def scan_target(
            target: str,
            user: GatewayUser = Depends(get_user_from_gateway_headers)
        ):
            logger.info(f"Scan requested by user {user.user_id} in team {user.team_id}")
            # Perform scan...
        ```
    """
    
    # Fail closed: without GATEWAY_INTERNAL_SECRET the service cannot verify that
    # a request actually came from the gateway, so the X-Wildbox-* headers can't
    # be trusted at all. Refuse to operate rather than trust forged headers.
    # (Mirrors identity's /authorize, which also returns 503 when unconfigured.)
    expected_secret = os.getenv("GATEWAY_INTERNAL_SECRET")
    if not expected_secret:
        logger.error(
            "GATEWAY_INTERNAL_SECRET not configured — refusing to trust gateway "
            "headers (fail-closed)."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Service misconfigured",
                "message": "GATEWAY_INTERNAL_SECRET is not set; the service cannot "
                           "verify gateway origin and will not trust request headers.",
                "code": "GATEWAY_SECRET_NOT_CONFIGURED",
            },
        )

    # Check if headers are present
    if not x_wildbox_user_id or not x_wildbox_team_id:
        logger.error(
            "Missing gateway authentication headers. "
            "Request may have bypassed the gateway or gateway auth is misconfigured."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Gateway authentication required",
                "message": "This service must be accessed through the API gateway. "
                          "Direct access is not permitted.",
                "code": "GATEWAY_AUTH_REQUIRED"
            }
        )

    # Proof-of-origin: the X-Wildbox-* headers are only trustworthy when the
    # request also carries the shared gateway secret (which the gateway stamps
    # on every proxied request and clients cannot supply). Without it, a request
    # reaching the service directly with forged headers would otherwise be trusted.
    if not x_gateway_secret or not hmac.compare_digest(x_gateway_secret, expected_secret):
        logger.warning("Rejected gateway headers without a valid X-Gateway-Secret")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Gateway authentication required",
                "message": "Direct access is not permitted; requests must traverse the gateway.",
                "code": "GATEWAY_SECRET_REQUIRED",
            },
        )
    
    # Validate UUIDs
    try:
        user_id = UUID4(x_wildbox_user_id)
        team_id = UUID4(x_wildbox_team_id)
    except ValueError as e:
        logger.error(f"Invalid UUID in gateway headers: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Invalid authentication headers",
                "message": "Gateway provided malformed user/team identifiers",
                "code": "INVALID_GATEWAY_HEADERS"
            }
        )
    
    # Default values for optional fields
    role = x_wildbox_role or "member"

    # Validate role
    valid_roles = {"owner", "admin", "member", "viewer"}
    if role not in valid_roles:
        logger.error(f"Invalid role in gateway headers: {role!r}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Invalid authentication headers",
                "message": "Gateway provided invalid user role",
                "code": "INVALID_GATEWAY_HEADERS"
            }
        )
    
    logger.debug(f"Gateway auth successful: user={user_id}, team={team_id}, role={role}")

    return GatewayUser(
        user_id=user_id,
        team_id=team_id,
        role=role
    )


def require_role(*required_roles: str):
    """
    Dependency factory for role-based access control.
    
    Creates a dependency that checks if the user has one of the required roles.
    
    Args:
        *required_roles: One or more role names that are allowed
        
    Returns:
        Dependency function that validates role
        
    Example:
        ```python
        from open_security_shared.gateway_auth import get_user_from_gateway_headers, require_role
        
        @router.delete("/api/teams/{team_id}/members/{user_id}")
        async def remove_member(
            team_id: str,
            user_id: str,
            user: GatewayUser = Depends(get_user_from_gateway_headers),
            _: None = Depends(require_role("owner", "admin"))
        ):
            # Only owners and admins can remove members
            pass
        ```
    """
    async def role_checker(user: GatewayUser = Depends(get_user_from_gateway_headers)) -> None:
        if user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Insufficient permissions",
                    "message": f"This action requires one of these roles: {', '.join(required_roles)}",
                    "code": "INSUFFICIENT_ROLE"
                }
            )
    return role_checker
