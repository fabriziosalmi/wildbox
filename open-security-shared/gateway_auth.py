"""
Gateway Authentication Module

This module provides authentication dependencies for backend services that trust
the Wildbox API Gateway's authentication headers.

Architecture:
    Browser/Client → Gateway (validates JWT/API key) → Backend Service (trusts gateway)
    
The gateway validates authentication and injects these headers:
    - X-Wildbox-User-ID: UUID of authenticated user
    - X-Wildbox-Team-ID: UUID of user's team
    - X-Wildbox-Plan: Subscription plan (free, pro, business)
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
        # user.user_id, user.team_id, user.plan, user.role are available
        return {"domain": domain, "user_id": user.user_id}
"""

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
    plan: str = "free"
    role: str = "member"
    
    class Config:
        frozen = True  # Immutable for security


async def get_user_from_gateway_headers(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_plan: Optional[str] = Header(None, alias="X-Wildbox-Plan"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
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
        x_wildbox_plan: Subscription plan injected by gateway
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
    plan = x_wildbox_plan or "free"
    role = x_wildbox_role or "member"
    
    # Validate plan
    valid_plans = {"free", "pro", "business", "enterprise"}
    if plan not in valid_plans:
        logger.warning(f"Unknown subscription plan: {plan}, defaulting to free")
        plan = "free"
    
    # Validate role
    valid_roles = {"owner", "admin", "member", "viewer"}
    if role not in valid_roles:
        logger.warning(f"Unknown role: {role}, defaulting to member")
        role = "member"
    
    logger.debug(f"Gateway auth successful: user={user_id}, team={team_id}, plan={plan}, role={role}")
    
    return GatewayUser(
        user_id=user_id,
        team_id=team_id,
        plan=plan,
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


def require_plan(*required_plans: str):
    """
    Dependency factory for plan-based access control.
    
    Creates a dependency that checks if the user's team has one of the required plans.
    
    Args:
        *required_plans: One or more plan names that are allowed
        
    Returns:
        Dependency function that validates plan
        
    Example:
        ```python
        @router.post("/api/tools/advanced-scan")
        async def advanced_scan(
            target: str,
            user: GatewayUser = Depends(get_user_from_gateway_headers),
            _: None = Depends(require_plan("pro", "business", "enterprise"))
        ):
            # Only pro+ users can use advanced scan
            pass
        ```
    """
    async def plan_checker(user: GatewayUser = Depends(get_user_from_gateway_headers)) -> None:
        if user.plan not in required_plans:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail={
                    "error": "Plan upgrade required",
                    "message": f"This feature requires one of these plans: {', '.join(required_plans)}",
                    "code": "PLAN_UPGRADE_REQUIRED",
                    "current_plan": user.plan
                }
            )
    return plan_checker
