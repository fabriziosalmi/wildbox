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
    - X-Wildbox-Auth-Type: how the caller authenticated: "session" (a JWT) or
      "api_key"; a Wildbox service calling for a user says "service"
    - X-Wildbox-Scopes: the scopes of an API key, separated by spaces; absent
      for a session or a service, which are not limited by scopes (#637)

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

A route the gateway guards with an API-key scope checks it again with
``require_scope``, so that a mistake in the gateway's scope map is not the
only thing between a key and the route:

    @app.post("/api/v1/ingest")
    async def ingest(user: GatewayUser = Depends(require_scope("data:ingest"))):
        ...
"""

import hmac
import logging
import os
from typing import Callable, Optional, Tuple

from fastapi import Depends, Header, HTTPException, Request, status
from pydantic import UUID4, BaseModel, ConfigDict

from .scopes import (
    GatewayCredentialError,
    credential_allows,
    parse_auth_type,
    parse_scopes,
    scope_for_method,
)

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
    # How the caller authenticated at the gateway (#637): "session",
    # "api_key" or "service", or None when the request did not say. None
    # satisfies no scope: see has_scope.
    auth_type: Optional[str] = None
    # The scopes the gateway forwarded for an API key, or None when it
    # forwarded none: a session or a service, which are not limited by
    # scopes, or a key that holds no scope at all.
    scopes: Optional[Tuple[str, ...]] = None

    model_config = ConfigDict(
        frozen=True,  # Immutable for security
    )

    def has_scope(self, required: str) -> bool:
        """Whether this caller's credential may do what needs ``required``.

        A session or a service may; an API key may when its scopes satisfy
        ``required`` by the gateway's hierarchy; a caller whose auth type is
        not stated may not. See open_security_shared.scopes.
        """
        return credential_allows(self.auth_type, self.scopes, required)


def _header_value(value) -> Optional[str]:
    """A header as FastAPI resolved it, or None.

    Called directly (a service's own dependency passing the headers on, a
    test), a parameter that was left out holds its ``Header(...)`` default,
    not None. That is a header nobody sent.
    """
    return value if isinstance(value, str) else None


async def get_user_from_gateway_headers(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
    x_gateway_secret: Optional[str] = Header(None, alias="X-Gateway-Secret"),
    x_wildbox_auth_type: Optional[str] = Header(None, alias="X-Wildbox-Auth-Type"),
    x_wildbox_scopes: Optional[str] = Header(None, alias="X-Wildbox-Scopes"),
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
        x_wildbox_auth_type: How the caller authenticated, injected by gateway
        x_wildbox_scopes: The API key's scopes, injected by gateway

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
                "code": "GATEWAY_AUTH_REQUIRED",
            },
        )

    # Proof-of-origin: the X-Wildbox-* headers are only trustworthy when the
    # request also carries the shared gateway secret (which the gateway stamps
    # on every proxied request and clients cannot supply). Without it, a request
    # reaching the service directly with forged headers would otherwise be trusted.
    if not x_gateway_secret or not hmac.compare_digest(
        x_gateway_secret, expected_secret
    ):
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
                "code": "INVALID_GATEWAY_HEADERS",
            },
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
                "code": "INVALID_GATEWAY_HEADERS",
            },
        )

    # What the credential is and what it may do (#637). Read strictly: a
    # value this service cannot read is refused, not taken for "no limit".
    try:
        auth_type = parse_auth_type(_header_value(x_wildbox_auth_type))
        scopes = parse_scopes(_header_value(x_wildbox_scopes))
    except GatewayCredentialError as e:
        logger.error(f"Invalid credential description in gateway headers: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Invalid authentication headers",
                "message": "Gateway provided a malformed auth type or scope list",
                "code": "INVALID_GATEWAY_HEADERS",
            },
        )

    logger.debug(
        f"Gateway auth successful: user={user_id}, team={team_id}, role={role}, "
        f"auth_type={auth_type}"
    )

    return GatewayUser(
        user_id=user_id,
        team_id=team_id,
        role=role,
        auth_type=auth_type,
        scopes=scopes,
    )


def _refuse_scope(user: GatewayUser, required: str) -> None:
    """Raise the 403 for a caller that may not do what needs ``required``.

    The shared error handlers (errors.py) show ``message`` and keep the
    dict readable as ``error.details``: the code, and the scope that was
    required, as the gateway's own refusal names it.
    """
    if user.auth_type is None:
        # Not a key without the scope: nothing says what the credential is.
        # A gateway from before #637 does not send the header.
        logger.warning(
            "Refused a request that needs scope %s: the gateway did not state the auth type",
            required,
        )
        message = (
            "The gateway did not say how the caller authenticated (X-Wildbox-Auth-Type). "
            "Upgrade the gateway together with this service."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Gateway authentication required",
                "message": message,
                "code": "GATEWAY_AUTH_TYPE_REQUIRED",
                "required_scope": required,
            },
        )
    logger.warning(
        "Refused user %s: the API key lacks scope %s", user.user_id, required
    )
    message = "This API key is not authorized for this operation."
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "insufficient_scope",
            "message": message,
            "code": "INSUFFICIENT_SCOPE",
            "required_scope": required,
        },
    )


def require_scope(
    required: Optional[str] = None,
    *,
    read: Optional[str] = None,
    write: Optional[str] = None,
    delete: Optional[str] = None,
    user_dependency: Callable = get_user_from_gateway_headers,
):
    """
    Dependency factory: the caller, if their credential has the scope.

    The gateway already refuses an API key that lacks the scope a route
    needs. This is the same check made by the service, on the scopes the
    gateway forwards, so that a mistake in the gateway's map is not the only
    thing between a key and the route (#637). It returns the user, so it
    stands in for the service's authentication dependency.

    A session, and a Wildbox service calling for a user, are not limited by
    scopes and pass. An API key passes when its scopes satisfy the required
    one by the gateway's hierarchy. A request whose auth type is missing is
    refused.

    Name one scope for a route, or the scopes the gateway requires by method
    for a service whose routes all follow that rule: ``read`` for GET, HEAD
    and OPTIONS, ``delete`` for DELETE when one is named, ``write`` for
    every other method.

    Args:
        required: The scope, as the gateway names it ("data:ingest").
        read, write, delete: The scopes by method, instead of ``required``.
        user_dependency: The service's own authentication dependency, when
            it has one that wraps get_user_from_gateway_headers.

    Example:
        ```python
        @app.post("/api/v1/ingest")
        async def ingest(user: GatewayUser = Depends(require_scope("data:ingest"))):
            ...

        # Every other route of the service: "read" to read, "write" to change.
        get_current_user = require_scope(read="read", write="write")
        ```
    """
    by_method = read is not None or write is not None or delete is not None
    if required is not None and by_method:
        raise ValueError(
            "require_scope takes one scope or the scopes by method, not both"
        )
    if required is None and not (read and write):
        raise ValueError(
            "require_scope needs a scope, or both a read and a write scope"
        )

    async def scope_checker(
        request: Request,
        user: GatewayUser = Depends(user_dependency),
    ) -> GatewayUser:
        needed = required or scope_for_method(request.method, read, write, delete)
        if not user.has_scope(needed):
            _refuse_scope(user, needed)
        return user

    return scope_checker


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

    async def role_checker(
        user: GatewayUser = Depends(get_user_from_gateway_headers),
    ) -> None:
        if user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Insufficient permissions",
                    "message": f"This action requires one of these roles: {', '.join(required_roles)}",
                    "code": "INSUFFICIENT_ROLE",
                },
            )

    return role_checker
