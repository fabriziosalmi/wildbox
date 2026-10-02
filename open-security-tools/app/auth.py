"""Authentication for the Tools service.

Every request must arrive through the API gateway, carrying the X-Wildbox-*
identity headers and the X-Gateway-Secret proof of origin. Verification is
delegated to the shared `open_security_shared.gateway_auth` dependency.

A static X-API-Key used to be accepted directly here as a legacy/dev path. It
built its identity on the nil UUID, which GatewayUser (UUID4) refuses, so it
answered every call with a server error; it was removed in #565. Personal API
keys still work: the gateway resolves them through identity and forwards the
caller as X-Wildbox-* headers.
"""

from typing import Optional

from fastapi import HTTPException, status, Request, Header

from open_security_shared.gateway_auth import GatewayUser, get_user_from_gateway_headers

from app.logging_config import get_logger

logger = get_logger(__name__)


async def get_current_user(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
    x_gateway_secret: Optional[str] = Header(None, alias="X-Gateway-Secret"),
    request: Request = None,
) -> GatewayUser:
    """Auth dependency: the caller's identity as forwarded by the gateway."""

    # The shared dependency verifies the GATEWAY_INTERNAL_SECRET proof of
    # origin and validates the headers.
    if x_wildbox_user_id and x_wildbox_team_id:
        return await get_user_from_gateway_headers(
            x_wildbox_user_id=x_wildbox_user_id,
            x_wildbox_team_id=x_wildbox_team_id,
            x_wildbox_role=x_wildbox_role,
            x_gateway_secret=x_gateway_secret,
        )

    client = request.client.host if request and request.client else "unknown"
    logger.warning(f"Unauthenticated request from {client}")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Access the tools service through the gateway.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# Alias for backward compatibility
verify_api_key = get_current_user
