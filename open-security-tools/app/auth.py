"""Authentication for the Tools service.

Two authentication modes:
1. **Gateway** (production): requests arrive through the API gateway with
   X-Wildbox-* identity headers and the X-Gateway-Secret proof-of-origin. This
   is delegated to the shared `open_security_shared.gateway_auth` dependency.
2. **Direct API key** (legacy/dev): a static X-API-Key. Scoped in #175 to a
   non-privileged "service" identity (no admin role) so it can no longer
   escalate; internal callers (agents) should forward the user's gateway
   identity instead and fall back to this key only transitionally.
"""

from typing import Optional

from fastapi import HTTPException, status, Request, Header

from open_security_shared.gateway_auth import GatewayUser, get_user_from_gateway_headers

from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


async def get_current_user(
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID"),
    x_wildbox_role: Optional[str] = Header(None, alias="X-Wildbox-Role"),
    x_gateway_secret: Optional[str] = Header(None, alias="X-Gateway-Secret"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    request: Request = None,
) -> GatewayUser:
    """Unified auth dependency: gateway headers (preferred) or a legacy API key."""

    # Gateway path (production): the shared dependency verifies the
    # GATEWAY_INTERNAL_SECRET proof-of-origin and validates the headers.
    if x_wildbox_user_id and x_wildbox_team_id:
        return await get_user_from_gateway_headers(
            x_wildbox_user_id=x_wildbox_user_id,
            x_wildbox_team_id=x_wildbox_team_id,
            x_wildbox_role=x_wildbox_role,
            x_gateway_secret=x_gateway_secret,
        )

    # Legacy/dev: direct API key. Scoped (#175) to a non-privileged "service"
    # identity — NOT admin — so a leaked/over-broad key can't perform
    # privileged actions. team_id stays the zero UUID, which under per-team
    # scoping (#178) only ever resolves to global/shared data.
    if x_api_key:
        if x_api_key != settings.get_api_key():
            client = request.client.host if request and request.client else "unknown"
            logger.warning(f"Invalid API key attempt from {client}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        logger.info("Direct API key authentication (legacy service mode)")
        return GatewayUser(
            user_id="00000000-0000-0000-0000-000000000000",
            team_id="00000000-0000-0000-0000-000000000000",
            role="service",
        )

    client = request.client.host if request and request.client else "unknown"
    logger.warning(f"Unauthenticated request from {client}")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide X-API-Key header or access via gateway.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# Alias for backward compatibility
verify_api_key = get_current_user
