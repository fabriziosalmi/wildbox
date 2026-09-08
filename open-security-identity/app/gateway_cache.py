"""
Invalidate the gateway's cached authorization decisions.

The gateway caches each decision for AUTH_CACHE_TTL (default 300s) under a key
derived from the token, and nothing could purge it: disabling a user, deleting an
API key, changing a role or removing a team membership all took effect only when
the entry expired (WILDBO-AUTH-03). Combined with the absence of revocation
(WILDBO-AUTH-01), the practical time-to-cut-off for a stolen token was its full
remaining lifetime.

Best-effort by design: a purge failure must never prevent the state change that
triggered it. The change is already durable in Postgres or the blacklist; the
purge only shortens the window, and the TTL remains the backstop.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_URL = os.getenv(
    "GATEWAY_INTERNAL_URL",
    "http://open-security-gateway/internal/gateway/purge-auth-cache",
)


async def purge_gateway_auth_cache(
    token: Optional[str] = None,
    token_type: str = "bearer",
    timeout: float = 2.0,
) -> bool:
    """
    Ask the gateway to drop cached decisions.

    Pass ``token`` to purge one entry; omit it to flush the whole cache (used when
    a user or key is deactivated, since the identity service does not hold the
    caller's raw token at that point).
    """
    secret = os.getenv("GATEWAY_INTERNAL_SECRET")
    if not secret:
        logger.warning(
            "GATEWAY_INTERNAL_SECRET is not set; cannot purge the gateway auth "
            "cache. Revocation will take effect when the cache entry expires."
        )
        return False

    payload = {"token": token, "token_type": token_type} if token else {}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                _DEFAULT_URL, json=payload, headers={"X-Gateway-Secret": secret}
            )
        if response.status_code == 200:
            return True
        logger.warning(
            "Gateway auth-cache purge returned %s; the entry will expire on its "
            "own TTL",
            response.status_code,
        )
    except Exception as exc:  # noqa: BLE001 - never block the state change
        logger.warning(
            "Gateway auth-cache purge failed (%s); the entry will expire on its "
            "own TTL",
            exc,
        )
    return False
