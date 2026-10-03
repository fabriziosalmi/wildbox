"""
Invalidate the gateway's cached authorization decisions.

The gateway caches each decision for AUTH_CACHE_TTL (default 300s) under a key
derived from the token, and nothing could purge it: disabling a user, deleting an
API key, changing a role or removing a team membership all took effect only when
the entry expired (WILDBO-AUTH-03). Combined with the absence of revocation
(WILDBO-AUTH-01), the practical time-to-cut-off for a stolen token was its full
remaining lifetime.

Every revocation is confirmed (#571). It backs a change that must not
report success while the gateway can still serve the credential: a logout
(``revoke_jtis_at_gateway()``), a password change
(``revoke_user_sessions_at_gateway()``, #569) and an API key disabled
(``revoke_api_keys_at_gateway()``, #593). Each retries, and raises unless the
gateway confirms every item it was given. The best-effort full flush that
user deactivation used, ``purge_gateway_auth_cache()``, is gone with #593:
deactivation now revokes the account's keys and sessions the same way.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Collection, Mapping, Optional

import httpx

logger = logging.getLogger(__name__)

# Port 8081 is the gateway's internal listener. The old default had no port,
# i.e. 80, which answers everything but /health with a 301 to HTTPS -- every
# purge failed and was logged as a warning (#475).
_DEFAULT_URL = os.getenv(
    "GATEWAY_INTERNAL_URL",
    "http://open-security-gateway:8081/internal/gateway/purge-auth-cache",
)


class GatewayRevocationError(RuntimeError):
    """The gateway did not confirm a revocation; it may still accept the jtis."""


# Pauses before the second and third attempt. Three attempts of at most
# `timeout` each bound how long a logout can wait on an unreachable gateway.
_RETRY_DELAYS = (0.1, 0.5)


def _unconfirmed(
    response: httpx.Response, expected: int, scope: Optional[str] = None
) -> Optional[str]:
    """Why ``response`` does not confirm ``expected`` revocations, or None.

    The reason carries the status and the start of the body: the gateway's
    answer once ended in a stray "nil", and a bare "JSONDecodeError" in the
    log did not say so (#571). The body never contains the secret.
    """
    excerpt = response.text[:200]
    if response.status_code != 200:
        return f"HTTP {response.status_code}: {excerpt!r}"
    try:
        body = response.json()
    except ValueError:
        return f"HTTP 200 with a body that is not JSON: {excerpt!r}"
    if not isinstance(body, dict) or body.get("revoked") != expected:
        # An older gateway flushes its cache and answers 200 without
        # counting: it cannot refuse a decision already in flight.
        return f"HTTP 200 without {expected} revoked: {excerpt!r}"
    if scope is not None and body.get("scope") != scope:
        return f"HTTP 200 for scope {body.get('scope')!r}, not {scope!r}: {excerpt!r}"
    return None


async def revoke_jtis_at_gateway(
    jtis: Collection[str],
    ttl_seconds: int,
    timeout: float = 2.0,
) -> None:
    """
    Make the gateway refuse every token carrying one of ``jtis``.

    The gateway records a revocation marker per jti, shared by all of its
    workers and checked on every request -- cached decision or not -- for
    ``ttl_seconds`` (at least its auth-cache TTL). That is what makes the
    revocation hold for a request whose authorization was already in flight
    when the logout ran, which a purge of the cached entry alone did not.

    Returns only once the gateway has answered that it recorded all of them;
    raises GatewayRevocationError otherwise.
    """
    jtis = list(jtis)
    if not jtis:
        return
    await _post_confirmed(
        {"jtis": jtis, "ttl": max(int(ttl_seconds), 1)}, len(jtis), timeout=timeout
    )


async def revoke_user_sessions_at_gateway(
    cutoffs: Mapping[str, float],
    ttl_seconds: int,
    timeout: float = 2.0,
) -> None:
    """
    Make the gateway refuse every session token of these users issued up to
    their cutoff (``{user_id: epoch seconds}``) -- what a password change
    needs (#569).

    The gateway keeps one marker per user for ``ttl_seconds`` (raised to its
    auth-cache TTL) and checks it on every request against the token's iat,
    cached decision or not, so a decision cached before the change, or one in
    flight across it, is not served. Raises GatewayRevocationError unless the
    gateway confirms every user; an older gateway, which does not know this
    body, flushes its cache and answers without the count, and is refused.
    """
    users = [
        {"user_id": str(user_id), "not_before": float(not_before)}
        for user_id, not_before in cutoffs.items()
    ]
    if not users:
        return
    await _post_confirmed(
        {"users": users, "ttl": max(int(ttl_seconds), 1)},
        len(users),
        scope="users",
        timeout=timeout,
    )


#: The most ids the gateway accepts in one body.
_MAX_API_KEYS_PER_CALL = 1000


async def revoke_api_keys_at_gateway(
    api_key_ids: Collection[str],
    ttl_seconds: int,
    timeout: float = 2.0,
) -> None:
    """
    Make the gateway refuse every request made with one of these API keys
    (#593), named by their ids: identity does not keep the raw key, so it
    cannot name the gateway's cache entry for it, and reports the id with
    every authorization it grants for the key instead.

    The gateway keeps a marker per key for ``ttl_seconds`` (raised to its
    auth-cache TTL) and checks it on every request, cached decision or not,
    so a decision cached before the revocation, or one in flight across it,
    is not served. Raises GatewayRevocationError unless the gateway confirms
    every key; an older gateway, which does not know this body, flushes its
    cache and answers without the count, and is refused.
    """
    ids = [str(api_key_id) for api_key_id in api_key_ids]
    for start in range(0, len(ids), _MAX_API_KEYS_PER_CALL):
        chunk = ids[start : start + _MAX_API_KEYS_PER_CALL]
        await _post_confirmed(
            {"api_keys": chunk, "ttl": max(int(ttl_seconds), 1)},
            len(chunk),
            scope="api_keys",
            timeout=timeout,
        )


async def _post_confirmed(
    payload: dict, expected: int, scope: Optional[str] = None, timeout: float = 2.0
) -> None:
    """POST a revocation to the gateway, retried, until it confirms ``expected``."""
    secret = os.getenv("GATEWAY_INTERNAL_SECRET")
    if not secret:
        raise GatewayRevocationError("GATEWAY_INTERNAL_SECRET is not set")

    problem = "no attempt made"
    for attempt, delay in enumerate((0.0, *_RETRY_DELAYS), start=1):
        if delay:
            await asyncio.sleep(delay)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    _DEFAULT_URL, json=payload, headers={"X-Gateway-Secret": secret}
                )
            problem = _unconfirmed(response, expected, scope)
            if problem is None:
                return
        except Exception as exc:  # noqa: BLE001 - retried, then raised
            problem = type(exc).__name__
        logger.warning(
            "Gateway revocation attempt %d/%d not confirmed (%s)",
            attempt,
            len(_RETRY_DELAYS) + 1,
            problem,
        )
    raise GatewayRevocationError(f"gateway did not confirm the revocation ({problem})")
