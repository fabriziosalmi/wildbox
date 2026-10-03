"""
Token revocation.

Logout used to be a client-side cookie deletion and nothing else: the gateway
routes /auth/logout to the dashboard SPA, identity exposed no logout endpoint,
and nothing in the repository ever called blacklist_token -- so the blacklist was
permanently empty and is_token_blacklisted always returned False. A token
captured before logout stayed valid for the remainder of its 30-minute lifetime,
and an operator who discovered a compromised session had no lever short of
rotating JWT_SECRET_KEY and invalidating every session at once (WILDBO-AUTH-01).

This module supplies the missing write side. The read side that matters is in
internal.py: /internal/authorize now consults the blacklist, so revocation
applies to gateway-mediated traffic rather than only to identity's own routes.
"""

import logging
from datetime import datetime, timezone
from typing import Mapping, Optional

from fastapi import APIRouter, Header, HTTPException, status

from .auth import verify_access_token
from .config import settings
from .gateway_cache import (
    GatewayRevocationError,
    revoke_jtis_at_gateway,
    revoke_user_sessions_at_gateway,
)
from .token_blacklist import blacklist_token

logger = logging.getLogger(__name__)

router = APIRouter()


class RevocationError(RuntimeError):
    """A revocation could not be made effective everywhere; see revoke_jtis."""


async def revoke_jtis(sessions: Mapping[str, datetime]) -> None:
    """Revoke sessions by jti, everywhere, or raise RevocationError.

    ``sessions`` maps each jti to its token's expiry (naive UTC). Each jti is
    blacklisted in Redis until then -- what identity's own routes and
    /internal/authorize consult -- and the gateway is told to refuse it on
    every worker, cached decision or not. Both steps must succeed: when this
    returns, no request carrying one of these tokens is let through, and that
    holds for a request whose authorization was already in flight (#571).

    Nothing here needs the raw tokens, so it also serves revocations of
    sessions other than the caller's, such as the other sessions of a user
    whose password changed.

    The gateway goes first. Its marker is what refuses a request already in
    flight, and if it cannot be confirmed nothing has been written yet, so the
    session is still whole and the caller can retry -- the other order would
    blacklist the token first, and a retried POST /auth/jwt/logout would then
    be refused as unauthenticated before it could reach the gateway again.
    Both steps are idempotent.
    """
    if not sessions:
        return
    # Long enough to cover the longest-lived of these tokens: past its expiry
    # the token is refused anyway.
    now = datetime.utcnow()
    ttl = max(
        int((expires_at - now).total_seconds()) for expires_at in sessions.values()
    )
    try:
        await revoke_jtis_at_gateway(list(sessions), ttl_seconds=ttl)
    except GatewayRevocationError as exc:
        raise RevocationError(str(exc)) from exc

    try:
        for jti, expires_at in sessions.items():
            await blacklist_token(jti, expires_at)
    except Exception as exc:
        raise RevocationError("the blacklist could not be written") from exc


async def revoke_sessions_issued_before(user_id, not_before: datetime) -> None:
    """End, at the gateway, the user's sessions issued up to ``not_before`` (#569).

    The other half of a password change: the caller stores the same instant in
    users.tokens_valid_after, which identity's own routes and
    /internal/authorize check, and must do so only after this returns. The
    gateway goes first for the reason revoke_jtis() gives: once it confirms,
    no request carrying one of those tokens is let through, not even one whose
    authorization was in flight, and if it does not, nothing has changed yet
    and the caller can retry. Raises RevocationError.

    The marker lasts as long as a token issued just before the change could
    (the access-token lifetime); after that the database cutoff alone holds,
    since no such token is still unexpired.
    """
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    try:
        await revoke_user_sessions_at_gateway(
            {str(user_id): not_before.timestamp()},
            ttl_seconds=settings.jwt_access_token_expire_minutes * 60,
        )
    except GatewayRevocationError as exc:
        raise RevocationError(str(exc)) from exc


async def revoke_token(token: str) -> None:
    """Revoke `token` everywhere, or fail with 503 (see revoke_jtis).

    Shared by POST /auth/logout and by the JWT strategy's destroy_token(), which
    fastapi-users calls for POST /auth/jwt/logout -- the route the dashboard's
    logout hook uses.

    Fails closed. The revocation used to be followed by a best-effort purge of
    the gateway's cache, whose failure was a log line: logout answered 200
    while the gateway could go on serving the token until its cache TTL ran
    out. Logout is idempotent, so a client told 503 can simply repeat it.
    """
    payload = verify_access_token(token)

    jti = payload.get("jti")
    if not jti:
        # Only tokens issued before RevocableJWTStrategy existed lack one.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token carries no jti and cannot be revoked individually",
        )

    exp = payload.get("exp")
    expires_at = (
        datetime.fromtimestamp(exp, tz=timezone.utc).replace(tzinfo=None)
        if exp
        else datetime.utcnow()
    )

    try:
        await revoke_jtis({jti: expires_at})
    except RevocationError as exc:
        logger.error("Logout could not revoke the session: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The session could not be revoked; retry the logout",
        ) from exc


@router.post("/logout", status_code=status.HTTP_200_OK, tags=["authentication"])
async def logout(authorization: Optional[str] = Header(None)):
    """
    Revoke the presented access token.

    The token's `jti` is added to the blacklist with a TTL matching the token's
    own expiry, so the entry costs nothing beyond the token's natural lifetime.

    Returns 200 whether or not the token was already revoked: logout is
    idempotent, and telling a caller that a token was *not* previously revoked
    leaks nothing useful.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    await revoke_token(token)
    return {"detail": "Token revoked"}
