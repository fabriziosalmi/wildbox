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

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, status

from .auth import verify_access_token
from .gateway_cache import purge_gateway_auth_cache
from .token_blacklist import blacklist_token

router = APIRouter()


async def revoke_token(token: str) -> None:
    """Blacklist `token` by its jti and drop the gateway's cached decision.

    Shared by POST /auth/logout and by the JWT strategy's destroy_token(), which
    fastapi-users calls for POST /auth/jwt/logout -- the route the dashboard's
    logout hook uses.
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

    await blacklist_token(jti, expires_at)

    # Drop the gateway's cached decision for this token so the revocation takes
    # effect now rather than after the cache TTL (WILDBO-AUTH-03). Best effort:
    # the blacklist entry above is what makes it correct.
    await purge_gateway_auth_cache(token=token, token_type="bearer")


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
