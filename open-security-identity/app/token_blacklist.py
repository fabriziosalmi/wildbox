"""
Token blacklist using Redis for JWT revocation.

Provides the ability to revoke tokens on logout or password change.
Revoked tokens are stored in Redis with automatic TTL expiration
matching the token's remaining lifetime.
"""

import hashlib
import hmac
import logging
from datetime import datetime, timedelta
from typing import Optional

import redis.asyncio as aioredis

from .config import settings

logger = logging.getLogger(__name__)

# Lazy-initialized Redis connection
_redis: Optional[aioredis.Redis] = None

TOKEN_BLACKLIST_PREFIX = "token:blacklist:"
LOGIN_ATTEMPTS_PREFIX = "login:attempts:"
LOGIN_LOCKOUT_PREFIX = "login:lockout:"


async def get_redis() -> aioredis.Redis:
    """Get or create async Redis connection."""
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
    return _redis


async def blacklist_token(token_jti: str, expires_at: datetime) -> None:
    """
    Add a token to the blacklist.

    Args:
        token_jti: The JWT 'jti' (unique token ID) or the token hash.
        expires_at: When the token naturally expires (used to set TTL).

    Raises whatever the Redis client raised. This used to log and return, so a
    logout during a Redis outage answered 200 with nothing revoked (#571); the
    caller must know the revocation did not happen.
    """
    try:
        r = await get_redis()
        ttl = max(int((expires_at - datetime.utcnow()).total_seconds()), 1)
        await r.setex(f"{TOKEN_BLACKLIST_PREFIX}{token_jti}", ttl, "revoked")
        logger.info(f"Token blacklisted (TTL={ttl}s)")
    except Exception as e:
        logger.error(f"Failed to blacklist token: {e}")
        raise


async def is_token_blacklisted(token_jti: str) -> bool:
    """Check if a token has been revoked."""
    try:
        r = await get_redis()
        return await r.exists(f"{TOKEN_BLACKLIST_PREFIX}{token_jti}") > 0
    except Exception as e:
        logger.error(f"Failed to check token blacklist: {e}")
        # Fail open: if Redis is down, don't block authenticated users.
        # In high-security environments, change to fail closed (return True).
        return False


def account_digest(email: str) -> str:
    """The first 12 hex digits of the SHA-256 of an address, for a log line.

    ``printf %s user@example.com | shasum -a 256`` gives the same digits, so
    a line about a lockout can be matched to an address one already knows
    without the log holding addresses.
    """
    return hashlib.sha256(str(email).strip().lower().encode("utf-8")).hexdigest()[:12]


def account_key(email: str) -> str:
    """What stands for an address in a Redis key: its keyed digest (#778).

    The lockout counters were kept under the address itself,
    ``login:attempts:<address>``, and the address is whatever was typed in
    the login form: a password pasted into the wrong field was written to
    Redis as a key name, and from there to its append-only file and to
    every backup of it, for anyone who can list keys to read.

    An HMAC, not the plain digest the log line uses (account_digest): that
    one is meant to be recomputed by an operator who knows the address, and
    so can be by anyone who guesses it, or the password. This one is keyed
    by the secret that keys the API-key digests, which is not in Redis. The
    label keeps the two uses of that secret apart.

    Case and surrounding space do not count, as at login. A change of the
    secret gives every address a new key: the counters in progress are left
    behind and expire on their own, within the lockout period.
    """
    from .auth import _api_key_hash_secret

    address = str(email).strip().lower().encode("utf-8")
    return hmac.new(
        _api_key_hash_secret().encode("utf-8"),
        b"login-lockout:" + address,
        hashlib.sha256,
    ).hexdigest()


async def record_failed_login(email: str) -> int:
    """
    Record a failed login attempt. Returns the current count.
    """
    try:
        r = await get_redis()
        key = f"{LOGIN_ATTEMPTS_PREFIX}{account_key(email)}"
        count = await r.incr(key)
        # Set expiry on first attempt
        if count == 1:
            await r.expire(key, settings.account_lockout_minutes * 60)
        return count
    except Exception as e:
        logger.error(f"Failed to record login attempt: {e}")
        return 0


async def clear_failed_logins(email: str) -> None:
    """Clear failed login counter on successful login."""
    try:
        r = await get_redis()
        await r.delete(f"{LOGIN_ATTEMPTS_PREFIX}{account_key(email)}")
    except Exception as e:
        logger.error(f"Failed to clear login attempts: {e}")


async def is_account_locked(email: str) -> bool:
    """Check if account is temporarily locked due to too many failed attempts."""
    try:
        r = await get_redis()
        account = account_key(email)
        lockout_key = f"{LOGIN_LOCKOUT_PREFIX}{account}"
        if await r.exists(lockout_key):
            return True
        # Check if attempts exceeded threshold
        attempts_key = f"{LOGIN_ATTEMPTS_PREFIX}{account}"
        count = await r.get(attempts_key)
        if count and int(count) >= settings.max_failed_login_attempts:
            # Lock the account
            await r.setex(lockout_key, settings.account_lockout_minutes * 60, "locked")
            # Not the address: it is whatever was typed in the login form,
            # a password pasted into the wrong field included (#755). The
            # digest lets an operator check a known address against the line.
            logger.warning(
                f"Account locked after {count} failed attempts "
                f"(account {account_digest(email)})"
            )
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to check account lockout: {e}")
        return False
