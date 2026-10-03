"""
Authentication utilities for JWT tokens and password hashing.
"""

import uuid
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from jwt.exceptions import InvalidTokenError
from fastapi_users.password import PasswordHelper
from fastapi import HTTPException, Depends, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .config import settings
from .database import get_db
from .models import User, TeamMembership, Team, ApiKey

# Password hashing: the same helper fastapi-users uses for registration, the
# initial admin and PATCH /users/me. It hashes with Argon2id and verifies
# Argon2id and bcrypt. This used to be passlib with bcrypt only, which raises
# UnknownHashError on the Argon2id hashes fastapi-users writes, so the custom
# password-change and self-deletion routes failed for every user (#501).
password_helper = PasswordHelper()

# HTTP Bearer token security
security = HTTPBearer()


def _api_key_hash_secret() -> str:
    """
    The key used to HMAC stored API keys.

    Deliberately NOT the JWT signing key. It used to be, which meant the 90-day
    JWT rotation SECURITY.md recommends silently invalidated every API key in
    the database: every stored digest recomputes differently, lookups stop
    matching, and there is no key_version column or re-hash path to carry them
    across (WILDBO-SEC-01).

    Falls back to the JWT secret when API_KEY_HASH_SECRET is unset, so existing
    deployments keep working; set API_KEY_HASH_SECRET to decouple the two, then
    the JWT key can be rotated without touching API keys.
    """
    return settings.api_key_hash_secret or settings.jwt_secret_key


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using HMAC-SHA256 for secure storage.
    
    Uses HMAC rather than a plain SHA256 digest to provide:
    - Keyed hashing (recovering a key from a database dump also requires the
      secret, which is not in the database)
    - Protection against rainbow table attacks
    
    Args:
        api_key: The API key to hash
        
    Returns:
        Hex-encoded HMAC-SHA256 hash of the API key
    """
    # HMAC-SHA256 is a secure keyed hash function, not weak hashing
    return hmac.new(  # nosec B324
        _api_key_hash_secret().encode(),
        api_key.encode(),
        hashlib.sha256
    ).hexdigest()


def api_key_expired(expires_at: Optional[datetime]) -> bool:
    """Whether an API key's expires_at has passed (#593).

    The column is a timestamptz and is read back timezone-aware; it was
    compared with a naive utcnow(), which raises TypeError. A naive value is
    read as UTC.
    """
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= datetime.now(timezone.utc)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash (Argon2id or legacy bcrypt)."""
    verified, _ = password_helper.verify_and_update(plain_password, hashed_password)
    return verified


def get_password_hash(password: str) -> str:
    """Hash a password (Argon2id).

    It applies no password policy: an account's password is set only through
    UserManager, whose validate_password() does (#583). Nothing in the app
    calls this.
    """
    return password_helper.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with the provided data.
    
    Args:
        data: Dictionary containing token payload data
        expires_delta: Optional expiration time delta
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.jwt_access_token_expire_minutes)

    # Add unique token ID for revocation support
    to_encode.update({"exp": expire, "jti": str(uuid.uuid4())})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def verify_access_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT access token.
    
    Args:
        token: JWT token string
        
    Returns:
        Token payload dictionary
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        # fastapi-users' JWTStrategy issues access tokens with this audience
        # (token_audience=["fastapi-users:auth"]). PyJWT requires the same
        # audience here or it raises InvalidAudienceError — which previously
        # made /internal/authorize reject every gateway-forwarded JWT.
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            audience="fastapi-users:auth",
        )
        return payload
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def token_predates_cutoff(payload: Dict[str, Any], user: Any) -> bool:
    """Whether a session token was issued at or before its user's cutoff (#569).

    A password change sets users.tokens_valid_after, so the account's other
    sessions end with it. A token is refused when its iat is not later than
    the cutoff, or when it carries no iat and so cannot show that it is.

    Granularity: login tokens carry a fractional iat (RevocableJWTStrategy),
    so a token issued in the same second as the change -- the new one handed
    to the session that changed the password -- is still told apart from one
    issued before it. A token with a whole-second iat issued in the second of
    the change is refused, which errs on the side of ending it.
    """
    cutoff = getattr(user, "tokens_valid_after", None)
    if cutoff is None:
        return False
    iat = payload.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)):
        return True
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    return iat <= cutoff.timestamp()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    FastAPI dependency to get the current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Authorization credentials
        db: Database session
        
    Returns:
        User object
        
    Raises:
        HTTPException: If authentication fails
    """
    from .token_blacklist import is_token_blacklisted

    # Verify token
    payload = verify_access_token(credentials.credentials)
    user_id = payload.get("sub")

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    # Check if token has been revoked
    jti = payload.get("jti")
    if jti and await is_token_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get user from database
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    if token_predates_cutoff(payload, user):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    FastAPI dependency to get the current active user.
    
    Args:
        current_user: Current user from get_current_user dependency
        
    Returns:
        Active user object
        
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_user_from_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    FastAPI dependency to get the current user from an API key header.
    
    This provides an alternative authentication method to JWT tokens,
    allowing users to authenticate API requests using API keys.
    
    Args:
        x_api_key: API key from X-API-Key header
        db: Database session
        
    Returns:
        User object associated with the API key
        
    Raises:
        HTTPException: If API key is invalid, expired, or missing
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # Validate API key format
    if not x_api_key.startswith("wsk_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # Hash the provided key
    hashed_key = hash_api_key(x_api_key)
    
    # Look up the API key with related user data
    result = await db.execute(
        select(ApiKey, User)
        .join(User, ApiKey.user_id == User.id)
        .where(ApiKey.hashed_key == hashed_key)
        .where(ApiKey.is_active == True)
        .where(User.is_active == True)
    )
    
    row = result.first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    api_key_obj, user = row
    
    # Check if key is expired
    if api_key_expired(api_key_obj.expires_at):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key expired",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # Update last used timestamp (fire and forget)
    api_key_obj.last_used_at = datetime.utcnow()
    await db.commit()
    
    return user


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key with prefix and hash.
    
    Returns:
        Tuple of (full_key, prefix, hashed_key)
    """
    # Generate random key part (32 bytes = 64 hex chars)
    key_part = secrets.token_hex(32)
    
    # Create prefix (first 4 chars of hash for identification)
    # Using usedforsecurity=False as this is just for prefix generation
    prefix_hash = hashlib.sha256(key_part.encode(), usedforsecurity=False).hexdigest()[:4]
    prefix = f"wsk_{prefix_hash}"
    
    # Full key combines prefix and key part
    full_key = f"{prefix}.{key_part}"
    
    # Hash the full key for storage using HMAC-SHA256 (secure)
    hashed_key = hash_api_key(full_key)
    
    return full_key, prefix, hashed_key


async def verify_api_key(api_key: str, db: AsyncSession) -> Optional[Dict[str, Any]]:
    """
    Verify an API key and return associated user/team information.
    
    Args:
        api_key: API key string
        db: Database session
        
    Returns:
        Dictionary with user/team info if valid, None if invalid
    """
    # Hash the provided key using HMAC-SHA256
    hashed_key = hash_api_key(api_key)
    
    # Look up the key in database
    result = await db.execute(
        select(ApiKey, User, Team, TeamMembership)
        .join(User, ApiKey.user_id == User.id)
        .join(Team, ApiKey.team_id ==  Team.id)
        .join(TeamMembership, (TeamMembership.user_id == User.id) & 
              (TeamMembership.team_id == Team.id))
        .where(ApiKey.hashed_key == hashed_key)
        .where(ApiKey.is_active == True)
        .where(User.is_active == True)
    )
    
    row = result.first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    api_key_obj, user, team, membership = row
    
    # Check if key is expired
    if api_key_expired(api_key_obj.expires_at):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key expired",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # Update last used timestamp
    api_key_obj.last_used_at = datetime.utcnow()
    await db.commit()
    
    return {
        "user_id": str(user.id),
        "team_id": str(team.id),
        "role": membership.role,
        "api_key_id": str(api_key_obj.id)
    }


