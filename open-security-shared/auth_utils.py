"""
Shared authentication utilities for Wildbox services.

This module provides reusable authentication functions and dependencies
for all FastAPI services in the Wildbox platform.
"""

from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from functools import lru_cache

from fastapi import HTTPException, status, Header
from jose import JWTError, jwt
from passlib.context import CryptContext


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against its bcrypt hash.

    Args:
        plain_password: The plain text password to verify
        hashed_password: The bcrypt hashed password to compare against

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: The plain text password to hash

    Returns:
        The bcrypt hashed password
    """
    return pwd_context.hash(password)


class AuthConfig:
    """Configuration for JWT and API authentication."""

    def __init__(
        self,
        jwt_secret_key: str,
        jwt_algorithm: str = "HS256",
        jwt_expiration_minutes: int = 60,
        api_key_enabled: bool = True
    ):
        """
        Initialize authentication configuration.

        Args:
            jwt_secret_key: Secret key for JWT signing (min 32 chars)
            jwt_algorithm: JWT algorithm (default: HS256)
            jwt_expiration_minutes: Token expiration time in minutes
            api_key_enabled: Whether to support API key authentication
        """
        if len(jwt_secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")

        self.jwt_secret_key = jwt_secret_key
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiration_minutes = jwt_expiration_minutes
        self.api_key_enabled = api_key_enabled


def create_access_token(
    data: Dict[str, Any],
    secret_key: str,
    algorithm: str = "HS256",
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Payload data to encode in token
        secret_key: Secret key for signing
        algorithm: JWT algorithm to use
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=1)

    to_encode.update({"exp": expire, "iat": datetime.utcnow()})

    try:
        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
        return encoded_jwt
    except Exception as e:
        raise ValueError(f"Failed to create token: {str(e)}")


def verify_access_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256"
) -> Dict[str, Any]:
    """
    Verify and decode a JWT access token.

    Args:
        token: JWT token to verify
        secret_key: Secret key for validation
        algorithm: JWT algorithm used

    Returns:
        Token payload dictionary

    Raises:
        HTTPException: If token is invalid, expired, or malformed
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def verify_api_key(
    api_key: str,
    valid_keys: list = None
) -> bool:
    """
    Verify an API key against a list of valid keys.

    Args:
        api_key: The API key to verify
        valid_keys: List of valid API keys

    Returns:
        True if API key is valid

    Raises:
        HTTPException: If API key is invalid
    """
    if not valid_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key validation not configured"
        )

    if api_key not in valid_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )

    return True


async def get_api_key_from_header(
    x_api_key: Optional[str] = Header(None)
) -> str:
    """
    Extract API key from X-API-Key header.

    Args:
        x_api_key: API key from header

    Returns:
        API key if provided

    Raises:
        HTTPException: If API key is missing
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="X-API-Key header required"
        )
    return x_api_key


async def get_bearer_token_from_header(
    authorization: Optional[str] = Header(None)
) -> str:
    """
    Extract bearer token from Authorization header.

    Args:
        authorization: Authorization header value

    Returns:
        Bearer token without "Bearer " prefix

    Raises:
        HTTPException: If header is missing or malformed
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Use: Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return parts[1]
