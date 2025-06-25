"""
Authentication utilities for JWT tokens and password hashing.
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .config import settings
from .database import get_db
from .models import User, TeamMembership, Team, ApiKey, Subscription

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token security
security = HTTPBearer()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password for storage."""
    return pwd_context.hash(password)


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
    
    to_encode.update({"exp": expire})
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
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


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
    # Verify token
    payload = verify_access_token(credentials.credentials)
    user_id = payload.get("sub")
    
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
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


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key with prefix and hash.
    
    Returns:
        Tuple of (full_key, prefix, hashed_key)
    """
    # Generate random key part (32 bytes = 64 hex chars)
    key_part = secrets.token_hex(32)
    
    # Create prefix (first 4 chars of hash for identification)
    prefix_hash = hashlib.sha256(key_part.encode()).hexdigest()[:4]
    prefix = f"wsk_{prefix_hash}"
    
    # Full key combines prefix and key part
    full_key = f"{prefix}.{key_part}"
    
    # Hash the full key for storage
    hashed_key = hashlib.sha256(full_key.encode()).hexdigest()
    
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
    # Hash the provided key
    hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
    
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
        return None
    
    api_key_obj, user, team, membership = row
    
    # Check if key is expired
    if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
        return None
    
    # Update last used timestamp
    api_key_obj.last_used_at = datetime.utcnow()
    await db.commit()
    
    return {
        "user_id": str(user.id),
        "team_id": str(team.id),
        "role": membership.role,
        "api_key_id": str(api_key_obj.id)
    }


async def authenticate_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Authenticate using API key and return authorization information.
    
    This is used by the internal authorization endpoint.
    Returns all necessary information for the API Gateway to make decisions.
    """
    try:
        api_key = credentials.credentials
        
        # Validate API key format (should start with wsk_)
        if not api_key.startswith("wsk_"):
            return {"is_authenticated": False}
        
        # Hash the provided key for lookup
        hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Look up the key in database with all related data
        result = await db.execute(
            select(ApiKey, User, Team, TeamMembership, Subscription)
            .join(User, ApiKey.user_id == User.id)
            .join(Team, ApiKey.team_id == Team.id)
            .join(TeamMembership, 
                  (TeamMembership.user_id == User.id) & 
                  (TeamMembership.team_id == Team.id))
            .outerjoin(Subscription, Subscription.team_id == Team.id)
            .where(
                ApiKey.hashed_key == hashed_key,
                ApiKey.is_active == True,
                User.is_active == True
            )
        )
        
        row = result.first()
        if not row:
            return {"is_authenticated": False}
        
        api_key_obj, user, team, membership, subscription = row
        
        # Check if key is expired
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
            return {"is_authenticated": False}
        
        # Update last used timestamp
        api_key_obj.last_used_at = datetime.utcnow()
        await db.commit()
        
        # Get subscription plan
        plan = subscription.plan_id if subscription else "free"
        
        # Determine permissions based on plan and role
        permissions = _get_permissions_for_plan_and_role(plan, membership.role)
        rate_limits = _get_rate_limits_for_plan(plan)
        
        return {
            "is_authenticated": True,
            "user_id": str(user.id),
            "team_id": str(team.id),
            "role": membership.role,
            "plan": plan,
            "permissions": permissions,
            "rate_limits": rate_limits
        }
        
    except Exception as e:
        print(f"Authentication error: {str(e)}")
        return {"is_authenticated": False}


def _get_permissions_for_plan_and_role(plan: str, role: str) -> list[str]:
    """
    Get permissions based on subscription plan and team role.
    
    This is where we define what each plan and role can do.
    """
    base_permissions = ["tool:basic"]
    
    # Plan-based permissions
    if plan == "pro":
        base_permissions.extend([
            "tool:advanced",
            "feed:basic", 
            "cspm:basic"
        ])
    elif plan == "business":
        base_permissions.extend([
            "tool:advanced",
            "tool:premium",
            "feed:premium",
            "cspm:advanced",
            "api:unlimited"
        ])
    
    # Role-based permissions
    if role in ["owner", "admin"]:
        base_permissions.extend([
            "team:manage",
            "billing:manage",
            "keys:manage"
        ])
    
    return list(set(base_permissions))  # Remove duplicates


def _get_rate_limits_for_plan(plan: str) -> Dict[str, str]:
    """Get rate limits based on subscription plan."""
    if plan == "free":
        return {"default": "100/hour", "api": "50/hour"}
    elif plan == "pro":
        return {"default": "1000/hour", "api": "500/hour"}
    elif plan == "business":
        return {"default": "10000/hour", "api": "unlimited"}
    else:
        return {"default": "10/hour", "api": "5/hour"}
