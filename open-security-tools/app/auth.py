"""Security implementation for API key authentication."""

from fastapi import HTTPException, Depends, status, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Union
import time
import hashlib
from collections import defaultdict, deque
from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)
security = HTTPBearer(auto_error=False)

# Simple in-memory rate limiting (in production, use Redis)
rate_limit_storage = defaultdict(lambda: deque())


class RateLimiter:
    """Simple rate limiter for API requests."""
    
    @staticmethod
    def is_allowed(identifier: str, limit: int = None, window: int = None) -> bool:
        """
        Check if request is allowed based on rate limiting.
        
        Args:
            identifier: Unique identifier (IP address, API key, etc.)
            limit: Request limit per window
            window: Time window in seconds
            
        Returns:
            True if request is allowed, False otherwise
        """
        limit = limit or settings.rate_limit_requests
        window = window or settings.rate_limit_window
        
        now = time.time()
        requests = rate_limit_storage[identifier]
        
        # Remove old requests outside the window
        while requests and requests[0] <= now - window:
            requests.popleft()
        
        # Check if limit is exceeded
        if len(requests) >= limit:
            return False
        
        # Add current request
        requests.append(now)
        return True


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host if request.client else "unknown"


def verify_api_key(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    api_key: Optional[str] = Header(None, alias="API-Key"),
    x_wildbox_user_id: Optional[str] = Header(None, alias="X-Wildbox-User-ID"),
    x_wildbox_team_id: Optional[str] = Header(None, alias="X-Wildbox-Team-ID")
) -> str:
    """
    Verify API key from multiple sources with rate limiting.
    
    Also accepts requests from the gateway with X-Wildbox-* headers injected by the gateway
    after user authentication. This allows logged-in users to access the API without needing
    a separate API key.
    
    Args:
        request: FastAPI request object
        credentials: HTTP authorization credentials
        x_api_key: API key from X-API-Key header
        api_key: API key from API-Key header
        x_wildbox_user_id: User ID injected by gateway (if authenticated via gateway)
        x_wildbox_team_id: Team ID injected by gateway (if authenticated via gateway)
        
    Returns:
        The verified API key or "gateway_authenticated" for gateway-authenticated requests
        
    Raises:
        HTTPException: If API key is invalid, missing, or rate limited
    """
    
    client_ip = get_client_ip(request)
    
    # Check if request is authenticated via gateway (has Wildbox headers from gateway)
    if x_wildbox_user_id and x_wildbox_team_id:
        logger.info(f"Gateway-authenticated request from user_id: {x_wildbox_user_id}, team_id: {x_wildbox_team_id}, IP: {client_ip}")
        return "gateway_authenticated"
    
    # Rate limiting check
    if not RateLimiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later.",
            headers={"Retry-After": str(settings.rate_limit_window)}
        )
    
    # Extract API key from various sources
    provided_key = None
    auth_method = None
    
    if credentials and credentials.credentials:
        provided_key = credentials.credentials
        auth_method = "Bearer token"
    elif x_api_key:
        provided_key = x_api_key
        auth_method = "X-API-Key header"
    elif api_key:
        provided_key = api_key
        auth_method = "API-Key header"
    
    if not provided_key:
        logger.warning(f"API request without credentials from IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide via Authorization header (Bearer token) or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify API key
    if provided_key != settings.get_api_key():
        # Hash the key for logging (security)
        key_hash = hashlib.sha256(provided_key.encode()).hexdigest()[:10]
        logger.warning(f"Invalid API key attempt from IP: {client_ip}, key hash: {key_hash}, method: {auth_method}")
        
        # Additional rate limiting for invalid keys
        if not RateLimiter.is_allowed(f"invalid_{client_ip}", limit=5, window=300):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many invalid authentication attempts. Please try again later.",
                headers={"Retry-After": "300"}
            )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    logger.info(f"API key verified successfully from IP: {client_ip}, method: {auth_method}")
    return provided_key


def verify_api_key_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    api_key: Optional[str] = Header(None, alias="API-Key")
) -> Optional[str]:
    """
    Optional API key verification for public endpoints.
    
    Returns:
        The verified API key if provided and valid, None otherwise
    """
    try:
        return verify_api_key(request, credentials, x_api_key, api_key)
    except HTTPException:
        return None


# Legacy function for backward compatibility
def verify_api_key_header(api_key: Optional[str] = None) -> str:
    """
    Legacy API key verification from X-API-Key header.
    
    Args:
        api_key: API key from X-API-Key header
        
    Returns:
        The verified API key
        
    Raises:
        HTTPException: If API key is invalid or missing
    """
    
    if not api_key:
        logger.warning("API request without X-API-Key header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header"
        )
    
    if api_key != settings.get_api_key():
        logger.warning(f"Invalid API key in header: {api_key[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    logger.info("API key verified successfully from header")
    return api_key
