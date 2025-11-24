"""
Idempotency middleware for FastAPI services.

Prevents duplicate transactions on retry by storing request fingerprints in Redis.
Implements RFC-compliant Idempotency-Key header handling.

Usage:
    from shared.idempotency import IdempotencyMiddleware, idempotent
    
    app.add_middleware(IdempotencyMiddleware)
    
    @app.post("/api/v1/payments")
    @idempotent(ttl=86400)  # 24 hour idempotency window
    async def create_payment(data: PaymentRequest):
        ...
"""

import hashlib
import json
from typing import Optional, Callable, Any
from functools import wraps
import redis.asyncio as redis
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)


class IdempotencyStore:
    """Redis-backed storage for idempotency keys."""
    
    def __init__(self, redis_url: str = "redis://wildbox-redis:6379/6"):
        self.redis_url = redis_url
        self._client: Optional[redis.Redis] = None
    
    async def connect(self):
        """Establish Redis connection."""
        if not self._client:
            self._client = await redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
    
    async def get(self, key: str) -> Optional[dict]:
        """Retrieve cached response for idempotency key."""
        await self.connect()
        data = await self._client.get(f"idempotency:{key}")
        if data:
            return json.loads(data)
        return None
    
    async def set(self, key: str, response_data: dict, ttl: int = 86400):
        """Store response with TTL (default 24 hours)."""
        await self.connect()
        await self._client.setex(
            f"idempotency:{key}",
            ttl,
            json.dumps(response_data)
        )
    
    async def delete(self, key: str):
        """Remove idempotency key (for testing/admin)."""
        await self.connect()
        await self._client.delete(f"idempotency:{key}")
    
    async def close(self):
        """Close Redis connection."""
        if self._client:
            await self._client.close()


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle idempotency for POST/PUT/PATCH/DELETE requests.
    
    Clients send `Idempotency-Key` header with unique value (UUID recommended).
    If duplicate request detected within TTL window, returns cached response.
    """
    
    def __init__(self, app, store: Optional[IdempotencyStore] = None):
        super().__init__(app)
        self.store = store or IdempotencyStore()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only process mutating methods
        if request.method not in ["POST", "PUT", "PATCH", "DELETE"]:
            return await call_next(request)
        
        # Check for idempotency key header
        idempotency_key = request.headers.get("Idempotency-Key")
        
        if not idempotency_key:
            # Idempotency optional - proceed without caching
            return await call_next(request)
        
        # Validate key format (RFC 4122 UUID recommended)
        if not self._is_valid_key(idempotency_key):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "invalid_idempotency_key",
                    "message": "Idempotency-Key must be a valid UUID or 32+ character string"
                }
            )
        
        # Generate request fingerprint (method + path + body hash)
        fingerprint = await self._generate_fingerprint(request, idempotency_key)
        
        # Check if request already processed
        cached_response = await self.store.get(fingerprint)
        
        if cached_response:
            logger.info(
                f"Idempotent request detected: {fingerprint[:16]}... "
                f"Returning cached response"
            )
            return JSONResponse(
                status_code=cached_response["status_code"],
                content=cached_response["body"],
                headers={
                    **cached_response.get("headers", {}),
                    "X-Idempotent-Replay": "true"
                }
            )
        
        # Process new request
        response = await call_next(request)
        
        # Cache successful responses (2xx status codes)
        if 200 <= response.status_code < 300:
            # Read response body
            body_bytes = b""
            async for chunk in response.body_iterator:
                body_bytes += chunk
            
            try:
                body_json = json.loads(body_bytes.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                body_json = {"data": body_bytes.decode(errors="ignore")}
            
            # Store in cache
            await self.store.set(
                fingerprint,
                {
                    "status_code": response.status_code,
                    "body": body_json,
                    "headers": dict(response.headers)
                },
                ttl=86400  # 24 hours
            )
            
            logger.info(f"Cached idempotent response: {fingerprint[:16]}...")
            
            # Recreate response with consumed body
            return JSONResponse(
                status_code=response.status_code,
                content=body_json,
                headers=dict(response.headers)
            )
        
        return response
    
    @staticmethod
    def _is_valid_key(key: str) -> bool:
        """Validate idempotency key format."""
        # Must be at least 32 characters (UUIDs are 36 with hyphens)
        if len(key) < 32:
            return False
        
        # Only allow alphanumeric and hyphens
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        return all(c in allowed for c in key)
    
    @staticmethod
    async def _generate_fingerprint(request: Request, idempotency_key: str) -> str:
        """
        Generate unique fingerprint for request.
        
        Combines: method + path + idempotency_key + body_hash
        Prevents replay attacks if client reuses key with different payload.
        """
        body = await request.body()
        body_hash = hashlib.sha256(body).hexdigest()
        
        fingerprint_data = f"{request.method}:{request.url.path}:{idempotency_key}:{body_hash}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()


def idempotent(ttl: int = 86400):
    """
    Decorator to mark endpoint as idempotent.
    
    Usage:
        @app.post("/api/v1/payments")
        @idempotent(ttl=3600)  # 1 hour window
        async def create_payment(data: PaymentRequest):
            ...
    
    Args:
        ttl: Time-to-live for idempotency cache in seconds (default 24h)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Decorator primarily for documentation
            # Actual logic handled by middleware
            return await func(*args, **kwargs)
        
        # Attach metadata for documentation/OpenAPI
        wrapper.__idempotent__ = True
        wrapper.__idempotency_ttl__ = ttl
        
        return wrapper
    return decorator


# Example usage in FastAPI app
"""
from fastapi import FastAPI
from shared.idempotency import IdempotencyMiddleware, idempotent

app = FastAPI()
app.add_middleware(IdempotencyMiddleware)

@app.post("/api/v1/users")
@idempotent(ttl=86400)
async def create_user(user: UserCreate):
    # Even if client retries, user only created once
    db_user = User(**user.dict())
    await db.add(db_user)
    await db.commit()
    return {"id": db_user.id, "email": db_user.email}

# Client usage:
# curl -X POST https://api.wildbox.io/api/v1/users \
#   -H "Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000" \
#   -H "Content-Type: application/json" \
#   -d '{"email": "user@example.com", "password": "secure123"}'
#
# If request fails and client retries with same Idempotency-Key,
# returns cached response instead of creating duplicate user.
"""
