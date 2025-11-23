"""Custom middleware for the FastAPI application."""

import time
import uuid
from typing import Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.logging_config import get_logger

logger = get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all HTTP requests and responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        
        # Add request ID to request state
        request.state.request_id = request_id
        
        # Log request
        start_time = time.time()
        logger.info(
            "HTTP request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "client_ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get("user-agent", "unknown")
            }
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log response
            logger.info(
                "HTTP request completed",
                extra={
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "duration": f"{duration:.3f}s"
                }
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            duration = time.time() - start_time
            logger.error(
                "HTTP request failed",
                extra={
                    "request_id": request_id,
                    "error": str(e),
                    "duration": f"{duration:.3f}s"
                }
            )
            
            # Return error response
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "request_id": request_id
                }
            )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        
        return response


class CacheControlMiddleware(BaseHTTPMiddleware):
    """Middleware to add appropriate cache control headers."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add cache control headers based on path
        if request.url.path.startswith("/static/"):
            # Cache static files for 1 hour
            response.headers["Cache-Control"] = "public, max-age=3600"
        elif request.url.path.startswith("/api/"):
            # Don't cache API responses
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        else:
            # Cache web pages for 5 minutes
            response.headers["Cache-Control"] = "public, max-age=300"
        
        return response
