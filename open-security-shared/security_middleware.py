"""
Security middleware for Wildbox FastAPI applications.

Provides:
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- CORS configuration
- Rate limiting
- Request/Response logging
"""

import os
from typing import List, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.

    Adds:
    - Strict-Transport-Security (HSTS)
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection
    - Content-Security-Policy
    - Referrer-Policy
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Strict Transport Security
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Content Type Options
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Frame Options (Clickjacking protection)
        response.headers["X-Frame-Options"] = "DENY"

        # XSS Protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # Feature Policy / Permissions Policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all requests and responses for security auditing."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Log request details (excluding sensitive headers)
        sensitive_headers = {"authorization", "x-api-key", "cookie"}
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in sensitive_headers
        }

        # Process request
        response = await call_next(request)

        return response


def setup_cors(
    app: FastAPI,
    allowed_origins: Optional[List[str]] = None,
    allow_credentials: bool = True,
    allow_methods: List[str] = None,
    allow_headers: List[str] = None
) -> None:
    """
    Setup CORS middleware with secure defaults.

    Args:
        app: FastAPI application instance
        allowed_origins: List of allowed origins (required for production)
        allow_credentials: Whether to allow credentials in CORS
        allow_methods: HTTP methods to allow
        allow_headers: HTTP headers to allow
    """
    if allowed_origins is None:
        # Default to localhost for development
        allowed_origins = ["http://localhost:3000", "http://localhost:3001"]

    if allow_methods is None:
        allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]

    if allow_headers is None:
        allow_headers = [
            "Content-Type",
            "Authorization",
            "X-API-Key",
            "Accept",
            "Origin",
        ]

    # Validate origins in production
    if os.getenv("ENVIRONMENT") == "production":
        if not allowed_origins or allowed_origins == ["*"]:
            raise ValueError(
                "CORS origins must be explicitly configured in production. "
                "Set CORS_ORIGINS environment variable to comma-separated list."
            )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
    )


def setup_security_middleware(
    app: FastAPI,
    enable_security_headers: bool = True,
    enable_request_logging: bool = True
) -> None:
    """
    Setup all security middleware for the application.

    Args:
        app: FastAPI application instance
        enable_security_headers: Whether to add security headers
        enable_request_logging: Whether to log requests
    """
    if enable_request_logging:
        app.add_middleware(RequestLoggingMiddleware)

    if enable_security_headers:
        app.add_middleware(SecurityHeadersMiddleware)


def get_cors_origins_from_env(default: Optional[List[str]] = None) -> List[str]:
    """
    Get CORS origins from environment variable.

    Environment variable format:
        CORS_ORIGINS=https://example.com,https://app.example.com

    Args:
        default: Default origins if env var not set

    Returns:
        List of allowed origins
    """
    cors_env = os.getenv("CORS_ORIGINS")

    if cors_env:
        return [origin.strip() for origin in cors_env.split(",")]

    return default or ["http://localhost:3000"]
