"""
Configuration management for Open Security Identity service.
"""

import json
from typing import Annotated, Any, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
        # Application settings
    app_name: str = "Wildbox Identity Service"
    app_version: str = "0.1.6"
    debug: bool = False
    port: int = 8001
    
    # Database
    database_url: str = Field(..., description="Database connection URL")
    
    # JWT Authentication
    jwt_secret_key: str = Field(..., description="JWT secret key for token signing", min_length=32)

    # Keys the HMAC used to store API-key digests. Kept separate from the JWT
    # signing key so that rotating one does not invalidate the other
    # (WILDBO-SEC-01). When unset, hash_api_key() falls back to jwt_secret_key
    # so existing deployments are unaffected until they set this and re-issue.
    api_key_hash_secret: Optional[str] = Field(
        default=None,
        min_length=32,
        description="Secret keying the HMAC for stored API keys (defaults to JWT key)",
    )
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # Redis (for token blacklist and rate limiting)
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")

    # Account lockout
    max_failed_login_attempts: int = 5
    account_lockout_minutes: int = 15
    
    
    # API Configuration
    api_v1_prefix: str = "/api/v1"
    internal_api_prefix: str = "/internal"

    # Gateway secret for service-to-service authentication
    gateway_internal_secret: Optional[str] = Field(None, description="Shared secret for gateway-to-identity communication")
    
    # CORS - SECURITY: Restrict origins in production
    #
    # NoDecode: pydantic-settings would otherwise read a list[str] from the
    # environment as JSON only, and CORS_ORIGINS is comma-separated in .env
    # and for every other service. identity exited at import on that value
    # and crash-looped (#531). _parse_cors_origins accepts both forms.
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000", "https://wildbox.local", "https://dashboard.wildbox.local"]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    cors_allow_headers: list[str] = ["Content-Type", "Authorization", "X-API-Key", "X-Requested-With"]
    
    
    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors_origins(cls, value: Any) -> Any:
        """Accept a JSON list or a comma-separated string of origins.

        '["https://a.example", "https://b.example"]' and
        'https://a.example, https://b.example' give the same list. An empty
        value gives an empty list, which allows no cross-origin requests: the
        dashboard reaches identity through the gateway on its own origin.
        """
        if not isinstance(value, str):
            return value
        text = value.strip()
        if text.startswith("["):
            # Invalid JSON raises ValueError, which pydantic reports as a
            # validation error naming the field.
            return json.loads(text)
        return [origin.strip() for origin in text.split(",") if origin.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
