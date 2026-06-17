"""
Configuration management for Open Security Identity service.
"""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


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
    cors_origins: list[str] = ["http://localhost:3000", "https://wildbox.local", "https://dashboard.wildbox.local"]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    cors_allow_headers: list[str] = ["Content-Type", "Authorization", "X-API-Key", "X-Requested-With"]
    
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
