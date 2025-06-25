"""
Configuration management for Open Security Identity service.
"""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Application
    app_name: str = "Open Security Identity"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # Database
    database_url: str = Field(..., description="Database connection URL")
    
    # JWT Authentication
    jwt_secret_key: str = Field(..., description="JWT secret key for token signing")
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    
    # Stripe Configuration
    stripe_secret_key: str = Field(..., description="Stripe secret key")
    stripe_publishable_key: str = Field(..., description="Stripe publishable key")
    stripe_webhook_secret: str = Field(..., description="Stripe webhook secret")
    
    # API Configuration
    api_v1_prefix: str = "/api/v1"
    internal_api_prefix: str = "/internal"
    
    # CORS
    cors_origins: list[str] = ["*"]
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = ["*"]
    cors_allow_headers: list[str] = ["*"]
    
    # Frontend URLs (for Stripe redirects)
    frontend_url: str = "http://localhost:3000"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
