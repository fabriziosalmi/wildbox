"""
Configuration management for Open Security Agents

Uses Pydantic Settings for environment-based configuration.
"""

import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    debug: bool = False
    log_level: str = "INFO"
    
    # Anthropic / Claude Configuration (optional — the worker imports without it;
    # analysis tasks fail gracefully when it's missing instead of crash-looping)
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-opus-4-8"
    anthropic_temperature: float = 0.1
    anthropic_max_tokens: int = 4096
    
    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    
    # Celery Configuration
    celery_broker_url: str = Field(default="redis://localhost:6379/0", env="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/0", env="CELERY_RESULT_BACKEND")
    
    # Wildbox Services
    wildbox_api_url: str = "http://localhost:8000"
    wildbox_data_url: str = "http://localhost:8001"
    wildbox_guardian_url: str = "http://localhost:8013"
    wildbox_responder_url: str = "http://localhost:8018"
    
    # Security
    internal_api_key: str = Field(default="", env="INTERNAL_API_KEY")  # REQUIRED: set via env var
    # Proof-of-origin secret used to forward the caller's gateway identity to
    # downstream services (#175). When set, internal tool calls carry the user's
    # X-Wildbox-* headers + this secret instead of the static service key.
    gateway_internal_secret: str = Field(default="", env="GATEWAY_INTERNAL_SECRET")
    
    # Analysis Settings
    max_analysis_time_minutes: int = 10
    max_concurrent_tasks: int = 5
    
    # Task Settings
    task_result_expires: int = 3600  # 1 hour
    task_timeout: int = 600  # 10 minutes
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
