"""
Configuration management for Open Security Agents

Uses Pydantic Settings for environment-based configuration.
"""

import os
from typing import Optional
from limits import parse_many
from pydantic import Field, ValidationInfo, field_validator
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
    # No longer read (#567): the client sent it as X-API-Key when it had no
    # caller identity, and the tools service stopped accepting that in #566.
    # Kept only so that a .env file which still sets INTERNAL_API_KEY loads.
    internal_api_key: str = Field(default="", env="INTERNAL_API_KEY")
    # REQUIRED. Proof-of-origin secret sent with the caller's gateway identity
    # (X-Wildbox-* headers) on every internal call (#175); without it internal
    # tool calls fail.
    gateway_internal_secret: str = Field(default="", env="GATEWAY_INTERNAL_SECRET")
    
    # Analysis Settings
    max_analysis_time_minutes: int = 10
    max_concurrent_tasks: int = 5
    
    # Task Settings
    task_result_expires: int = 3600  # 1 hour
    task_timeout: int = 600  # 10 minutes

    # Rate limits on POST /v1/analyze (#651), in the `limits` notation
    # ("5/minute", "5/minute;50/day"). ANALYZE_RATE_LIMIT applies to each
    # authenticated user. ANALYZE_TEAM_RATE_LIMIT, when set, is a ceiling
    # for all the users of one team together; empty means no ceiling.
    analyze_rate_limit: str = "5/minute"
    analyze_team_rate_limit: str = ""

    @field_validator("analyze_rate_limit", "analyze_team_rate_limit")
    @classmethod
    def _valid_rate_limit(cls, value: str, info: ValidationInfo) -> str:
        # slowapi logs a limit it cannot parse and then does not apply it,
        # so a typo would silently remove the limit. Refuse to start instead.
        value = (value or "").strip()
        if not value:
            if info.field_name == "analyze_rate_limit":
                raise ValueError("ANALYZE_RATE_LIMIT must not be empty")
            return value
        try:
            items = parse_many(value)
        except ValueError as e:
            raise ValueError(f"invalid rate limit {value!r}: {e}") from e
        if not items or any(item.amount < 1 for item in items):
            raise ValueError(f"invalid rate limit {value!r}: amounts must be 1 or more")
        return value

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
