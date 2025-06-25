"""
Configuration management for Open Security Agents

Uses Pydantic Settings for environment-based configuration.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    debug: bool = False
    log_level: str = "INFO"
    
    # OpenAI Configuration
    openai_api_key: str
    openai_model: str = "gpt-4o"
    openai_temperature: float = 0.1
    
    # Redis Configuration
    redis_url: str = "redis://localhost:6379/0"
    
    # Celery Configuration
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"
    
    # Wildbox Services
    wildbox_api_url: str = "http://localhost:8000"
    wildbox_data_url: str = "http://localhost:8001"
    wildbox_guardian_url: str = "http://localhost:8002"
    wildbox_responder_url: str = "http://localhost:8003"
    
    # Security
    internal_api_key: str = "wildbox-internal-key-change-in-production"
    
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
