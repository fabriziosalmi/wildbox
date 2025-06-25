"""
Configuration management for Open Security Responder

Handles environment variables and application settings using Pydantic.
"""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application settings
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # Redis configuration
    redis_url: str = Field(default="redis://localhost:6381/0", env="REDIS_URL")
    redis_key_prefix: str = Field(default="responder:", env="REDIS_KEY_PREFIX")
    
    # Wildbox service URLs
    wildbox_api_url: str = Field(
        default="http://localhost:8000",
        env="WILDBOX_API_URL",
        description="Open Security API service URL"
    )
    wildbox_data_url: str = Field(
        default="http://localhost:8002",
        env="WILDBOX_DATA_URL",
        description="Open Security Data service URL"
    )
    wildbox_guardian_url: str = Field(
        default="http://localhost:8003",
        env="WILDBOX_GUARDIAN_URL",
        description="Open Security Guardian service URL"
    )
    wildbox_sensor_url: str = Field(
        default="http://localhost:8004",
        env="WILDBOX_SENSOR_URL",
        description="Open Security Sensor service URL"
    )
    
    # API configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8005, env="API_PORT")
    api_key: Optional[str] = Field(default=None, env="API_KEY")
    
    # Playbook configuration
    playbooks_directory: str = Field(
        default="./playbooks",
        env="PLAYBOOKS_DIRECTORY",
        description="Directory containing playbook YAML files"
    )
    
    # Execution settings
    default_step_timeout: int = Field(
        default=300,
        env="DEFAULT_STEP_TIMEOUT",
        description="Default timeout for step execution in seconds"
    )
    max_concurrent_executions: int = Field(
        default=10,
        env="MAX_CONCURRENT_EXECUTIONS",
        description="Maximum number of concurrent playbook executions"
    )
    execution_retention_days: int = Field(
        default=30,
        env="EXECUTION_RETENTION_DAYS",
        description="Number of days to retain execution results"
    )
    
    # Dramatiq configuration
    dramatiq_processes: int = Field(default=4, env="DRAMATIQ_PROCESSES")
    dramatiq_threads: int = Field(default=4, env="DRAMATIQ_THREADS")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()
