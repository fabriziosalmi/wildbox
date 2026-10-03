"""
Configuration management for Open Security CSPM
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Optional, Dict, Any
import os


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # App configuration
    app_name: str = "Open Security CSPM"
    app_version: str = "0.1.6"
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    
    # Server configuration
    # Binding all interfaces is intended: the service runs in a container and
    # is reached through the container network. Override with HOST if needed.
    host: str = Field(default="0.0.0.0", env="HOST")  # nosec B104
    port: int = Field(default=8019, env="PORT")
    workers: int = Field(default=4, env="WORKERS")
    
    # Redis configuration
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    
    # Celery configuration
    celery_broker_url: str = Field(default="redis://localhost:6379/0", env="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/0", env="CELERY_RESULT_BACKEND")
    celery_task_serializer: str = "json"
    celery_accept_content: List[str] = ["json"]
    celery_result_serializer: str = "json"
    celery_timezone: str = "UTC"
    
    # Logging configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Security configuration
    secret_key: str = Field(..., env="SECRET_KEY", min_length=32, description="Secret key (min 32 chars, set via SECRET_KEY env var)")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # API configuration
    api_v1_prefix: str = "/api/v1"
    cors_origins: List[str] = Field(default=["http://localhost:3000"], env="CORS_ORIGINS")
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]
    cors_allow_headers: List[str] = ["*"]
    
    # Scan configuration
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    # The time limit of one scan; the soft limit is a minute shorter, so the
    # lower bound keeps it positive. docker-compose.yml passes
    # CSPM_SCAN_TIMEOUT_SECONDS as SCAN_TIMEOUT_SECONDS to cspm and
    # cspm-worker, and gives the worker as long to stop (#601).
    scan_timeout_seconds: int = Field(default=3600, ge=120, le=86400)
    default_scan_regions: Dict[str, List[str]] = {
        "aws": ["us-east-1", "us-west-2", "eu-west-1"],
        "gcp": ["us-central1", "europe-west1"],
        "azure": ["eastus", "westus2", "westeurope"]
    }
    
    # How many days a scan is kept in Redis: its metadata, its entry in the
    # team's scan index and, once it completes, its report (#591). The
    # compliance pages and the cloud security overview are built from these
    # reports. They used to be read from the Celery result backend, which
    # drops results after a day. Validated here, so the API and the worker
    # refuse to start with a value that is not a whole number of days
    # between 1 and 3650. The field name is the variable name:
    # CSPM_REPORT_RETENTION_DAYS.
    cspm_report_retention_days: int = Field(default=90, ge=1, le=3650)

    # Storage configuration
    reports_storage_path: str = Field(default="./reports", env="REPORTS_STORAGE_PATH")
    
    # Monitoring configuration
    prometheus_enabled: bool = Field(default=True, env="PROMETHEUS_ENABLED")
    prometheus_port: int = Field(default=9090, env="PROMETHEUS_PORT")
    
    # Integration URLs
    wildbox_identity_url: str = Field(default="http://localhost:8001", env="WILDBOX_IDENTITY_URL")
    wildbox_api_url: str = Field(default="http://localhost:8000", env="WILDBOX_API_URL")
    wildbox_guardian_url: str = Field(default="http://localhost:8002", env="WILDBOX_GUARDIAN_URL")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


class CloudProviderSettings(BaseSettings):
    """Cloud provider specific settings."""
    
    # AWS Configuration
    aws_enabled: bool = Field(default=True, env="AWS_ENABLED")
    aws_default_region: str = Field(default="us-east-1", env="AWS_DEFAULT_REGION")
    aws_max_retries: int = Field(default=3, env="AWS_MAX_RETRIES")
    
    # GCP Configuration
    gcp_enabled: bool = Field(default=True, env="GCP_ENABLED")
    gcp_default_region: str = Field(default="us-central1", env="GCP_DEFAULT_REGION")
    gcp_max_retries: int = Field(default=3, env="GCP_MAX_RETRIES")
    
    # Azure Configuration
    azure_enabled: bool = Field(default=True, env="AZURE_ENABLED")
    azure_default_region: str = Field(default="eastus", env="AZURE_DEFAULT_REGION")
    azure_max_retries: int = Field(default=3, env="AZURE_MAX_RETRIES")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instances
settings = Settings()
cloud_settings = CloudProviderSettings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings


def get_cloud_settings() -> CloudProviderSettings:
    """Get cloud provider settings."""
    return cloud_settings
