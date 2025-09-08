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
    app_version: str = "1.0.0"
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    
    # Server configuration
    host: str = Field(default="0.0.0.0", env="HOST")
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
    secret_key: str = Field(default="INSECURE-DEFAULT-SECRET-KEY-CHANGE-THIS", env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # API configuration
    api_v1_prefix: str = "/api/v1"
    cors_origins: List[str] = Field(default=["*"], env="CORS_ORIGINS")
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]
    cors_allow_headers: List[str] = ["*"]
    
    # Scan configuration
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    scan_timeout_seconds: int = Field(default=3600, env="SCAN_TIMEOUT_SECONDS")  # 1 hour
    default_scan_regions: Dict[str, List[str]] = {
        "aws": ["us-east-1", "us-west-2", "eu-west-1"],
        "gcp": ["us-central1", "europe-west1"],
        "azure": ["eastus", "westus2", "westeurope"]
    }
    
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
