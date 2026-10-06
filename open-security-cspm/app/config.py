"""
Configuration management for Open Security CSPM
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import List, Dict

from . import __version__


class Settings(BaseSettings):
    """Application settings with environment variable support.

    Each field is read from the variable of its own name, in any case:
    ``redis_url`` from ``REDIS_URL``. The fields used to say so with
    ``Field(env="REDIS_URL")``, the pydantic v1 form, which v2 ignores: it
    was harmless only while every name matched its field (#665).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # App configuration
    app_name: str = "Open Security CSPM"
    # The package's version (app/__init__.py): it was written here too (#665).
    app_version: str = __version__
    # Empty when ENVIRONMENT is not declared: the API schema and documentation
    # pages are for "development" only, and the default used to be that
    # value, so a service started without the variable published them (#722).
    environment: str = Field(default="")
    debug: bool = Field(default=False)
    
    # Server configuration
    # Binding all interfaces is intended: the service runs in a container and
    # is reached through the container network. Override with HOST if needed.
    host: str = Field(default="0.0.0.0")  # nosec B104
    port: int = Field(default=8019)
    workers: int = Field(default=4)
    
    # Redis configuration
    # The password is part of the URL: there is no REDIS_PASSWORD setting.
    redis_url: str = Field(default="redis://localhost:6379/0")
    
    # Celery configuration
    celery_broker_url: str = Field(default="redis://localhost:6379/0")
    celery_result_backend: str = Field(default="redis://localhost:6379/0")
    celery_task_serializer: str = "json"
    celery_accept_content: List[str] = ["json"]
    celery_result_serializer: str = "json"
    celery_timezone: str = "UTC"
    
    # Logging configuration
    log_level: str = Field(default="INFO")
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Security configuration. Required, at least 32 characters: without it
    # the API and the worker do not start. Nothing reads the field itself;
    # app/credential_crypto.py reads SECRET_KEY from the environment as the
    # key that encrypts cloud credentials when CSPM_CREDENTIAL_KEY is unset.
    # The service issues no token: ACCESS_TOKEN_EXPIRE_MINUTES was declared
    # here and read by nothing (#665).
    secret_key: str = Field(..., min_length=32, description="Secret key (min 32 chars, set via SECRET_KEY env var)")

    # API configuration
    cors_origins: List[str] = Field(default=["http://localhost:3000"])
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]
    cors_allow_headers: List[str] = ["*"]
    
    # Scan configuration
    max_concurrent_scans: int = Field(default=5)
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

    # Not settings any more, because nothing read them (#665):
    # REPORTS_STORAGE_PATH (reports are kept in Redis), PROMETHEUS_ENABLED
    # and PROMETHEUS_PORT (/metrics is always served, on the API's port),
    # WILDBOX_IDENTITY_URL, WILDBOX_API_URL and WILDBOX_GUARDIAN_URL (the
    # service calls none of them), and a second class, CloudProviderSettings,
    # with AWS_ENABLED, GCP_ENABLED, AZURE_ENABLED and a default region and
    # retry count for each: the provider and the regions of a scan come from
    # the request, and only AWS can be scanned.


# Global settings instance
settings = Settings()
