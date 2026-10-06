"""
Configuration management for Open Security Responder

Handles environment variables and application settings using Pydantic.
"""

from typing import Optional
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

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

    # Application settings
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    
    # Redis configuration
    redis_url: str = Field(default="redis://localhost:6381/0")
    redis_key_prefix: str = Field(default="responder:")
    
    # Wildbox service URLs. The connectors call the services here directly,
    # on the internal network, as the run's caller (app/caller.py). The
    # defaults are the services' addresses and ports in docker-compose.yml
    # (a network alias or container name, and the port each one listens
    # on), which also sets them explicitly. Guardian's default said 8003;
    # Guardian listens on 8013. Each must be an absolute http(s) URL, or
    # the service does not start.
    wildbox_api_url: str = Field(
        default="http://open-security-tools:8000",
        description="Tools service URL"
    )
    wildbox_data_url: str = Field(
        default="http://open-security-data:8002",
        description="Data service URL"
    )
    wildbox_guardian_url: str = Field(
        default="http://open-security-guardian:8013",
        description="Guardian service URL"
    )
    # No WILDBOX_SENSOR_URL: no connector calls the sensor, and the setting
    # was kept only so that a .env naming it still loaded (#665).
    wildbox_agents_url: str = Field(
        default="http://open-security-agents:8006",
        description="Agents service URL"
    )

    @field_validator(
        "wildbox_api_url",
        "wildbox_data_url",
        "wildbox_guardian_url",
        "wildbox_agents_url",
    )
    @classmethod
    def _service_url(cls, value: str, info) -> str:
        """An absolute http(s) URL with a host, without a trailing slash."""
        parts = urlsplit(value.strip())
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(
                f"{info.field_name.upper()} must be an absolute http(s) URL "
                f"with a host, such as http://open-security-tools:8000; got {value!r}"
            )
        if parts.query or parts.fragment:
            raise ValueError(
                f"{info.field_name.upper()} must not carry a query or a fragment"
            )
        return value.strip().rstrip("/")

    # The proof of origin the services require with the gateway identity
    # headers. The responder checks it on the requests it receives (through
    # open_security_shared.gateway_auth) and sends it, with the run's caller,
    # on the requests its connectors make (app/caller.py, #616).
    gateway_internal_secret: Optional[str] = Field(
        default=None,
        description="Shared secret proving a request comes from the gateway",
    )

    # API configuration
    # Binding all interfaces is intended: the service runs in a container and
    # is reached through the container network. Override with API_HOST if needed.
    api_host: str = Field(default="0.0.0.0")  # nosec B104
    api_port: int = Field(default=8018)
    
    # Playbook configuration
    playbooks_directory: str = Field(
        default="./playbooks",
        description="Directory containing playbook YAML files"
    )
    
    # Execution settings. DEFAULT_STEP_TIMEOUT, MAX_CONCURRENT_EXECUTIONS,
    # DRAMATIQ_PROCESSES, DRAMATIQ_THREADS and API_KEY were declared here and
    # read by nothing (#665): the engine applies no step timeout and no
    # limit on concurrent runs, and the worker starts with Dramatiq's
    # defaults (scripts/entrypoint.sh).
    execution_retention_days: int = Field(
        default=30,
        description="Number of days to retain execution results"
    )


# Global settings instance
settings = Settings()
