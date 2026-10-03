"""
Configuration management for Open Security Responder

Handles environment variables and application settings using Pydantic.
"""

from typing import Optional
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application settings
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # Redis configuration
    redis_url: str = Field(default="redis://localhost:6381/0", env="REDIS_URL")
    redis_key_prefix: str = Field(default="responder:", env="REDIS_KEY_PREFIX")
    
    # Wildbox service URLs. The connectors call the services here directly,
    # on the internal network, as the run's caller (app/caller.py). The
    # defaults are the services' addresses and ports in docker-compose.yml
    # (a network alias or container name, and the port each one listens
    # on), which also sets them explicitly. Guardian's default said 8003;
    # Guardian listens on 8013. Each must be an absolute http(s) URL, or
    # the service does not start.
    wildbox_api_url: str = Field(
        default="http://open-security-tools:8000",
        env="WILDBOX_API_URL",
        description="Tools service URL"
    )
    wildbox_data_url: str = Field(
        default="http://open-security-data:8002",
        env="WILDBOX_DATA_URL",
        description="Data service URL"
    )
    wildbox_guardian_url: str = Field(
        default="http://open-security-guardian:8013",
        env="WILDBOX_GUARDIAN_URL",
        description="Guardian service URL"
    )
    # No connector calls the sensor. Kept so that an env file which sets it
    # still loads: the settings refuse unknown keys from a .env file.
    wildbox_sensor_url: str = Field(
        default="http://open-security-sensor:8004",
        env="WILDBOX_SENSOR_URL",
        description="Sensor service URL (unused)"
    )
    wildbox_agents_url: str = Field(
        default="http://open-security-agents:8006",
        env="WILDBOX_AGENTS_URL",
        description="Agents service URL"
    )

    @field_validator(
        "wildbox_api_url",
        "wildbox_data_url",
        "wildbox_guardian_url",
        "wildbox_sensor_url",
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
        env="GATEWAY_INTERNAL_SECRET",
        description="Shared secret proving a request comes from the gateway",
    )

    # API configuration
    # Binding all interfaces is intended: the service runs in a container and
    # is reached through the container network. Override with API_HOST if needed.
    api_host: str = Field(default="0.0.0.0", env="API_HOST")  # nosec B104
    api_port: int = Field(default=8018, env="API_PORT")
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
