"""Enhanced configuration with better validation and security."""

from open_security_shared.environment import is_development, production_checks_apply
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, SecretStr
from typing import Optional, List, Union


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Every field here is read by the service. Nine that were not are gone
    (#665): ``api_key_name``, ``log_format``, ``tool_result_ttl``,
    ``enable_caching``, ``database_url``, ``enable_audit_logging``,
    ``enable_security_headers``, ``tools_directory`` and
    ``auto_reload_tools``, with ``get_secret_key()``, which read a field
    that no longer existed. A variable of one of those names in the
    environment is ignored; in a ``.env`` file in the service's directory it
    stops the service at start, as every key the settings do not know does.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Security settings. Required at start-up, and checked there. It is not
    # a request credential: the service accepts only requests forwarded by
    # the gateway (#565).
    api_key: SecretStr = Field(..., min_length=20, description="API key for authentication")
    # NOTE: there is deliberately no `secret_key` setting. One used to exist,
    # described as "Secret key for sessions" and defaulting to a fresh
    # secrets.token_urlsafe(32) per process -- so it differed between the API and
    # the worker and changed on every restart, and no code ever read it. It
    # implied session signing that does not exist (WILDBO-CONF-05). If sessions
    # are added, declare it required (Field(..., min_length=32)) as identity and
    # CSPM do, so a missing value fails at startup instead of being invented.
    
    # Server settings
    host: str = Field(default="127.0.0.1", description="Host to bind the server")
    port: int = Field(default=8000, ge=1, le=65535, description="Port to bind the server")
    debug: bool = Field(default=False, description="Debug mode")
    # None when ENVIRONMENT is not declared; validate_environment turns that
    # into "", which is neither "development" (the API schema is served) nor
    # "production" (the start-up checks in app/main.py are fatal). The
    # default was "development", so a service started without the variable
    # published its schema (#722). A value that is set must still be one of
    # the three names: an empty or misspelt ENVIRONMENT refuses to start.
    environment: Optional[str] = Field(default=None, description="Environment name")
    
    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level")
    
    # CORS settings
    cors_origins: Union[List[str], str] = Field(default=["http://localhost:3000"], description="Allowed CORS origins")
    cors_allow_credentials: bool = Field(default=True, description="Allow CORS credentials")
    
    # Execution history
    execution_history_limit: int = Field(
        default=1000,
        ge=1,
        description="Executions retained in the in-process history ring buffer",
    )
    # NOTE: there is deliberately no rate-limit setting. RATE_LIMIT_REQUESTS,
    # RATE_LIMIT_WINDOW and ENABLE_RATE_LIMITING used to be declared here, and
    # docker-compose.yml set the first two, but no code ever enforced them:
    # operators tuned values that changed nothing (#646). They are removed,
    # not enforced, because the limit they describe (requests per caller per
    # window) is the gateway's: every request reaches this service through
    # it, already counted against the caller's team (RATE_LIMIT_PER_HOUR,
    # auth_handler.lua). At the defaults the gateway stops a team at 166
    # requests a minute, long before the 500 these settings named, so a
    # second counter here would have refused nothing.
    #
    # What the gateway cannot limit is the cost of a single call, and that
    # is limited here by other means: MAX_CONCURRENT_TOOLS and TOOL_TIMEOUT
    # below, and the per-caller hourly limits of the tools that act for a
    # caller (app/security/authorization.py).

    # Tool execution settings
    tool_timeout: int = Field(default=300, ge=1, le=3600, description="Default tool execution timeout in seconds")
    max_concurrent_tools: int = Field(default=10, ge=1, le=100, description="Maximum concurrent tool executions")

    # Redis: the Celery broker and result backend, the ownership and the
    # outcomes of asynchronous runs, and each caller's hourly operation
    # count. Nothing is cached in it.
    redis_url: Optional[str] = Field(default=None, description="Redis URL")

    # Internal targets the network tools may scan (#614): comma-separated CIDR
    # ranges, IP addresses and host names. Empty by default, so private,
    # loopback, link-local and other internal targets are refused. Parsed
    # here so that a bad entry stops the service and the worker at start-up
    # rather than at the first scan. See app/target_policy.py.
    tools_allowed_internal_targets: str = Field(
        default="",
        description="Internal CIDR ranges and host names the network tools may scan",
    )

    @field_validator('tools_allowed_internal_targets')
    @classmethod
    def validate_tools_allowed_internal_targets(cls, v):
        from app.target_policy import parse_allowlist

        parse_allowlist(v)
        return v or ""

    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'log_level must be one of {valid_levels}')
        return v.upper()
    
    @field_validator('environment')
    @classmethod
    def validate_environment(cls, v):
        if v is None:
            return ""  # not declared: not development, not production
        valid_envs = ['development', 'staging', 'production']
        if v.lower() not in valid_envs:
            raise ValueError(f'environment must be one of {valid_envs}')
        return v.lower()
    
    @field_validator('api_key')
    @classmethod
    def validate_api_key(cls, v):
        if isinstance(v, SecretStr):
            key_value = v.get_secret_value()
        else:
            key_value = str(v)
        
        if len(key_value) < 32:
            raise ValueError('API key must be at least 32 characters long for security')
        
        # Check for common weak patterns
        weak_patterns = [
            'password', 'secret', 'key', 'admin', 'test', 'demo', 
            '123', 'abc', 'default', 'wildbox', 'api-key'
        ]
        key_lower = key_value.lower()
        for pattern in weak_patterns:
            if pattern in key_lower:
                raise ValueError(f'API key contains weak pattern "{pattern}". Use a randomly generated key.')
        
        # Check for sufficient entropy (basic check)
        unique_chars = len(set(key_value))
        if unique_chars < 16:
            raise ValueError('API key has insufficient entropy. Use a randomly generated key.')
        
        return v
    
    @field_validator('cors_origins')
    @classmethod
    def validate_cors_origins(cls, v):
        if isinstance(v, str):
            # Handle comma-separated string from environment variables
            if ',' in v:
                return [origin.strip() for origin in v.split(',') if origin.strip()]
            return [v] if v else ["*"]
        if isinstance(v, list):
            return v if v else ["*"]
        return ["*"]
    
    def get_api_key(self) -> str:
        """Get the API key as a string."""
        return self.api_key.get_secret_value()
    
    def production_checks_apply(self) -> bool:
        """Whether the start-up checks of app/main.py are fatal.

        True for every environment that is not explicitly development, by
        the rule every service shares. There was an is_production() here,
        true for the exact value "production" only, so "staging" started
        with a weak API key, and so did an undeclared environment (#736).
        """
        return production_checks_apply(self.environment)

    def is_development(self) -> bool:
        """Check if running in development environment."""
        return is_development(self.environment)


# Global settings instance
settings = Settings()
