"""Enhanced configuration with better validation and security."""

from open_security_shared.environment import is_development, production_checks_apply
from pydantic_settings import BaseSettings
from pydantic import Field, validator, SecretStr
from typing import Optional, List, Union
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Security settings
    api_key: SecretStr = Field(..., min_length=20, description="API key for authentication")
    api_key_name: str = Field(default="X-API-Key", description="Header name for API key")
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
    log_format: str = Field(default="json", description="Log format: json or text")
    
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
    tool_result_ttl: int = Field(default=3600, description="Tool result cache TTL in seconds")
    
    # Cache settings
    redis_url: Optional[str] = Field(default=None, description="Redis URL for caching")
    enable_caching: bool = Field(default=False, description="Enable result caching")
    
    # Database settings (for future use)
    database_url: Optional[str] = Field(default=None, description="Database URL for persistence")
    enable_audit_logging: bool = Field(default=True, description="Enable audit logging")
    
    # Security headers
    enable_security_headers: bool = Field(default=True, description="Enable security headers")
    
    # Tool discovery
    tools_directory: str = Field(default="app/tools", description="Directory containing security tools")
    auto_reload_tools: bool = Field(default=True, description="Auto-reload tools on changes")
    
    # Internal targets the network tools may scan (#614): comma-separated CIDR
    # ranges, IP addresses and host names. Empty by default, so private,
    # loopback, link-local and other internal targets are refused. Parsed
    # here so that a bad entry stops the service and the worker at start-up
    # rather than at the first scan. See app/target_policy.py.
    tools_allowed_internal_targets: str = Field(
        default="",
        description="Internal CIDR ranges and host names the network tools may scan",
    )

    @validator('tools_allowed_internal_targets')
    def validate_tools_allowed_internal_targets(cls, v):
        from app.target_policy import parse_allowlist

        parse_allowlist(v)
        return v or ""

    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'log_level must be one of {valid_levels}')
        return v.upper()
    
    @validator('environment')
    def validate_environment(cls, v):
        if v is None:
            return ""  # not declared: not development, not production
        valid_envs = ['development', 'staging', 'production']
        if v.lower() not in valid_envs:
            raise ValueError(f'environment must be one of {valid_envs}')
        return v.lower()
    
    @validator('api_key')
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
    
    @validator('cors_origins')
    def validate_cors_origins(cls, v):
        if isinstance(v, str):
            # Handle comma-separated string from environment variables
            if ',' in v:
                return [origin.strip() for origin in v.split(',') if origin.strip()]
            return [v] if v else ["*"]
        if isinstance(v, list):
            return v if v else ["*"]
        return ["*"]
    
    @validator('tools_directory')
    def validate_tools_directory(cls, v):
        if not os.path.isabs(v):
            return os.path.join(os.getcwd(), v)
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False
    }

    def get_api_key(self) -> str:
        """Get the API key as a string."""
        return self.api_key.get_secret_value()
    
    def get_secret_key(self) -> str:
        """Get the secret key as a string."""
        return self.secret_key.get_secret_value()
    
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
