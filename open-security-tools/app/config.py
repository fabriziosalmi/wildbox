"""Enhanced configuration with better validation and security."""

from pydantic_settings import BaseSettings
from pydantic import Field, validator, SecretStr
from typing import Optional, List, Union
import secrets
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Security settings
    api_key: SecretStr = Field(..., min_length=20, description="API key for authentication")
    api_key_name: str = Field(default="X-API-Key", description="Header name for API key")
    secret_key: SecretStr = Field(default_factory=lambda: secrets.token_urlsafe(32), description="Secret key for sessions")
    
    # Server settings
    host: str = Field(default="127.0.0.1", description="Host to bind the server")
    port: int = Field(default=8000, ge=1, le=65535, description="Port to bind the server")
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field(default="development", description="Environment name")
    
    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(default="json", description="Log format: json or text")
    
    # CORS settings
    cors_origins: Union[List[str], str] = Field(default=["*"], description="Allowed CORS origins")
    cors_allow_credentials: bool = Field(default=True, description="Allow CORS credentials")
    
    # Rate limiting
    rate_limit_requests: int = Field(default=100, description="Requests per minute per IP")
    rate_limit_window: int = Field(default=60, description="Rate limit window in seconds")
    enable_rate_limiting: bool = Field(default=True, description="Enable rate limiting")
    
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
    
    # Service URLs for health aggregation
    identity_service_url: Optional[str] = Field(default=None, description="Identity service URL")
    data_service_url: Optional[str] = Field(default=None, description="Data service URL") 
    guardian_service_url: Optional[str] = Field(default=None, description="Guardian service URL")
    sensor_service_url: Optional[str] = Field(default=None, description="Sensor service URL")
    responder_service_url: Optional[str] = Field(default=None, description="Responder service URL")
    agents_service_url: Optional[str] = Field(default=None, description="Agents service URL")
    cspm_service_url: Optional[str] = Field(default=None, description="CSPM service URL")

    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'log_level must be one of {valid_levels}')
        return v.upper()
    
    @validator('environment')
    def validate_environment(cls, v):
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
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"
    
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"


# Global settings instance
settings = Settings()
