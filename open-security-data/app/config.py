"""
Application Configuration Management

Centralized configuration handling for the security data lake platform.
"""

import os
from typing import List
from dataclasses import dataclass, field

from open_security_shared.environment import production_checks_apply

# Environment detection. Empty when ENVIRONMENT is not declared. Only
# "development" is a development environment (API schema and documentation
# pages, the reloader); every other value, an undeclared one included, is
# held to the checks in AppConfig.__post_init__. The default was
# "development", so a service started without the variable, a bare
# `docker run` for instance, published its route map (#722), and the checks
# were for the exact value "production" only (#736).
ENV = os.getenv("ENVIRONMENT", "")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# What this module reads is what the service uses. It used to parse some
# sixty variables into nine classes, and the service read sixteen of
# them. API_WORKERS, RATE_LIMIT_ENABLED, COLLECTION_INTERVAL,
# DATA_RETENTION_DAYS, BACKUP_ENABLED, JWT_EXPIRATION, ALLOWED_SOURCES,
# LOG_FILE_ENABLED, SENTRY_DSN, METRICS_PORT, PROMETHEUS_ENABLED and the rest
# changed nothing (#665). The service uses no Redis (REDIS_URL was parsed
# too), writes no log file and stores no file: it no longer creates data/
# and logs/ directories when it is imported. A source's own timeout, rate
# limit and interval are columns of the source (app/models.py).

@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str = os.getenv("DATABASE_URL", "")  # REQUIRED: set via DATABASE_URL env var
    pool_size: int = int(os.getenv("DB_POOL_SIZE", "20"))
    max_overflow: int = int(os.getenv("DB_POOL_OVERFLOW", "10"))
    pool_timeout: int = int(os.getenv("DB_POOL_TIMEOUT", "30"))
    echo: bool = os.getenv("DB_ECHO", "false").lower() == "true"

@dataclass
class APIConfig:
    """API server configuration"""
    # Binding all interfaces is intended: the service runs in a container and
    # is reached through the container network. Override with API_HOST if needed.
    host: str = os.getenv("API_HOST", "0.0.0.0")  # nosec B104
    port: int = int(os.getenv("API_PORT", "8002"))

    # CORS
    cors_enabled: bool = os.getenv("CORS_ENABLED", "true").lower() == "true"
    cors_origins: List[str] = field(default_factory=lambda: [
        origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()
    ])

@dataclass
class CollectionConfig:
    """Data collection configuration"""
    # Sources the scheduler collects at the same time.
    max_concurrent: int = int(os.getenv("MAX_CONCURRENT_COLLECTORS", "10"))

@dataclass
class SecurityConfig:
    """Security configuration"""
    secret_key: str = os.getenv("SECRET_KEY", "")  # REQUIRED: set via SECRET_KEY env var

    # API Security
    # NOTE: API_KEY_REQUIRED / API_KEY_HEADER used to be parsed here and were
    # read by nothing in the service (WILDBO-CONF-04). They read as a security
    # toggle -- an operator who set API_KEY_REQUIRED=true would believe they had
    # added a check -- so they have been removed rather than left as a decoy.
    # Authentication for this service is the gateway proof-of-origin dependency
    # in app/auth.py.

    # Indicators or telemetry events accepted in one request.
    max_batch_size: int = int(os.getenv("MAX_BATCH_SIZE", "1000"))

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = os.getenv("LOG_LEVEL", "INFO")
    format: str = os.getenv("LOG_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

@dataclass
class AppConfig:
    """Main application configuration"""
    # Core configs
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    collection: CollectionConfig = field(default_factory=CollectionConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # Environment
    environment: str = ENV
    debug: bool = DEBUG
    
    def __post_init__(self):
        """Post-initialization validation"""
        # Validate critical settings everywhere but in development. The test
        # was for the exact value "production": "staging", "Production" or
        # no ENVIRONMENT at all started without them (#736).
        if production_checks_apply(self.environment):
            if not self.security.secret_key:
                raise ValueError("SECRET_KEY must be set unless ENVIRONMENT=development")
            if not self.database.url:
                raise ValueError("DATABASE_URL must be set unless ENVIRONMENT=development")

            if self.debug:
                raise ValueError("DEBUG must be False unless ENVIRONMENT=development")

# Global configuration instance
config = AppConfig()

def get_config() -> AppConfig:
    """Get the global configuration instance"""
    return config

def reload_config() -> AppConfig:
    """Reload configuration from environment variables"""
    global config
    config = AppConfig()
    return config
