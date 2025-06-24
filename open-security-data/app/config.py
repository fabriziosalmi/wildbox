"""
Application Configuration Management

Centralized configuration handling for the security data lake platform.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path

# Environment detection
ENV = os.getenv("ENVIRONMENT", "development")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# Base directories
BASE_DIR = Path(__file__).parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str = os.getenv("DATABASE_URL", "postgresql://secdata:secdata@localhost:5432/securitydata")
    pool_size: int = int(os.getenv("DB_POOL_SIZE", "20"))
    max_overflow: int = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    pool_timeout: int = int(os.getenv("DB_POOL_TIMEOUT", "30"))
    echo: bool = os.getenv("DB_ECHO", "false").lower() == "true"

@dataclass
class RedisConfig:
    """Redis configuration"""
    url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    max_connections: int = int(os.getenv("REDIS_MAX_CONNECTIONS", "100"))
    socket_timeout: int = int(os.getenv("REDIS_SOCKET_TIMEOUT", "5"))
    socket_connect_timeout: int = int(os.getenv("REDIS_CONNECT_TIMEOUT", "5"))

@dataclass
class APIConfig:
    """API server configuration"""
    host: str = os.getenv("API_HOST", "0.0.0.0")
    port: int = int(os.getenv("API_PORT", "8000"))
    workers: int = int(os.getenv("API_WORKERS", "4"))
    max_requests: int = int(os.getenv("API_MAX_REQUESTS", "1000"))
    max_requests_jitter: int = int(os.getenv("API_MAX_REQUESTS_JITTER", "100"))
    timeout: int = int(os.getenv("API_TIMEOUT", "30"))
    keep_alive: int = int(os.getenv("API_KEEP_ALIVE", "2"))
    
    # Rate limiting
    rate_limit_enabled: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    rate_limit_window: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
    
    # CORS
    cors_enabled: bool = os.getenv("CORS_ENABLED", "true").lower() == "true"
    cors_origins: List[str] = field(default_factory=lambda: os.getenv("CORS_ORIGINS", "*").split(","))

@dataclass
class CollectionConfig:
    """Data collection configuration"""
    enabled: bool = os.getenv("COLLECTION_ENABLED", "true").lower() == "true"
    interval: int = int(os.getenv("COLLECTION_INTERVAL", "3600"))  # 1 hour
    max_concurrent: int = int(os.getenv("MAX_CONCURRENT_COLLECTORS", "10"))
    timeout: int = int(os.getenv("COLLECTION_TIMEOUT", "300"))  # 5 minutes
    retry_attempts: int = int(os.getenv("COLLECTION_RETRY_ATTEMPTS", "3"))
    retry_delay: int = int(os.getenv("COLLECTION_RETRY_DELAY", "60"))
    
    # Rate limiting for external APIs
    rate_limit_requests: int = int(os.getenv("EXTERNAL_RATE_LIMIT_REQUESTS", "100"))
    rate_limit_window: int = int(os.getenv("EXTERNAL_RATE_LIMIT_WINDOW", "60"))
    
    # Data validation
    validate_data: bool = os.getenv("VALIDATE_COLLECTION_DATA", "true").lower() == "true"
    skip_duplicates: bool = os.getenv("SKIP_DUPLICATES", "true").lower() == "true"

@dataclass
class StorageConfig:
    """Data storage configuration"""
    data_retention_days: int = int(os.getenv("DATA_RETENTION_DAYS", "365"))
    archive_after_days: int = int(os.getenv("ARCHIVE_AFTER_DAYS", "90"))
    cleanup_interval: int = int(os.getenv("CLEANUP_INTERVAL", "86400"))  # 24 hours
    
    # File storage
    file_storage_path: Path = Path(os.getenv("FILE_STORAGE_PATH", str(DATA_DIR / "files")))
    max_file_size: int = int(os.getenv("MAX_FILE_SIZE", "104857600"))  # 100MB
    
    # Backup
    backup_enabled: bool = os.getenv("BACKUP_ENABLED", "false").lower() == "true"
    backup_interval: int = int(os.getenv("BACKUP_INTERVAL", "86400"))  # 24 hours
    backup_retention: int = int(os.getenv("BACKUP_RETENTION", "30"))  # 30 days

@dataclass
class SecurityConfig:
    """Security configuration"""
    secret_key: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    jwt_expiration: int = int(os.getenv("JWT_EXPIRATION", "3600"))  # 1 hour
    
    # API Security
    api_key_required: bool = os.getenv("API_KEY_REQUIRED", "false").lower() == "true"
    api_key_header: str = os.getenv("API_KEY_HEADER", "X-API-Key")
    
    # Input validation
    max_query_size: int = int(os.getenv("MAX_QUERY_SIZE", "10000"))
    max_batch_size: int = int(os.getenv("MAX_BATCH_SIZE", "1000"))
    
    # Source validation
    allowed_sources: List[str] = field(default_factory=lambda: 
        os.getenv("ALLOWED_SOURCES", "").split(",") if os.getenv("ALLOWED_SOURCES") else [])
    blocked_sources: List[str] = field(default_factory=lambda: 
        os.getenv("BLOCKED_SOURCES", "").split(",") if os.getenv("BLOCKED_SOURCES") else [])

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = os.getenv("LOG_LEVEL", "INFO")
    format: str = os.getenv("LOG_FORMAT", 
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_enabled: bool = os.getenv("LOG_FILE_ENABLED", "true").lower() == "true"
    file_path: Path = Path(os.getenv("LOG_FILE_PATH", str(LOGS_DIR / "app.log")))
    max_bytes: int = int(os.getenv("LOG_MAX_BYTES", "10485760"))  # 10MB
    backup_count: int = int(os.getenv("LOG_BACKUP_COUNT", "5"))
    
    # Structured logging
    json_format: bool = os.getenv("LOG_JSON_FORMAT", "false").lower() == "true"
    
    # External logging
    sentry_enabled: bool = os.getenv("SENTRY_ENABLED", "false").lower() == "true"
    sentry_dsn: Optional[str] = os.getenv("SENTRY_DSN")

@dataclass
class MonitoringConfig:
    """Monitoring and metrics configuration"""
    enabled: bool = os.getenv("MONITORING_ENABLED", "true").lower() == "true"
    metrics_port: int = int(os.getenv("METRICS_PORT", "9090"))
    health_check_enabled: bool = os.getenv("HEALTH_CHECK_ENABLED", "true").lower() == "true"
    health_check_port: int = int(os.getenv("HEALTH_CHECK_PORT", "8080"))
    
    # Prometheus
    prometheus_enabled: bool = os.getenv("PROMETHEUS_ENABLED", "false").lower() == "true"
    prometheus_port: int = int(os.getenv("PROMETHEUS_PORT", "8000"))

@dataclass
class AppConfig:
    """Main application configuration"""
    # Core configs
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    api: APIConfig = field(default_factory=APIConfig)
    collection: CollectionConfig = field(default_factory=CollectionConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    
    # Environment
    environment: str = ENV
    debug: bool = DEBUG
    
    def __post_init__(self):
        """Post-initialization validation"""
        # Ensure storage directories exist
        self.storage.file_storage_path.mkdir(parents=True, exist_ok=True)
        self.logging.file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Validate critical settings in production
        if self.environment == "production":
            if self.security.secret_key == "dev-secret-key-change-in-production":
                raise ValueError("SECRET_KEY must be changed in production")
            
            if self.debug:
                raise ValueError("DEBUG must be False in production")

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
