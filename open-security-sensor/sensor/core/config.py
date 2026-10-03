"""
Configuration management for the Security Sensor
"""

import os
import yaml
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Where a batch goes, relative to the gateway (#628). The sensor never talks
# to the data service directly: the data service accepts only requests the
# gateway has authenticated, so the sensor authenticates at the gateway with
# an identity API key, and the gateway forwards the batch with the key's team.
INGEST_PATH = "/api/v1/data/ingest"

# Values that mean "no key yet". The shipped configuration carried the first
# one, which nothing could ever have accepted.
_UNSET_API_KEYS = {"", "CONFIGURE_VIA_ENV", "your-api-key-here"}


@dataclass
class DataLakeConfig:
    """Data lake connection configuration.

    ``endpoint`` is the gateway: ``https://<gateway>`` or the full
    ``https://<gateway>/api/v1/data/ingest``. ``api_key`` is an identity
    personal API key (``wsk_...``), sent as X-API-Key; scope it to
    ``data:ingest``. ``ca_bundle`` is a PEM file of certificates to trust for
    the gateway, for a gateway whose certificate no public CA signed (the
    development stack's self-signed one).
    """
    endpoint: str
    api_key: str
    tls_verify: bool = True
    ca_bundle: Optional[str] = None
    sensor_id: Optional[str] = None
    batch_size: int = 100
    flush_interval: int = 30
    timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 5

    @property
    def forwarding_enabled(self) -> bool:
        """Is there a key to forward with?

        A deployment starts before anyone can have created the key (identity
        issues it, and identity is part of the same stack), so a missing key
        disables forwarding instead of stopping the sensor. Everything else
        about the destination is validated at start-up.
        """
        return (self.api_key or "").strip() not in _UNSET_API_KEYS

    @property
    def ingest_url(self) -> str:
        """The URL batches are posted to, derived from ``endpoint``."""
        endpoint = (self.endpoint or "").strip().rstrip("/")
        if urlparse(endpoint).path.endswith(INGEST_PATH):
            return endpoint
        return endpoint + INGEST_PATH

    def validate(self) -> List[str]:
        """Errors in the destination, the credential and the TLS trust."""
        errors = []
        endpoint = (self.endpoint or "").strip()
        if not endpoint:
            errors.append(
                "data_lake.endpoint is required: the gateway URL, "
                "https://<gateway> (SENSOR_DATA_LAKE_ENDPOINT)"
            )
        else:
            parsed = urlparse(endpoint)
            path = parsed.path.rstrip("/")
            if parsed.scheme != "https" or not parsed.hostname:
                errors.append(
                    f"data_lake.endpoint must be the gateway's https:// URL, "
                    f"got {endpoint!r}: the gateway serves the API over HTTPS "
                    f"only"
                )
            elif path and not path.endswith(INGEST_PATH):
                errors.append(
                    f"data_lake.endpoint must be https://<gateway> or "
                    f"https://<gateway>{INGEST_PATH}, got path {path!r}. The "
                    f"sensor no longer posts to the data service's "
                    f"/api/v1/ingest directly; see UPGRADING.md"
                )
            if parsed.query or parsed.fragment or parsed.username:
                errors.append(
                    "data_lake.endpoint must not carry a query, a fragment or "
                    "credentials"
                )

        key = (self.api_key or "").strip()
        if self.forwarding_enabled:
            if not key.startswith("wsk_"):
                errors.append(
                    "data_lake.api_key is not an identity API key (those "
                    "begin with wsk_). Create one for the sensor's team "
                    "member, with the data:ingest scope"
                )
            elif any(c.isspace() for c in key):
                errors.append("data_lake.api_key must not contain whitespace")

        if self.ca_bundle:
            if not self.tls_verify:
                errors.append(
                    "data_lake.ca_bundle is set but data_lake.tls_verify is "
                    "false, so the bundle would be ignored: remove one of them"
                )
            elif not os.path.isfile(self.ca_bundle):
                errors.append(
                    f"data_lake.ca_bundle {self.ca_bundle!r} does not exist or "
                    f"is not a file"
                )
            elif not os.access(self.ca_bundle, os.R_OK):
                errors.append(
                    f"data_lake.ca_bundle {self.ca_bundle!r} is not readable"
                )

        for name in ("batch_size", "flush_interval", "timeout", "retry_attempts"):
            if getattr(self, name) < 1:
                errors.append(f"data_lake.{name} must be at least 1")
        if self.retry_delay < 0:
            errors.append("data_lake.retry_delay must not be negative")
        return errors

@dataclass
class CollectionConfig:
    """Telemetry collection configuration"""
    process_events: bool = True
    network_connections: bool = True
    file_monitoring: bool = True
    user_events: bool = True
    system_inventory: bool = True
    log_forwarding: bool = False

@dataclass
class FIMConfig:
    """File Integrity Monitoring configuration"""
    enabled: bool = True
    paths: List[str] = field(default_factory=lambda: [
        "/etc", "/bin", "/usr/bin", "/opt"
    ])
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "*.tmp", "*.log", "*.cache", "*.pid"
    ])
    recursive: bool = True
    max_depth: int = 10

@dataclass
class PerformanceConfig:
    """Performance tuning configuration"""
    query_interval: int = 10
    max_memory_mb: int = 128
    max_cpu_percent: int = 5
    max_queue_size: int = 1000
    worker_threads: int = 4

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file: Optional[str] = None
    max_size: int = 10485760  # 10MB
    backup_count: int = 5
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

@dataclass
class NetworkConfig:
    """Network configuration"""
    bind_address: str = "127.0.0.1"
    bind_port: int = 8004
    enable_api: bool = True
    api_key: Optional[str] = None

@dataclass
class SensorConfig:
    """Main sensor configuration"""
    data_lake: DataLakeConfig
    collection: CollectionConfig = field(default_factory=CollectionConfig)
    fim: FIMConfig = field(default_factory=FIMConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Validate data lake configuration
        errors.extend(self.data_lake.validate())

        # Validate performance limits
        if self.performance.max_memory_mb < 32:
            errors.append("performance.max_memory_mb must be at least 32MB")
        
        if self.performance.max_cpu_percent < 1 or self.performance.max_cpu_percent > 100:
            errors.append("performance.max_cpu_percent must be between 1 and 100")
        
        # Validate FIM paths
        if self.fim.enabled and not self.fim.paths:
            errors.append("fim.paths cannot be empty when FIM is enabled")
        
        return errors

def get_default_config_paths() -> List[Path]:
    """Get list of default configuration file paths to check"""
    paths = []
    
    # Current directory
    paths.append(Path("config.yaml"))
    paths.append(Path("sensor-config.yaml"))
    
    # Platform-specific paths
    if os.name == 'nt':  # Windows
        paths.extend([
            Path(os.environ.get('PROGRAMFILES', 'C:\\Program Files')) / 'SecuritySensor' / 'config.yaml',
            Path(os.environ.get('APPDATA', '')) / 'SecuritySensor' / 'config.yaml'
        ])
    else:  # Unix-like
        paths.extend([
            Path('/etc/security-sensor/config.yaml'),
            Path('/usr/local/etc/security-sensor/config.yaml'),
            Path.home() / '.config' / 'security-sensor' / 'config.yaml'
        ])
    
    return [p for p in paths if p.exists()]

def load_config(config_path: Optional[str] = None) -> SensorConfig:
    """Load configuration from file"""
    
    if config_path:
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
    else:
        # Find default config file
        default_paths = get_default_config_paths()
        if not default_paths:
            raise FileNotFoundError("No configuration file found in default locations")
        config_file = default_paths[0]
        logger.info(f"Using configuration file: {config_file}")
    
    try:
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in configuration file: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to read configuration file: {e}")
    
    # Apply environment variable overrides
    config_data = _apply_env_overrides(config_data)
    
    # Build configuration objects
    try:
        config = _build_config_from_dict(config_data)
    except Exception as e:
        raise ValueError(f"Invalid configuration: {e}")
    
    # Validate configuration
    errors = config.validate()
    if errors:
        raise ValueError(f"Configuration validation errors: {'; '.join(errors)}")
    
    return config

def _apply_env_overrides(config_data: Dict[str, Any]) -> Dict[str, Any]:
    """Apply environment variable overrides to configuration"""
    
    # Map of environment variables to config paths
    env_mappings = {
        'SENSOR_DATA_LAKE_ENDPOINT': ['data_lake', 'endpoint'],
        'SENSOR_DATA_LAKE_API_KEY': ['data_lake', 'api_key'],
        'SENSOR_DATA_LAKE_TLS_VERIFY': ['data_lake', 'tls_verify'],
        'SENSOR_DATA_LAKE_CA_BUNDLE': ['data_lake', 'ca_bundle'],
        'SENSOR_DATA_LAKE_SENSOR_ID': ['data_lake', 'sensor_id'],
        'SENSOR_LOGGING_LEVEL': ['logging', 'level'],
        'SENSOR_LOGGING_FILE': ['logging', 'file'],
        'SENSOR_PERFORMANCE_MAX_MEMORY': ['performance', 'max_memory_mb'],
        'SENSOR_PERFORMANCE_MAX_CPU': ['performance', 'max_cpu_percent'],
        # The local API's own key. Without it _require_auth fails closed and
        # every route but /health answers 503 "API authentication is not
        # configured on this sensor" -- which is what the shipped
        # config.yaml.example (api_key: null) produced, so the sensor's entire
        # local API was inert in the default deployment with no environment
        # variable able to switch it on.
        'SENSOR_API_KEY': ['network', 'api_key'],
    }
    
    for env_var, config_path in env_mappings.items():
        env_value = os.environ.get(env_var)
        if env_value is not None:
            # Navigate to the config section
            current = config_data
            for key in config_path[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            # Convert value to appropriate type
            final_key = config_path[-1]
            if final_key in ['tls_verify'] and env_value.lower() in ['true', '1', 'yes']:
                current[final_key] = True
            elif final_key in ['tls_verify'] and env_value.lower() in ['false', '0', 'no']:
                current[final_key] = False
            elif final_key in ['max_memory_mb', 'max_cpu_percent']:
                try:
                    current[final_key] = int(env_value)
                except ValueError:
                    logger.warning(f"Invalid integer value for {env_var}: {env_value}")
            else:
                current[final_key] = env_value
    
    return config_data

def _build_config_from_dict(config_data: Dict[str, Any]) -> SensorConfig:
    """Build SensorConfig from dictionary"""
    
    # Data lake configuration (required)
    data_lake_data = config_data.get('data_lake', {})
    data_lake = DataLakeConfig(
        endpoint=data_lake_data.get('endpoint') or '',
        api_key=data_lake_data.get('api_key') or '',
        tls_verify=data_lake_data.get('tls_verify', True),
        # An empty value (an unset compose variable) means "not set".
        ca_bundle=data_lake_data.get('ca_bundle') or None,
        sensor_id=data_lake_data.get('sensor_id') or None,
        batch_size=data_lake_data.get('batch_size', 100),
        flush_interval=data_lake_data.get('flush_interval', 30),
        timeout=data_lake_data.get('timeout', 30),
        retry_attempts=data_lake_data.get('retry_attempts', 3),
        retry_delay=data_lake_data.get('retry_delay', 5)
    )
    
    # Collection configuration
    collection_data = config_data.get('collection', {})
    collection = CollectionConfig(
        process_events=collection_data.get('process_events', True),
        network_connections=collection_data.get('network_connections', True),
        file_monitoring=collection_data.get('file_monitoring', True),
        user_events=collection_data.get('user_events', True),
        system_inventory=collection_data.get('system_inventory', True),
        log_forwarding=collection_data.get('log_forwarding', False)
    )
    
    # FIM configuration
    fim_data = config_data.get('fim', {})
    fim = FIMConfig(
        enabled=fim_data.get('enabled', True),
        paths=fim_data.get('paths', ["/etc", "/bin", "/usr/bin", "/opt"]),
        exclude_patterns=fim_data.get('exclude_patterns', ["*.tmp", "*.log", "*.cache", "*.pid"]),
        recursive=fim_data.get('recursive', True),
        max_depth=fim_data.get('max_depth', 10)
    )
    
    # Performance configuration
    perf_data = config_data.get('performance', {})
    performance = PerformanceConfig(
        query_interval=perf_data.get('query_interval', 10),
        max_memory_mb=perf_data.get('max_memory_mb', 128),
        max_cpu_percent=perf_data.get('max_cpu_percent', 5),
        max_queue_size=perf_data.get('max_queue_size', 1000),
        worker_threads=perf_data.get('worker_threads', 4)
    )
    
    # Logging configuration
    log_data = config_data.get('logging', {})
    logging_config = LoggingConfig(
        level=log_data.get('level', 'INFO'),
        file=log_data.get('file'),
        max_size=log_data.get('max_size', 10485760),
        backup_count=log_data.get('backup_count', 5),
        format=log_data.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    
    # Network configuration
    net_data = config_data.get('network', {})
    network = NetworkConfig(
        bind_address=net_data.get('bind_address', '127.0.0.1'),
        bind_port=net_data.get('bind_port', 8004),
        enable_api=net_data.get('enable_api', True),
        api_key=net_data.get('api_key')
    )
    
    return SensorConfig(
        data_lake=data_lake,
        collection=collection,
        fim=fim,
        performance=performance,
        logging=logging_config,
        network=network
    )
