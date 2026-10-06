"""
Configuration management for the Security Sensor
"""

import os
import re
import yaml
import logging
from pathlib import Path
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Where a batch goes, relative to the gateway (#628). The sensor never talks
# to the data service directly: the data service accepts only requests the
# gateway has authenticated, so the sensor authenticates at the gateway with
# an identity API key, and the gateway forwards the batch with the key's team.
INGEST_PATH = "/api/v1/data/ingest"

# The most a batch's events may weigh, serialized. The gateway refuses a
# request body over 10 MiB (client_max_body_size); this leaves room for the
# envelope and for a proxy that counts differently.
MAX_BATCH_BYTES = 8 * 1024 * 1024
# The smallest buffer that still holds one event of any size a batch takes
# would be MAX_BATCH_BYTES; a smaller one is allowed, down to this, and then
# bounds the size of an event too.
MIN_BUFFER_BYTES = 64 * 1024

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
    # A batch the gateway does not take for a reason that may pass is kept
    # and sent again: first after retry_delay seconds, then after twice as
    # long each time, up to retry_max_delay. No number of attempts gives it
    # up. What waits meanwhile is bounded by buffer_max_events and
    # buffer_max_bytes (of serialized events); see
    # sensor.pipeline.data_forwarder.
    retry_delay: int = 5
    retry_max_delay: int = 300
    buffer_max_events: int = 5000
    buffer_max_bytes: int = 16 * 1024 * 1024
    # The share of the team's request budget at the gateway that this
    # sensor may use in a minute; the rest is left to the team's other
    # clients (its dashboard sessions, its other keys).
    rate_limit_share: float = 0.5
    # data_lake keys the file sets that no longer mean anything.
    obsolete_keys: List[str] = field(default_factory=list, repr=False)

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

        numbers = (
            "batch_size",
            "flush_interval",
            "timeout",
            "retry_delay",
            "retry_max_delay",
            "buffer_max_events",
            "buffer_max_bytes",
        )
        for name in numbers:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                errors.append(f"data_lake.{name} must be a whole number, got {value!r}")
        if errors:
            return errors

        for name in ("batch_size", "flush_interval", "timeout"):
            if getattr(self, name) < 1:
                errors.append(f"data_lake.{name} must be at least 1")
        if self.retry_delay < 0:
            errors.append("data_lake.retry_delay must not be negative")
        if self.retry_max_delay < self.retry_delay:
            errors.append(
                "data_lake.retry_max_delay must not be less than "
                "data_lake.retry_delay"
            )
        if self.buffer_max_events < self.batch_size:
            errors.append(
                f"data_lake.buffer_max_events ({self.buffer_max_events}) must "
                f"be at least data_lake.batch_size ({self.batch_size}): the "
                f"buffer holds the batch being sent"
            )
        if self.buffer_max_bytes < MIN_BUFFER_BYTES:
            errors.append(
                f"data_lake.buffer_max_bytes must be at least {MIN_BUFFER_BYTES}"
            )
        share = self.rate_limit_share
        if (
            isinstance(share, bool)
            or not isinstance(share, (int, float))
            or not 0 < share <= 1
        ):
            errors.append(
                f"data_lake.rate_limit_share must be a number above 0 and at "
                f"most 1, got {share!r}"
            )
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

# What the log forwarder reads (#638). The section used to be ignored: the
# forwarder read a fixed list of paths whatever the file said.
LOG_SOURCE_TYPES = ("file", "journald", "windows_event", "unified_log")
LOG_FILE_FORMATS = ("syslog", "nginx", "apache", "raw")
LOG_READ_FROM = ("end", "beginning")
# The one format each of the other types produces.
_FIXED_LOG_FORMATS = {
    "journald": "json",
    "unified_log": "json",
    "windows_event": "windows_event",
}
_LOG_SOURCE_KEYS = (
    "name",
    "type",
    "path",
    "format",
    "enabled",
    "read_from",
    "log_name",
)
MAX_LOG_SOURCES = 64
# A source's name becomes the event type ("log.<name>") and a tag.
_LOG_SOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Same pattern the forwarder applies before it names the log to PowerShell.
_WINDOWS_LOG_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,63}$")
_WILDCARDS = re.compile(r"[*?\[]")


def has_wildcard(path: str) -> bool:
    """Is this path a glob pattern?"""
    return bool(_WILDCARDS.search(path))


def log_source_root(path: str) -> str:
    """The directory a file source is confined to.

    The longest leading run of directories the path names without a wildcard:
    ``/var/log/nginx`` for ``/var/log/nginx/access.log`` and for
    ``/var/log/nginx/*.log``, ``/var/www`` for ``/var/www/*/logs/access.log``.
    The forwarder reads no file that resolves outside it.
    """
    drive, tail = os.path.splitdrive(path)
    parts = tail.replace("\\", "/").split("/") if os.name == "nt" else tail.split("/")
    kept = []
    for part in parts[:-1]:
        if has_wildcard(part):
            break
        kept.append(part)
    root = "/".join(kept)
    return (drive + root) if root else (drive + "/")


@dataclass
class LogSourceConfig:
    """One entry of ``log_sources``: something the log forwarder reads.

    ``type: file`` tails ``path``, a file or a glob pattern, and parses each
    line as ``format``. The other types read a system log and take no path.
    """

    name: str
    type: str = "file"
    path: Optional[str] = None
    format: str = "raw"
    enabled: bool = True
    # Where to start in a file that exists when the sensor starts. A file that
    # appears later is always read from its beginning.
    read_from: str = "end"
    log_name: Optional[str] = None  # windows_event only

    @property
    def root(self) -> Optional[str]:
        return log_source_root(self.path) if self.path else None

    def to_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


def parse_log_sources(raw: Any) -> Tuple[List[LogSourceConfig], List[str]]:
    """The ``log_sources`` section as sources, and what is wrong with it.

    Every problem names its entry, so that one start-up reports them all. An
    entry with a problem yields no source: a section with errors stops the
    sensor (see ``SensorConfig.validate``) rather than run with part of it.
    Whether a path exists or can be read is not checked here: that changes
    while the sensor runs, and the forwarder reports it per source.
    """
    if raw is None:
        return [], [
            "log_sources is present but empty: list the sources, write "
            "'log_sources: []' to forward no log, or remove the key to read "
            "the platform's default sources"
        ]
    if not isinstance(raw, list):
        return [], [
            f"log_sources must be a list of sources, got {type(raw).__name__}"
        ]
    if len(raw) > MAX_LOG_SOURCES:
        return [], [
            f"log_sources has {len(raw)} entries; at most {MAX_LOG_SOURCES} "
            f"are supported (a glob pattern covers many files in one entry)"
        ]

    sources: List[LogSourceConfig] = []
    errors: List[str] = []
    names = set()
    for index, entry in enumerate(raw):
        where = f"log_sources[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{where} must be a mapping with a name and a path")
            continue
        name = entry.get("name")
        if isinstance(name, str) and name:
            where = f"{where} ({name!r})"
        problems = _log_source_problems(entry)
        if isinstance(name, str) and name in names:
            problems.append(f"the name {name!r} is used by an earlier source")
        if problems:
            errors.extend(f"{where}: {problem}" for problem in problems)
            continue
        names.add(name)
        source_type = entry.get("type", "file")
        sources.append(
            LogSourceConfig(
                name=name,
                type=source_type,
                path=entry.get("path"),
                format=entry.get("format")
                or _FIXED_LOG_FORMATS.get(source_type, "raw"),
                enabled=entry.get("enabled", True),
                read_from=entry.get("read_from", "end"),
                log_name=entry.get("log_name"),
            )
        )
    return sources, errors


def _log_source_problems(entry: Dict[str, Any]) -> List[str]:
    """What is wrong with one ``log_sources`` entry."""
    problems = []

    unknown = sorted(str(key) for key in entry if key not in _LOG_SOURCE_KEYS)
    if unknown:
        # Refused, not ignored: 'enable: false' would otherwise leave a
        # source the operator meant to switch off forwarding its file.
        problems.append(
            f"unknown key(s) {', '.join(unknown)}; the keys are "
            f"{', '.join(_LOG_SOURCE_KEYS)}"
        )

    name = entry.get("name")
    if not isinstance(name, str) or not _LOG_SOURCE_NAME.match(name):
        problems.append(
            "name is required: 1 to 64 letters, digits, '_', '.' or '-', "
            "starting with a letter or a digit"
        )

    if not isinstance(entry.get("enabled", True), bool):
        problems.append(
            f"enabled must be true or false, got {entry.get('enabled')!r}"
        )

    source_type = entry.get("type", "file")
    if source_type not in LOG_SOURCE_TYPES:
        problems.append(
            f"unknown type {source_type!r}; the types are "
            f"{', '.join(LOG_SOURCE_TYPES)}"
        )
        return problems

    source_format = entry.get("format")
    if source_type == "file":
        problems.extend(_log_path_problems(entry.get("path")))
        if source_format is not None and source_format not in LOG_FILE_FORMATS:
            problems.append(
                f"unknown format {source_format!r}; the formats of a file "
                f"source are {', '.join(LOG_FILE_FORMATS)}"
            )
        if entry.get("read_from", "end") not in LOG_READ_FROM:
            problems.append(
                f"read_from must be one of {', '.join(LOG_READ_FROM)}, got "
                f"{entry.get('read_from')!r}"
            )
        if "log_name" in entry:
            problems.append("log_name applies to type windows_event only")
        return problems

    fixed = _FIXED_LOG_FORMATS[source_type]
    if source_format is not None and source_format != fixed:
        problems.append(
            f"a {source_type} source has the format {fixed}; remove format"
        )
    for key in ("path", "read_from"):
        if key in entry:
            problems.append(f"{key} applies to type file only")
    if source_type == "windows_event":
        log_name = entry.get("log_name")
        if not isinstance(log_name, str) or not _WINDOWS_LOG_NAME.match(log_name):
            problems.append(
                "log_name is required for type windows_event: the event "
                "log's name, such as Security"
            )
    elif "log_name" in entry:
        problems.append("log_name applies to type windows_event only")
    return problems


def _log_path_problems(path: Any) -> List[str]:
    """What is wrong with a file source's ``path``."""
    if not isinstance(path, str) or not path:
        return ["path is required for type file"]
    if "\x00" in path:
        return ["path must not contain a NUL character"]
    if not os.path.isabs(path):
        return [f"path must be absolute, got {path!r}"]
    if "**" in path:
        return [
            f"path {path!r}: '**' is not supported; a pattern does not "
            f"descend into directories it does not name"
        ]
    root = log_source_root(path)
    if has_wildcard(path) and os.path.splitdrive(root)[1] in ("/", "\\", ""):
        return [
            f"path {path!r}: a pattern must name the directory it reads, "
            f"not match from the filesystem root"
        ]
    return []


# The most fim.max_files may be: a watched file takes about 700 bytes of
# memory and 250 of the saved baseline.
FIM_MAX_FILES_LIMIT = 1000000


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
    # The most files the monitor watches, all paths together: what it keeps
    # in memory and in its saved baseline. Beyond it files are not watched,
    # and the monitor says how many.
    max_files: int = 50000

@dataclass
class PerformanceConfig:
    """Performance tuning configuration"""
    query_interval: int = 10
    max_memory_mb: int = 128
    max_cpu_percent: int = 5
    max_queue_size: int = 1000
    worker_threads: int = 4


LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file: Optional[str] = None
    max_size: int = 10485760  # 10MB
    backup_count: int = 5
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    def validate(self) -> List[str]:
        """Errors in the logging settings.

        They were handed to the logging module unchecked. A format it
        refuses ("json") stopped the sensor with a traceback; one it
        accepts and cannot apply (a field no record has) made every log
        call fail, so the sensor ran and logged nothing.
        """
        errors = []
        if not isinstance(self.level, str) or self.level.upper() not in LOG_LEVELS:
            errors.append(
                f"logging.level must be one of {', '.join(LOG_LEVELS)}, got "
                f"{self.level!r}"
            )
        errors.extend(self._format_errors())
        for name in ("max_size", "backup_count"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(
                    f"logging.{name} must be a whole number, 0 or more, got "
                    f"{value!r}"
                )
        if self.file is not None and (not isinstance(self.file, str) or not self.file):
            errors.append(f"logging.file must be a path or null, got {self.file!r}")
        return errors

    def _format_errors(self) -> List[str]:
        example = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        # Empty, the logging module would use a format of its own.
        if not isinstance(self.format, str) or not self.format.strip():
            return [
                f"logging.format must be a logging format such as {example!r}, "
                f"got {self.format!r}"
            ]
        marker = "a record of the sensor"
        record = logging.LogRecord("sensor", logging.INFO, __file__, 1, marker, None, None)
        try:
            # The format is applied to a record, as it will be to every one.
            line = logging.Formatter(self.format).format(record)
        except (ValueError, KeyError, TypeError) as e:
            return [
                f"logging.format {self.format!r} is not a format the logging "
                f"module can apply ({type(e).__name__}: {e}); it is a "
                f"%-style format such as {example!r}"
            ]
        if marker not in line:
            return [
                f"logging.format {self.format!r} has no %(message)s: the "
                f"sensor would log lines without their message"
            ]
        return []


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
    # What the log forwarder reads. None: the configuration has no
    # log_sources section, and the forwarder reads the platform's defaults.
    # A list, even an empty one: exactly these sources.
    log_sources: Optional[List[LogSourceConfig]] = None
    # What parse_log_sources found wrong with the section.
    log_source_errors: List[str] = field(default_factory=list, repr=False)
    # Where the sensor keeps what must outlive the process: the log
    # forwarder's read positions. None: nowhere, positions are in memory
    # only and read_from applies again at every start.
    data_dir: Optional[str] = None

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []

        # Validate data lake configuration
        errors.extend(self.data_lake.validate())

        # So do logging settings the logging module cannot use.
        errors.extend(self.logging.validate())

        # A log source that cannot be understood stops the sensor, as a
        # destination that cannot work does: reading something other than
        # what the operator wrote is not a safe fallback.
        errors.extend(self.log_source_errors)

        # A data directory the operator names and the sensor cannot write
        # would mean positions silently not kept.
        if self.data_dir is not None:
            from sensor.collectors.position_store import data_dir_problem

            if not isinstance(self.data_dir, str):
                errors.append(f"data_dir must be a path, got {self.data_dir!r}")
            else:
                problem = data_dir_problem(self.data_dir)
                if problem:
                    errors.append(problem)

        # Validate performance limits
        if self.performance.max_memory_mb < 32:
            errors.append("performance.max_memory_mb must be at least 32MB")
        
        if self.performance.max_cpu_percent < 1 or self.performance.max_cpu_percent > 100:
            errors.append("performance.max_cpu_percent must be between 1 and 100")
        
        # Validate FIM paths. Whether a path exists is not checked here: it
        # can appear while the sensor runs, and the file monitor reports it.
        if not isinstance(self.fim.paths, list) or not all(
            isinstance(path, str) and os.path.isabs(path) for path in self.fim.paths
        ):
            errors.append(
                f"fim.paths must be a list of absolute paths, got "
                f"{self.fim.paths!r}"
            )
        elif self.fim.enabled and not self.fim.paths:
            errors.append("fim.paths cannot be empty when FIM is enabled")
        # A string here would be read one character at a time, and its "*"
        # would exclude every file.
        patterns = self.fim.exclude_patterns
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) for pattern in patterns
        ):
            errors.append(
                f"fim.exclude_patterns must be a list of patterns, got {patterns!r}"
            )
        for name, least, most in (
            ("max_depth", 0, 1000),
            ("max_files", 1, FIM_MAX_FILES_LIMIT),
        ):
            value = getattr(self.fim, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not least <= value <= most
            ):
                errors.append(
                    f"fim.{name} must be a whole number between {least} and "
                    f"{most}, got {value!r}"
                )
        
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
        'SENSOR_DATA_DIR': ['data_dir'],
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
                    # The variable, not its value: what is set by mistake
                    # can be a secret meant for another variable (#755).
                    logger.warning(f"{env_var} is not an integer and is ignored")
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
        retry_delay=data_lake_data.get('retry_delay', 5),
        retry_max_delay=data_lake_data.get('retry_max_delay', 300),
        buffer_max_events=data_lake_data.get('buffer_max_events', 5000),
        buffer_max_bytes=data_lake_data.get('buffer_max_bytes', 16 * 1024 * 1024),
        rate_limit_share=data_lake_data.get('rate_limit_share', 0.5),
        # Read by nothing since #725: a batch is no longer given up after a
        # number of attempts. Said at start-up rather than silently ignored.
        obsolete_keys=[key for key in ('retry_attempts',) if key in data_lake_data],
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
        max_depth=fim_data.get('max_depth', 10),
        max_files=fim_data.get('max_files', 50000)
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

    # Log sources. The key's presence is what matters: absent, the forwarder
    # reads the platform's defaults; present, exactly what it lists.
    log_sources = None
    log_source_errors: List[str] = []
    if 'log_sources' in config_data:
        log_sources, log_source_errors = parse_log_sources(config_data['log_sources'])

    return SensorConfig(
        data_lake=data_lake,
        collection=collection,
        fim=fim,
        performance=performance,
        logging=logging_config,
        network=network,
        log_sources=log_sources,
        log_source_errors=log_source_errors,
        # An empty value (an unset variable) means "not set".
        data_dir=config_data.get('data_dir') or None,
    )
