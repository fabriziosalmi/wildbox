"""
Configuration management for security tools
"""

import os
from typing import Dict, Any, Optional
from pathlib import Path


class ToolConfig:
    """Centralized configuration for all security tools"""
    
    # Default timeouts
    DEFAULT_TIMEOUT = 30
    MIN_TIMEOUT = 1
    MAX_TIMEOUT = 300
    
    # Rate limiting defaults
    DEFAULT_RATE_LIMIT = 10  # requests per minute
    DEFAULT_RATE_WINDOW = 60  # seconds
    
    # Connection limits
    MAX_CONNECTIONS = 100
    MAX_CONNECTIONS_PER_HOST = 10
    
    # File size limits
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    MAX_HASH_BATCH_SIZE = 1000
    
    # API endpoints (configurable via environment)
    API_ENDPOINTS = {
        'virustotal': os.getenv('VIRUSTOTAL_API_URL', 'https://www.virustotal.com/vtapi/v2/'),
        'shodan': os.getenv('SHODAN_API_URL', 'https://api.shodan.io/'),
        'censys': os.getenv('CENSYS_API_URL', 'https://search.censys.io/api/v2/'),
        'have_i_been_pwned': os.getenv('HIBP_API_URL', 'https://haveibeenpwned.com/api/v3/'),
        'urlvoid': os.getenv('URLVOID_API_URL', 'https://api.urlvoid.com/v1/'),
        'abuseipdb': os.getenv('ABUSEIPDB_API_URL', 'https://api.abuseipdb.com/api/v2/'),
    }
    
    # Security settings
    ALLOWED_DOMAINS = os.getenv('ALLOWED_DOMAINS', '').split(',') if os.getenv('ALLOWED_DOMAINS') else []
    BLOCKED_DOMAINS = os.getenv('BLOCKED_DOMAINS', '').split(',') if os.getenv('BLOCKED_DOMAINS') else []
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    @classmethod
    def get_api_key(cls, service: str) -> Optional[str]:
        """Get API key for a service from environment variables"""
        key_name = f'{service.upper()}_API_KEY'
        return os.getenv(key_name)
    
    @classmethod
    def require_api_key(cls, service: str) -> str:
        """Get API key for a service, raise error if not found"""
        key = cls.get_api_key(service)
        if not key:
            raise ValueError(f"API key for {service} not configured. Set {service.upper()}_API_KEY environment variable")
        return key
    
    @classmethod
    def get_endpoint(cls, service: str) -> str:
        """Get API endpoint for a service"""
        endpoint = cls.API_ENDPOINTS.get(service.lower())
        if not endpoint:
            raise ValueError(f"Unknown service: {service}")
        return endpoint
    
    @classmethod
    def is_domain_allowed(cls, domain: str) -> bool:
        """Check if domain is allowed for scanning"""
        domain = domain.lower()
        
        # Check blocked list first
        if cls.BLOCKED_DOMAINS and any(blocked in domain for blocked in cls.BLOCKED_DOMAINS if blocked):
            return False
        
        # If allow list is configured, only allow those domains
        if cls.ALLOWED_DOMAINS:
            return any(allowed in domain for allowed in cls.ALLOWED_DOMAINS if allowed)
        
        # Default: allow all domains (except blocked)
        return True
    
    @classmethod
    def get_tool_config(cls, tool_name: str) -> Dict[str, Any]:
        """Get tool-specific configuration"""
        config = {
            'timeout': cls.DEFAULT_TIMEOUT,
            'rate_limit': cls.DEFAULT_RATE_LIMIT,
            'rate_window': cls.DEFAULT_RATE_WINDOW,
            'max_connections': cls.MAX_CONNECTIONS,
            'max_connections_per_host': cls.MAX_CONNECTIONS_PER_HOST,
        }
        
        # Tool-specific overrides from environment
        tool_prefix = f'TOOL_{tool_name.upper()}_'
        for key in config.keys():
            env_key = f'{tool_prefix}{key.upper()}'
            env_value = os.getenv(env_key)
            if env_value:
                try:
                    # Try to convert to appropriate type
                    if isinstance(config[key], int):
                        config[key] = int(env_value)
                    elif isinstance(config[key], float):
                        config[key] = float(env_value)
                    else:
                        config[key] = env_value
                except ValueError:
                    pass  # Keep default value if conversion fails
        
        return config
    
    @classmethod
    def validate_config(cls) -> Dict[str, Any]:
        """Validate configuration and return status"""
        issues = []
        warnings = []
        
        # Check required environment variables for production
        if os.getenv('ENVIRONMENT') == 'production':
            required_vars = ['API_KEY_SECRET', 'DATABASE_URL']
            for var in required_vars:
                if not os.getenv(var):
                    issues.append(f"Missing required environment variable: {var}")
        
        # Check API keys
        api_services = ['virustotal', 'shodan', 'censys']
        missing_keys = []
        for service in api_services:
            if not cls.get_api_key(service):
                missing_keys.append(service)
        
        if missing_keys:
            warnings.append(f"Missing API keys for services: {', '.join(missing_keys)}")
        
        # Check timeout values
        if cls.DEFAULT_TIMEOUT < cls.MIN_TIMEOUT or cls.DEFAULT_TIMEOUT > cls.MAX_TIMEOUT:
            issues.append(f"Invalid default timeout: {cls.DEFAULT_TIMEOUT}")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }


class SecurityConfig:
    """Security-specific configuration"""
    
    # Input validation limits
    MAX_INPUT_LENGTH = 10000
    MAX_BATCH_SIZE = 100
    MAX_CONCURRENT_REQUESTS = 50
    
    # Scanning limits
    MAX_PORTS_PER_SCAN = 1000
    MAX_SUBDOMAINS_PER_SCAN = 10000
    MAX_URLS_PER_SCAN = 1000
    
    # File handling
    ALLOWED_FILE_EXTENSIONS = ['.txt', '.csv', '.json', '.xml', '.log']
    MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB
    
    # Network scanning restrictions
    PRIVATE_IP_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16'
    ]
    
    RESTRICTED_PORTS = [
        22,    # SSH
        3389,  # RDP
        5432,  # PostgreSQL
        3306,  # MySQL
        1433,  # MSSQL
        6379,  # Redis
    ]
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """Check if IP address is in private range"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in ipaddress.ip_network(network) for network in cls.PRIVATE_IP_RANGES)
        except ValueError:
            return False
    
    @classmethod
    def is_port_restricted(cls, port: int) -> bool:
        """Check if port is restricted for scanning"""
        return port in cls.RESTRICTED_PORTS
    
    @classmethod
    def validate_scan_target(cls, target: str) -> Dict[str, Any]:
        """Validate if target is safe to scan"""
        issues = []
        warnings = []
        
        # Check if target is private IP
        if cls.is_private_ip(target):
            issues.append("Scanning private IP addresses is not allowed")
        
        # Check domain restrictions
        if not ToolConfig.is_domain_allowed(target):
            issues.append("Target domain is not allowed for scanning")
        
        return {
            'allowed': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }


# Initialize configuration validation on import
config_status = ToolConfig.validate_config()
if not config_status['valid']:
    import logging
    logger = logging.getLogger(__name__)
    logger.error(f"Configuration validation failed: {config_status['issues']}")

if config_status['warnings']:
    import logging
    logger = logging.getLogger(__name__)
    for warning in config_status['warnings']:
        logger.warning(warning)
