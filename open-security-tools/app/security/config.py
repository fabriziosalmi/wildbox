"""
Enhanced Security Configuration Management
Replaces hardcoded values with secure configuration.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class SecurityConfig:
    """Enhanced security configuration management."""
    
    def __init__(self):
        self.config_dir = Path(os.getenv('SECURITY_CONFIG_DIR', '/etc/security'))
        self.validate_environment()
        self.load_all_configs()
    
    def validate_environment(self):
        """Validate required environment variables."""
        required_vars = [
            'JWT_SECRET_KEY',
            'DATABASE_URL',
            'REDIS_URL',
            'ENCRYPTION_KEY'
        ]
        
        missing = [var for var in required_vars if not os.getenv(var)]
        if missing:
            raise ValueError(f"Missing required environment variables: {missing}")
    
    def load_all_configs(self):
        """Load all security configurations."""
        try:
            self.api_config = self.load_api_configuration()
            self.rate_limits = self.load_rate_limit_configuration()
            self.security_headers = self.load_security_headers()
            self.tool_permissions = self.load_tool_permissions()
            logger.info("Security configuration loaded successfully")
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Failed to load security configuration: {e}")
            raise
    
    def load_api_configuration(self) -> Dict[str, str]:
        """Load API endpoints configuration."""
        return {
            'virustotal': os.getenv('VIRUSTOTAL_API_URL', 'https://www.virustotal.com/vtapi/v2/'),
            'shodan': os.getenv('SHODAN_API_URL', 'https://api.shodan.io/'),
            'censys': os.getenv('CENSYS_API_URL', 'https://search.censys.io/api/v2/'),
            'hibp': os.getenv('HIBP_API_URL', 'https://haveibeenpwned.com/api/v3/'),
            'urlvoid': os.getenv('URLVOID_API_URL', 'https://api.urlvoid.com/v1/'),
            'abuseipdb': os.getenv('ABUSEIPDB_API_URL', 'https://api.abuseipdb.com/api/v2/'),
        }
    
    def load_rate_limit_configuration(self) -> Dict[str, int]:
        """Load rate limiting configuration."""
        return {
            'requests_per_minute': int(os.getenv('RATE_LIMIT_RPM', '60')),
            'requests_per_hour': int(os.getenv('RATE_LIMIT_RPH', '1000')),
            'requests_per_day': int(os.getenv('RATE_LIMIT_RPD', '10000')),
            'max_concurrent_requests': int(os.getenv('MAX_CONCURRENT_REQUESTS', '10')),
            'burst_size': int(os.getenv('BURST_SIZE', '20'))
        }
    
    def load_security_headers(self) -> Dict[str, str]:
        """Load security headers configuration."""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
    
    def load_tool_permissions(self) -> Dict[str, Dict[str, Any]]:
        """Load tool-specific permissions and constraints."""
        config_file = self.config_dir / 'tool_permissions.json'
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        
        # Default safe configuration
        return {
            'sql_injection_scanner': {
                'max_payloads': 20,
                'timeout': 10,
                'require_authorization': True,
                'destructive_payloads_allowed': False
            },
            'port_scanner': {
                'max_ports': 1000,
                'timeout': 5,
                'require_authorization': True,
                'rate_limit_per_target': 10
            },
            'file_upload_scanner': {
                'max_file_size': 1048576,  # 1MB
                'allowed_extensions': ['.txt', '.pdf', '.jpg', '.png'],
                'require_authorization': True,
                'malicious_payloads_allowed': False
            }
        }
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tool."""
        return self.tool_permissions.get(tool_name, {})
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a tool is enabled."""
        tool_config = self.get_tool_config(tool_name)
        return tool_config.get('enabled', True)
    
    def get_max_file_size(self, tool_name: str = None) -> int:
        """Get maximum file size for uploads."""
        if tool_name:
            tool_config = self.get_tool_config(tool_name)
            return tool_config.get('max_file_size', 10 * 1024 * 1024)  # 10MB default
        return int(os.getenv('MAX_FILE_SIZE', '104857600'))  # 100MB default
    
    def get_timeout(self, tool_name: str = None) -> int:
        """Get timeout for operations."""
        if tool_name:
            tool_config = self.get_tool_config(tool_name)
            return tool_config.get('timeout', 30)
        return int(os.getenv('DEFAULT_TIMEOUT', '30'))
    
    def get_allowed_domains(self) -> List[str]:
        """Get list of allowed domains for testing."""
        domains_str = os.getenv('ALLOWED_DOMAINS', '')
        return [d.strip() for d in domains_str.split(',') if d.strip()]
    
    def get_blocked_domains(self) -> List[str]:
        """Get list of blocked domains."""
        domains_str = os.getenv('BLOCKED_DOMAINS', '')
        return [d.strip() for d in domains_str.split(',') if d.strip()]

# Global configuration instance
security_config = SecurityConfig()
