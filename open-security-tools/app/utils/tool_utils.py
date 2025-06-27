"""
Utility module for common tool functionality
This module provides standardized utilities for all security tools
"""

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse, urlunparse
import aiohttp
import ssl

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for external API calls"""
    
    def __init__(self, max_requests: int = 10, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission to make a request"""
        async with self._lock:
            now = datetime.now()
            # Remove old requests outside time window
            cutoff = now - timedelta(seconds=self.time_window)
            self.requests = [req_time for req_time in self.requests if req_time > cutoff]
            
            if len(self.requests) >= self.max_requests:
                # Calculate sleep time until we can make another request
                oldest_request = min(self.requests)
                sleep_time = self.time_window - (now - oldest_request).total_seconds()
                if sleep_time > 0:
                    logger.info(f"Rate limit reached, sleeping for {sleep_time:.2f} seconds")
                    await asyncio.sleep(sleep_time)
            
            self.requests.append(now)


class InputValidator:
    """Input validation utilities for security tools"""
    
    # Domain validation pattern (RFC compliant)
    DOMAIN_PATTERN = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    
    # IP address patterns
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    # Hash patterns
    HASH_PATTERNS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'sha512': re.compile(r'^[a-fA-F0-9]{128}$')
    }
    
    @classmethod
    def validate_domain(cls, domain: str) -> str:
        """Validate domain name format"""
        if not domain:
            raise ValueError("Domain cannot be empty")
        
        # Remove protocol if present
        if '://' in domain:
            domain = urlparse(f"http://{domain}").netloc or domain
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Length checks
        if len(domain) > 253:
            raise ValueError("Domain name too long (max 253 characters)")
        
        if not cls.DOMAIN_PATTERN.match(domain):
            raise ValueError("Invalid domain name format")
        
        return domain.lower()
    
    @classmethod
    def validate_ip(cls, ip: str) -> str:
        """Validate IP address format"""
        if not ip:
            raise ValueError("IP address cannot be empty")
        
        if not cls.IPV4_PATTERN.match(ip):
            raise ValueError("Invalid IPv4 address format")
        
        return ip
    
    @classmethod
    def validate_url(cls, url: str) -> str:
        """Validate URL format"""
        if not url:
            raise ValueError("URL cannot be empty")
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        # Validate domain part
        domain = parsed.netloc.split(':')[0]
        cls.validate_domain(domain)
        
        return urlunparse(parsed)
    
    @classmethod
    def validate_hash(cls, hash_value: str, hash_type: Optional[str] = None) -> Dict[str, str]:
        """Validate hash format and detect type"""
        if not hash_value:
            raise ValueError("Hash value cannot be empty")
        
        hash_value = hash_value.strip().lower()
        
        detected_types = []
        for htype, pattern in cls.HASH_PATTERNS.items():
            if pattern.match(hash_value):
                detected_types.append(htype)
        
        if not detected_types:
            raise ValueError("Invalid hash format")
        
        if hash_type and hash_type not in detected_types:
            raise ValueError(f"Hash does not match specified type {hash_type}")
        
        return {
            'hash': hash_value,
            'type': hash_type or detected_types[0],
            'possible_types': detected_types
        }
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        if not filename:
            raise ValueError("Filename cannot be empty")
        
        # Remove path components
        filename = filename.split('/')[-1].split('\\')[-1]
        
        # Remove dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\0']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Prevent hidden files and special names
        if filename.startswith('.'):
            filename = '_' + filename[1:]
        
        # Windows reserved names
        reserved_names = ['CON', 'PRN', 'AUX', 'NUL'] + [f'COM{i}' for i in range(1, 10)] + [f'LPT{i}' for i in range(1, 10)]
        if filename.upper() in reserved_names:
            filename = f"_{filename}"
        
        return filename[:255]  # Limit length
    
    @classmethod
    def validate_port(cls, port: Union[int, str]) -> int:
        """Validate port number"""
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            raise ValueError("Port must be a number")
        
        if not 1 <= port_num <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        
        return port_num
    
    @classmethod
    def validate_timeout(cls, timeout: Union[int, float], min_timeout: int = 1, max_timeout: int = 300) -> float:
        """Validate timeout value"""
        try:
            timeout_val = float(timeout)
        except (ValueError, TypeError):
            raise ValueError("Timeout must be a number")
        
        if not min_timeout <= timeout_val <= max_timeout:
            raise ValueError(f"Timeout must be between {min_timeout} and {max_timeout} seconds")
        
        return timeout_val


class SessionManager:
    """HTTP session manager with proper resource handling"""
    
    def __init__(self, timeout: int = 30, max_connections: int = 100, max_connections_per_host: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=max_connections_per_host,
            ssl=ssl.create_default_context()
        )
        self._session = None
    
    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=self.connector,
            headers={'User-Agent': 'Wildbox-Security-Tools/1.0'}
        )
        return self._session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()


class ToolExceptionHandler:
    """Centralized exception handling for tools"""
    
    @staticmethod
    def handle_network_error(e: Exception, target: str) -> Dict[str, Any]:
        """Handle network-related errors"""
        if isinstance(e, asyncio.TimeoutError):
            return {
                'success': False,
                'error': f"Timeout connecting to {target}",
                'error_type': 'timeout'
            }
        elif isinstance(e, aiohttp.ClientConnectorError):
            return {
                'success': False,
                'error': f"Failed to connect to {target}",
                'error_type': 'connection'
            }
        elif isinstance(e, aiohttp.ClientResponseError):
            return {
                'success': False,
                'error': f"HTTP error {e.status}: {e.message}",
                'error_type': 'http'
            }
        else:
            return {
                'success': False,
                'error': f"Network error: {str(e)}",
                'error_type': 'network'
            }
    
    @staticmethod
    def handle_validation_error(e: Exception) -> Dict[str, Any]:
        """Handle validation errors"""
        return {
            'success': False,
            'error': f"Invalid input: {str(e)}",
            'error_type': 'validation'
        }
    
    @staticmethod
    def handle_generic_error(e: Exception, tool_name: str) -> Dict[str, Any]:
        """Handle generic errors"""
        logger.error(f"Unexpected error in {tool_name}: {str(e)}", exc_info=True)
        return {
            'success': False,
            'error': f"Analysis failed: {type(e).__name__}",
            'error_type': 'internal'
        }


class MetricsCollector:
    """Simple metrics collection for monitoring"""
    
    def __init__(self):
        self._metrics = {}
        self._counters = {}
    
    def timer(self, name: str):
        """Context manager for timing operations"""
        return TimerContext(self, name)
    
    def counter(self, name: str):
        """Get or create a counter"""
        if name not in self._counters:
            self._counters[name] = 0
        return CounterWrapper(self._counters, name)
    
    def gauge(self, name: str, value: float):
        """Set a gauge value"""
        self._metrics[name] = {
            'type': 'gauge',
            'value': value,
            'timestamp': time.time()
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics"""
        return {
            'metrics': self._metrics,
            'counters': self._counters
        }


class TimerContext:
    """Timer context manager"""
    
    def __init__(self, collector: MetricsCollector, name: str):
        self.collector = collector
        self.name = name
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.collector.gauge(self.name, duration)


class CounterWrapper:
    """Counter wrapper"""
    
    def __init__(self, counters: Dict[str, int], name: str):
        self.counters = counters
        self.name = name
    
    def increment(self, value: int = 1):
        """Increment counter"""
        self.counters[self.name] += value
    
    def get(self) -> int:
        """Get counter value"""
        return self.counters[self.name]


# Global instances
default_rate_limiter = RateLimiter()
metrics_collector = MetricsCollector()
