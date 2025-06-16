"""
Enhanced Input Validation and Sanitization
Comprehensive security validation for all security tools.
"""

import re
import json
import ipaddress
import urllib.parse
from typing import Any, Dict, List, Union, Optional
from fastapi import HTTPException, status
import logging

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Comprehensive security validation for all inputs."""
    
    # Enhanced dangerous patterns
    DANGEROUS_PATTERNS = [
        # SQL injection patterns (comprehensive)
        r"(?i)(\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b|\bINSERT\b.*\bINTO\b)",
        r"(?i)(\bDELETE\b.*\bFROM\b|\bUPDATE\b.*\bSET\b|\bCREATE\b.*\bTABLE\b)",
        r"(?i)(\bEXEC\b|\bEXECUTE\b|\bxp_cmdshell\b)",
        r"(?i)('|\").*(-{2}|#|\/\*)",
        r"(?i)(waitfor\s+delay|pg_sleep|sleep\s*\()",
        
        # NoSQL injection patterns
        r"(?i)(\$ne|\$gt|\$lt|\$gte|\$lte|\$regex|\$where|\$exists)",
        r"(?i)(\$or|\$and|\$not|\$nor)",
        
        # XSS patterns (enhanced)
        r"(?i)<script[^>]*>.*?</script>",
        r"(?i)(javascript:|data:|vbscript:|about:)",
        r"(?i)(on\w+\s*=|<iframe|<object|<embed)",
        r"(?i)(expression\s*\(|@import|background-image\s*:)",
        
        # Command injection patterns
        r"[;&|`$\(\){}]",
        r"(?i)(wget|curl|nc|netcat|bash|sh|cmd|powershell)",
        r"(?i)(eval|exec|system|passthru|shell_exec)",
        
        # Path traversal patterns
        r"\.\.[\\/]",
        r"(?i)(etc[\\/]passwd|windows[\\/]system32)",
        r"(?i)(proc[\\/]|dev[\\/]|sys[\\/])",
        
        # File inclusion patterns
        r"(?i)(file|http|ftp|data|php|expect)://",
        
        # XXE patterns
        r"(?i)(<!entity|<!doctype.*entity)",
        r"(?i)(SYSTEM\s+[\"']|PUBLIC\s+[\"'])",
        
        # LDAP injection patterns
        r"[()=*!&|]",
        r"(?i)(\(|\)|=|\*|!|&|\|)",
        
        # Template injection
        r"(?i)(\{\{|\}\}|<%|%>)",
        r"(?i)(jinja|twig|freemarker|velocity)"
    ]
    
    # Allowed URL schemes
    ALLOWED_URL_SCHEMES = ['http', 'https']
    
    # Maximum input lengths
    MAX_LENGTHS = {
        'url': 2048,
        'domain': 253,
        'ip': 45,  # IPv6 max length
        'string': 1000,
        'filename': 255,
        'email': 254
    }
    
    @classmethod
    def validate_url(cls, url: str, allow_private: bool = False) -> str:
        """Validate and sanitize URL input."""
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")
        
        if len(url) > cls.MAX_LENGTHS['url']:
            raise ValueError(f"URL too long (max {cls.MAX_LENGTHS['url']} characters)")
        
        # Check for dangerous patterns
        cls._check_dangerous_patterns(url)
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Validate scheme
            if parsed.scheme.lower() not in cls.ALLOWED_URL_SCHEMES:
                raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
            
            # Validate hostname
            if not parsed.hostname:
                raise ValueError("URL must have a hostname")
            
            # Check for private/local addresses if not allowed
            if not allow_private:
                cls._validate_public_host(parsed.hostname)
            
            return url
            
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")
    
    @classmethod
    def validate_ip_address(cls, ip: str) -> str:
        """Validate IP address."""
        if not ip or not isinstance(ip, str):
            raise ValueError("IP address must be a non-empty string")
        
        if len(ip) > cls.MAX_LENGTHS['ip']:
            raise ValueError(f"IP address too long")
        
        try:
            # This will raise an exception for invalid IPs
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValueError("Invalid IP address format")
    
    @classmethod
    def validate_domain(cls, domain: str) -> str:
        """Validate domain name."""
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")
        
        if len(domain) > cls.MAX_LENGTHS['domain']:
            raise ValueError(f"Domain too long (max {cls.MAX_LENGTHS['domain']} characters)")
        
        # Check for dangerous patterns
        cls._check_dangerous_patterns(domain)
        
        # Basic domain format validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain):
            raise ValueError("Invalid domain format")
        
        return domain
    
    @classmethod
    def validate_string(cls, value: str, max_length: int = None, field_name: str = "input") -> str:
        """Validate and sanitize string input."""
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")
        
        max_len = max_length or cls.MAX_LENGTHS['string']
        if len(value) > max_len:
            raise ValueError(f"{field_name} too long (max {max_len} characters)")
        
        # Check for dangerous patterns
        cls._check_dangerous_patterns(value)
        
        # Basic sanitization
        sanitized = value.strip()
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        return sanitized
    
    @classmethod
    def validate_filename(cls, filename: str) -> str:
        """Validate filename for security."""
        if not filename or not isinstance(filename, str):
            raise ValueError("Filename must be a non-empty string")
        
        if len(filename) > cls.MAX_LENGTHS['filename']:
            raise ValueError(f"Filename too long (max {cls.MAX_LENGTHS['filename']} characters)")
        
        # Check for path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            raise ValueError("Filename contains invalid path characters")
        
        # Check for dangerous patterns
        cls._check_dangerous_patterns(filename)
        
        # Check for dangerous file extensions
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.php', '.asp', '.jsp']
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            raise ValueError("Dangerous file extension detected")
        
        return filename
    
    @classmethod
    def validate_email(cls, email: str) -> str:
        """Validate email address."""
        if not email or not isinstance(email, str):
            raise ValueError("Email must be a non-empty string")
        
        if len(email) > cls.MAX_LENGTHS['email']:
            raise ValueError(f"Email too long (max {cls.MAX_LENGTHS['email']} characters)")
        
        # Check for dangerous patterns
        cls._check_dangerous_patterns(email)
        
        # Basic email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")
        
        return email.lower()
    
    @classmethod
    def validate_port(cls, port: Union[int, str]) -> int:
        """Validate port number."""
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                raise ValueError("Port must be between 1 and 65535")
            return port_num
        except (ValueError, TypeError):
            raise ValueError("Invalid port number")
    
    @classmethod
    def validate_json(cls, data: str) -> Dict[str, Any]:
        """Validate and parse JSON data."""
        if not data or not isinstance(data, str):
            raise ValueError("JSON data must be a non-empty string")
        
        # Check for dangerous patterns
        cls._check_dangerous_patterns(data)
        
        try:
            parsed = json.loads(data)
            # Recursively validate the parsed data
            cls._validate_dict_recursive(parsed, max_depth=5)
            return parsed
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {str(e)}")
    
    @classmethod
    def _check_dangerous_patterns(cls, value: str) -> None:
        """Check for dangerous patterns in input."""
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, value):
                logger.warning(f"Dangerous pattern detected: {pattern[:50]}...")
                raise ValueError("Input contains potentially dangerous content")
    
    @classmethod
    def _validate_public_host(cls, hostname: str) -> None:
        """Validate that hostname is not a private/local address."""
        try:
            # Try to parse as IP address first
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise ValueError("Private/local IP addresses not allowed")
        except ValueError:
            # Not an IP address, check for local hostnames
            local_hostnames = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
            if hostname.lower() in local_hostnames:
                raise ValueError("Local hostnames not allowed")
    
    @classmethod
    def _validate_dict_recursive(cls, data: Dict[str, Any], max_depth: int = 5) -> None:
        """Recursively validate dictionary data."""
        if max_depth <= 0:
            raise ValueError("Maximum nesting depth exceeded")
        
        for key, value in data.items():
            # Validate key
            if not isinstance(key, str) or len(key) > 100:
                raise ValueError("Invalid dictionary key")
            
            cls._check_dangerous_patterns(key)
            
            # Validate value based on type
            if isinstance(value, str):
                cls.validate_string(value)
            elif isinstance(value, dict):
                cls._validate_dict_recursive(value, max_depth - 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, (str, dict)):
                        if isinstance(item, str):
                            cls.validate_string(item)
                        else:
                            cls._validate_dict_recursive(item, max_depth - 1)

# Global validator instance
security_validator = SecurityValidator()
