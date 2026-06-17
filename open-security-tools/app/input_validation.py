"""Input validation middleware and utilities for enhanced security."""

import re
import json
from typing import Any, Dict, List, Union
from fastapi import Request, HTTPException, status
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

class InputSanitizer:
    """Utility class for input sanitization and validation."""
    
    # Dangerous patterns that should be blocked
    DANGEROUS_PATTERNS = [
        # SQL injection patterns
        r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into)",
        r"(?i)('|\"|;).*(-{2}|#|\/\*)",
        
        # XSS patterns
        r"(?i)<script[^>]*>.*?</script>",
        r"(?i)javascript:",
        r"(?i)on\w+\s*=",
        
        # Command injection patterns
        r"[;&|`$\(\){}]",
        r"(?i)(wget|curl|nc|netcat|bash|sh|cmd|powershell)",
        
        # Path traversal patterns
        r"\.\.[\\/]",
        r"(?i)etc[\\/]passwd",
        r"(?i)windows[\\/]system32",
        
        # File inclusion patterns
        r"(?i)(file|http|ftp|data)://",
        
        # XXE patterns
        r"(?i)<!entity",
        r"(?i)<!doctype.*entity",
    ]
    
    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 1000) -> str:
        """Sanitize a string input."""
        if not isinstance(value, str):
            raise ValueError("Input must be a string")
        
        # Length check
        if len(value) > max_length:
            raise ValueError(f"Input too long (max {max_length} characters)")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, value):
                logger.warning(f"Blocked dangerous pattern in input: {pattern}")
                raise ValueError("Input contains potentially dangerous content")
        
        # Basic HTML entity encoding for output safety
        value = value.replace("&", "&amp;")
        value = value.replace("<", "&lt;")
        value = value.replace(">", "&gt;")
        value = value.replace('"', "&quot;")
        value = value.replace("'", "&#x27;")
        
        return value.strip()
    
    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any], max_depth: int = 5) -> Dict[str, Any]:
        """Sanitize dictionary inputs recursively."""
        if max_depth <= 0:
            raise ValueError("Maximum nesting depth exceeded")
        
        sanitized = {}
        for key, value in data.items():
            # Sanitize the key
            if not isinstance(key, str):
                key = str(key)
            
            # Length limit for keys
            if len(key) > 100:
                raise ValueError("Key too long")
            
            sanitized_key = cls.sanitize_string(key, max_length=100)
            
            # Sanitize the value based on type
            if isinstance(value, str):
                sanitized[sanitized_key] = cls.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[sanitized_key] = cls.sanitize_dict(value, max_depth - 1)
            elif isinstance(value, list):
                sanitized[sanitized_key] = cls.sanitize_list(value, max_depth - 1)
            elif isinstance(value, (int, float, bool)) or value is None:
                sanitized[sanitized_key] = value
            else:
                # Convert unknown types to string and sanitize
                sanitized[sanitized_key] = cls.sanitize_string(str(value))
        
        return sanitized
    
    @classmethod
    def sanitize_list(cls, data: List[Any], max_depth: int = 5) -> List[Any]:
        """Sanitize list inputs recursively."""
        if max_depth <= 0:
            raise ValueError("Maximum nesting depth exceeded")
        
        # Limit list size
        if len(data) > 1000:
            raise ValueError("List too large (max 1000 items)")
        
        sanitized = []
        for item in data:
            if isinstance(item, str):
                sanitized.append(cls.sanitize_string(item))
            elif isinstance(item, dict):
                sanitized.append(cls.sanitize_dict(item, max_depth - 1))
            elif isinstance(item, list):
                sanitized.append(cls.sanitize_list(item, max_depth - 1))
            elif isinstance(item, (int, float, bool)) or item is None:
                sanitized.append(item)
            else:
                sanitized.append(cls.sanitize_string(str(item)))
        
        return sanitized

    @classmethod
    def validate_url(cls, url: str) -> str:
        """Validate and sanitize URL inputs. Blocks SSRF attempts."""
        if not isinstance(url, str):
            raise ValueError("URL must be a string")

        url = url.strip()

        # Length check
        if len(url) > 2048:
            raise ValueError("URL too long")

        # Only allow http/https schemes
        if not re.match(r'^https?://', url, re.IGNORECASE):
            raise ValueError("URL must start with http:// or https://")

        # Parse the URL to extract the hostname
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            raise ValueError("URL must contain a valid hostname")

        # Block known dangerous hostnames
        blocked_hostnames = {
            'localhost', 'metadata.google.internal',
            'metadata.internal', 'instance-data',
        }
        if hostname.lower() in blocked_hostnames:
            raise ValueError(f"URL hostname '{hostname}' is blocked (SSRF protection)")

        # Resolve hostname to IP and validate
        cls._validate_ip_not_private(hostname)

        return url

    # Tool-input fields that carry a URL the tool will connect to (SSRF surface).
    URL_REQUEST_FIELDS = ("target_url", "url")

    @classmethod
    def validate_request_urls(cls, input_obj) -> None:
        """SSRF guard for tool inputs.

        Validate any URL-bearing field on a validated tool-input object so a tool
        cannot be pointed at private/internal/cloud-metadata hosts. Only http(s)
        values are checked (non-URL fields are left untouched for the tool to
        handle). Raises ValueError if a target resolves to a blocked host.
        """
        for field in cls.URL_REQUEST_FIELDS:
            value = getattr(input_obj, field, None)
            if isinstance(value, str) and re.match(r'^https?://', value.strip(), re.IGNORECASE):
                cls.validate_url(value)

    @classmethod
    def validate_ip(cls, ip_str: str) -> str:
        """Validate an IP address. Blocks private/internal ranges."""
        if not isinstance(ip_str, str):
            raise ValueError("IP must be a string")

        ip_str = ip_str.strip()

        # Strip CIDR notation for validation (but allow it in output)
        ip_part = ip_str.split('/')[0]
        cls._validate_ip_not_private(ip_part)
        return ip_str

    @classmethod
    def _validate_ip_not_private(cls, host: str) -> None:
        """Check that a host (IP or hostname) does not resolve to a private IP."""
        import ipaddress
        import socket

        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            # It's a hostname, try to resolve it
            try:
                resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
                for family, _type, _proto, _canonname, sockaddr in resolved:
                    addr = ipaddress.ip_address(sockaddr[0])
                    if cls._is_blocked_ip(addr):
                        raise ValueError(
                            f"Hostname '{host}' resolves to blocked IP {addr} (SSRF protection)"
                        )
                return
            except socket.gaierror:
                # Cannot resolve — allow (external DNS may not be reachable at validation time)
                return

        if cls._is_blocked_ip(addr):
            raise ValueError(f"IP address {addr} is in a blocked range (SSRF protection)")

    @staticmethod
    def _is_blocked_ip(addr) -> bool:
        """Return True if the IP address is private, loopback, link-local, or cloud metadata."""
        import ipaddress
        # Cloud metadata endpoints
        CLOUD_METADATA_IPS = {
            ipaddress.ip_address('169.254.169.254'),  # AWS/GCP/Azure metadata
            ipaddress.ip_address('fd00::c2b6:a9ff:fe52:2ea5'),  # Azure IPv6 metadata
        }
        if addr in CLOUD_METADATA_IPS:
            return True
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )

    @classmethod
    def validate_filename(cls, filename: str) -> str:
        """Validate and sanitize filename inputs."""
        if not isinstance(filename, str):
            raise ValueError("Filename must be a string")
        
        filename = filename.strip()
        
        # Block path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            raise ValueError("Filename contains invalid characters")
        
        # Block dangerous extensions
        dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr',
            '.sh', '.bash', '.zsh', '.fish', '.ps1'
        ]
        
        for ext in dangerous_extensions:
            if filename.lower().endswith(ext):
                raise ValueError(f"Dangerous file extension: {ext}")
        
        # Length check
        if len(filename) > 255:
            raise ValueError("Filename too long")
        
        return filename


async def validate_request_input(request: Request, call_next):
    """Middleware to validate and sanitize request inputs."""
    try:
        # Get request body if it exists
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            
            if "application/json" in content_type:
                # Read and parse JSON body
                body = await request.body()
                if body:
                    try:
                        json_data = json.loads(body)
                        # Sanitize JSON data
                        if isinstance(json_data, dict):
                            sanitized_data = InputSanitizer.sanitize_dict(json_data)
                        elif isinstance(json_data, list):
                            sanitized_data = InputSanitizer.sanitize_list(json_data)
                        else:
                            sanitized_data = json_data
                        
                        # Store sanitized data for use in the endpoint
                        request.state.sanitized_json = sanitized_data
                        
                    except json.JSONDecodeError:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid JSON format"
                        )
                    except ValueError as e:
                        logger.warning(f"Input validation failed: {e}")
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Input validation failed: {str(e)}"
                        )
        
        # Continue processing
        response = await call_next(request)
        return response
        
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Input validation middleware error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during input validation"
        )
