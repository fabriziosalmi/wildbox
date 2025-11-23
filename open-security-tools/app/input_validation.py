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
        """Validate and sanitize URL inputs."""
        if not isinstance(url, str):
            raise ValueError("URL must be a string")
        
        url = url.strip()
        
        # Basic URL validation
        if not re.match(r'^https?://', url, re.IGNORECASE):
            raise ValueError("URL must start with http:// or https://")
        
        # Block dangerous URLs
        dangerous_hosts = [
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            '169.254.', '10.', '172.16.', '192.168.'
        ]
        
        for host in dangerous_hosts:
            if host in url:
                raise ValueError("URL points to restricted network range")
        
        # Length check
        if len(url) > 2048:
            raise ValueError("URL too long")
        
        return url

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
