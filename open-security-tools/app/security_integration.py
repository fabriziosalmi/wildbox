"""
Security Integration Layer - Backward Compatible
Gradually integrates security controls without breaking existing functionality.
"""

import logging
import os
from typing import Any, Dict, Optional, Callable
from functools import wraps
import asyncio

logger = logging.getLogger(__name__)

class SecurityIntegration:
    """Backward-compatible security integration for existing tools."""
    
    def __init__(self):
        self.security_enabled = os.getenv('SECURITY_CONTROLS_ENABLED', 'false').lower() == 'true'
        self.strict_mode = os.getenv('SECURITY_STRICT_MODE', 'false').lower() == 'true'
        self.credential_manager = None
        self.authorization_manager = None
        self.validator = None
        
        if self.security_enabled:
            self._initialize_security_components()
    
    def _initialize_security_components(self):
        """Initialize security components only if enabled."""
        try:
            from app.security.credential_manager import credential_manager
            from app.security.authorization import authorization_manager
            from app.security.validator import security_validator
            
            self.credential_manager = credential_manager
            self.authorization_manager = authorization_manager
            self.validator = security_validator
            logger.info("Security components initialized successfully")
        except ImportError as e:
            logger.warning(f"Security components not available: {e}")
            if self.strict_mode:
                raise
            # Fall back to no security controls
            self.security_enabled = False
    
    def secure_tool_execution(self, tool_name: str):
        """Decorator to add security controls to tool execution."""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                try:
                    # Extract common parameters
                    input_data = args[0] if args else None
                    user_id = kwargs.get('user_id')
                    
                    # Apply security controls if enabled
                    if self.security_enabled and input_data:
                        await self._apply_security_controls(tool_name, input_data, user_id)
                    
                    # Execute original function
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)
                    
                    return result
                    
                except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                    if self.strict_mode:
                        raise
                    logger.warning(f"Security check failed for {tool_name}, continuing without security: {e}")
                    # Execute without security controls in non-strict mode
                    if asyncio.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        return func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    async def _apply_security_controls(self, tool_name: str, input_data: Any, user_id: Optional[str]):
        """Apply security controls to tool execution."""
        if not self.security_enabled:
            return
        
        try:
            # Input validation
            if self.validator and hasattr(input_data, 'target_url'):
                target_url = getattr(input_data, 'target_url', None)
                if target_url:
                    self.validator.validate_url(target_url, allow_private=True)
            
            # Authorization check (only if user_id provided)
            if self.authorization_manager and user_id:
                from app.security.authorization import OperationType
                operation_type = self.authorization_manager.get_operation_type(tool_name, {})
                
                target = getattr(input_data, 'target_url', 'unknown')
                self.authorization_manager.require_authorization(
                    target=target,
                    user_id=user_id,
                    operation=operation_type,
                    tool_name=tool_name
                )
        
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Security control failed for {tool_name}: {e}")
            if self.strict_mode:
                raise
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key through secure credential manager or fallback."""
        if self.security_enabled and self.credential_manager:
            try:
                return self.credential_manager.get_api_key(service)
            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                logger.warning(f"Secure credential retrieval failed for {service}: {e}")
        
        # Fallback to environment variables
        env_var_map = {
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'shodan': 'SHODAN_API_KEY',
            'censys': 'CENSYS_API_KEY',
            'hibp': 'HIBP_API_KEY',
            'urlvoid': 'URLVOID_API_KEY',
            'abuseipdb': 'ABUSEIPDB_API_KEY'
        }
        
        env_var = env_var_map.get(service.lower())
        if env_var:
            return os.getenv(env_var)
        
        return None
    
    def validate_input(self, input_data: Any, field_name: str = "input") -> Any:
        """Validate input with fallback to basic validation."""
        if not self.security_enabled or not self.validator:
            return input_data
        
        try:
            if isinstance(input_data, str):
                return self.validator.validate_string(input_data, field_name=field_name)
            return input_data
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.warning(f"Input validation failed for {field_name}: {e}")
            if self.strict_mode:
                raise
            return input_data

# Global security integration instance
security_integration = SecurityIntegration()
