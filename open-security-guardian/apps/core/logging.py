"""
Core Logging Configuration - JSON formatter and utilities

The Guardian: Proactive Vulnerability Management
"""

import json
import logging
import traceback
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        """Format log record as JSON."""
        log_data = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, 'user') and record.user:
            log_data['user'] = str(record.user)
        
        if hasattr(record, 'ip_address') and record.ip_address:
            log_data['ip_address'] = record.ip_address
        
        if hasattr(record, 'method') and record.method:
            log_data['method'] = record.method
        
        if hasattr(record, 'path') and record.path:
            log_data['path'] = record.path
        
        if hasattr(record, 'status_code') and record.status_code:
            log_data['status_code'] = record.status_code
        
        if hasattr(record, 'duration_ms') and record.duration_ms:
            log_data['duration_ms'] = record.duration_ms
        
        if hasattr(record, 'user_agent') and record.user_agent:
            log_data['user_agent'] = record.user_agent
        
        # Add exception information if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        return json.dumps(log_data, default=str)


def get_logger(name):
    """Get a logger instance with proper configuration."""
    return logging.getLogger(f"guardian.{name}")


class SecurityLogger:
    """Security-focused logging utilities."""
    
    def __init__(self, name):
        self.logger = get_logger(name)
    
    def log_login_attempt(self, username, ip_address, success=True):
        """Log authentication attempt."""
        self.logger.info(
            f"Login {'successful' if success else 'failed'}: {username}",
            extra={
                'event_type': 'authentication',
                'username': username,
                'ip_address': ip_address,
                'success': success,
            }
        )
    
    def log_api_key_usage(self, api_key_name, endpoint, ip_address):
        """Log API key usage."""
        self.logger.info(
            f"API key used: {api_key_name} -> {endpoint}",
            extra={
                'event_type': 'api_access',
                'api_key_name': api_key_name,
                'endpoint': endpoint,
                'ip_address': ip_address,
            }
        )
    
    def log_security_event(self, event_type, description, **kwargs):
        """Log general security events."""
        self.logger.warning(
            f"Security event: {event_type} - {description}",
            extra={
                'event_type': 'security',
                'security_event_type': event_type,
                'description': description,
                **kwargs
            }
        )
    
    def log_vulnerability_scan(self, scanner_name, target, vulnerabilities_found):
        """Log vulnerability scan completion."""
        self.logger.info(
            f"Vulnerability scan completed: {scanner_name} -> {target}",
            extra={
                'event_type': 'vulnerability_scan',
                'scanner_name': scanner_name,
                'target': target,
                'vulnerabilities_found': vulnerabilities_found,
            }
        )
    
    def log_remediation_action(self, vulnerability_id, action, user):
        """Log remediation actions."""
        self.logger.info(
            f"Remediation action: {action} for vulnerability {vulnerability_id}",
            extra={
                'event_type': 'remediation',
                'vulnerability_id': vulnerability_id,
                'action': action,
                'user': str(user),
            }
        )
