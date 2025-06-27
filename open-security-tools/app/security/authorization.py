"""
Authorization and Access Control System
Manages permissions for security testing operations.
"""

import logging
import hashlib
import time
import ipaddress
from typing import Dict, List, Optional, Set
from enum import Enum
from datetime import datetime, timedelta
import json
import os

logger = logging.getLogger(__name__)

class OperationType(Enum):
    """Types of security operations requiring authorization."""
    READ_ONLY = "read_only"
    PASSIVE_SCAN = "passive_scan"
    ACTIVE_SCAN = "active_scan"
    DESTRUCTIVE_TEST = "destructive_test"
    CREDENTIAL_TEST = "credential_test"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"

class RiskLevel(Enum):
    """Risk levels for operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AuthorizationManager:
    """Manages authorization for security testing operations."""
    
    def __init__(self):
        self.authorized_targets: Set[str] = set()
        self.user_permissions: Dict[str, List[OperationType]] = {}
        self.rate_limits: Dict[str, Dict[str, int]] = {}
        self.load_configuration()
    
    def load_configuration(self):
        """Load authorization configuration from secure files."""
        try:
            # Load authorized targets
            targets_file = os.getenv('AUTHORIZED_TARGETS_FILE', '/etc/security/authorized_targets.json')
            if os.path.exists(targets_file):
                with open(targets_file, 'r') as f:
                    targets_config = json.load(f)
                    self.authorized_targets.update(targets_config.get('targets', []))
                    logger.info(f"Loaded {len(self.authorized_targets)} authorized targets")
            
            # Load user permissions
            perms_file = os.getenv('USER_PERMISSIONS_FILE', '/etc/security/user_permissions.json')
            if os.path.exists(perms_file):
                with open(perms_file, 'r') as f:
                    perms_config = json.load(f)
                    for user_id, perms in perms_config.items():
                        self.user_permissions[user_id] = [OperationType(p) for p in perms]
                    logger.info(f"Loaded permissions for {len(self.user_permissions)} users")
        
        except Exception as e:
            logger.error(f"Failed to load authorization configuration: {e}")
    
    def is_target_authorized(self, target: str, operation: OperationType) -> bool:
        """Check if target is authorized for the given operation."""
        try:
            # Check explicit authorization
            if target in self.authorized_targets:
                return True
            
            # Check domain-based authorization
            if self._is_domain_authorized(target):
                return True
            
            # Check IP range authorization
            if self._is_ip_range_authorized(target):
                return True
            
            # Special case for read-only operations on public resources
            if operation == OperationType.READ_ONLY:
                return self._is_public_resource(target)
            
            return False
        
        except Exception as e:
            logger.error(f"Authorization check failed for {target}: {e}")
            return False
    
    def is_user_authorized(self, user_id: str, operation: OperationType) -> bool:
        """Check if user is authorized for the given operation type."""
        if not user_id:
            return False
        
        user_perms = self.user_permissions.get(user_id, [])
        return operation in user_perms
    
    def check_rate_limit(self, user_id: str, operation: OperationType) -> bool:
        """Check if user is within rate limits for the operation."""
        current_time = int(time.time())
        window_size = 3600  # 1 hour window
        
        # Define rate limits by operation type
        limits = {
            OperationType.READ_ONLY: 1000,
            OperationType.PASSIVE_SCAN: 100,
            OperationType.ACTIVE_SCAN: 10,
            OperationType.DESTRUCTIVE_TEST: 1,
            OperationType.CREDENTIAL_TEST: 5,
            OperationType.VULNERABILITY_EXPLOIT: 1
        }
        
        limit = limits.get(operation, 10)
        
        # Initialize user rate limit tracking
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = {}
        
        op_key = operation.value
        if op_key not in self.rate_limits[user_id]:
            self.rate_limits[user_id][op_key] = []
        
        # Clean old entries
        cutoff_time = current_time - window_size
        self.rate_limits[user_id][op_key] = [
            timestamp for timestamp in self.rate_limits[user_id][op_key]
            if timestamp > cutoff_time
        ]
        
        # Check limit
        if len(self.rate_limits[user_id][op_key]) >= limit:
            return False
        
        # Record current request
        self.rate_limits[user_id][op_key].append(current_time)
        return True
    
    def require_authorization(self, target: str, user_id: str, operation: OperationType, 
                            tool_name: str, additional_checks: Optional[Dict] = None):
        """Comprehensive authorization check with logging."""
        try:
            # Log the authorization attempt
            self._log_authorization_attempt(target, user_id, operation, tool_name)
            
            # Check user authorization
            if not self.is_user_authorized(user_id, operation):
                raise PermissionError(f"User {user_id} not authorized for {operation.value} operations")
            
            # Check target authorization
            if not self.is_target_authorized(target, operation):
                raise PermissionError(f"Target {target} not authorized for {operation.value} operations")
            
            # Check rate limiting
            if not self.check_rate_limit(user_id, operation):
                raise PermissionError(f"Rate limit exceeded for {operation.value} operations")
            
            # Additional security checks
            if additional_checks:
                self._perform_additional_checks(additional_checks, target, operation)
            
            # Log successful authorization
            logger.info(f"Authorization granted: user={user_id}, target={target}, operation={operation.value}, tool={tool_name}")
            
        except Exception as e:
            logger.error(f"Authorization denied: user={user_id}, target={target}, operation={operation.value}, reason={str(e)}")
            raise
    
    def get_operation_type(self, tool_name: str, parameters: Dict) -> OperationType:
        """Determine operation type based on tool and parameters."""
        # Map tools to operation types
        destructive_tools = [
            'sql_injection_scanner',
            'file_upload_scanner',
            'vulnerability_exploit'
        ]
        
        credential_tools = [
            'hash_cracker',
            'brute_force_scanner',
            'iot_security_scanner'
        ]
        
        active_scan_tools = [
            'network_port_scanner',
            'network_vulnerability_scanner',
            'web_security_scanner'
        ]
        
        if tool_name in destructive_tools:
            return OperationType.DESTRUCTIVE_TEST
        elif tool_name in credential_tools:
            return OperationType.CREDENTIAL_TEST
        elif tool_name in active_scan_tools:
            return OperationType.ACTIVE_SCAN
        else:
            return OperationType.PASSIVE_SCAN
    
    def _is_domain_authorized(self, target: str) -> bool:
        """Check if target domain is in authorized domain list."""
        try:
            # Extract domain from URL or use as-is
            if target.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                domain = urlparse(target).hostname
            else:
                domain = target
            
            # Check against authorized domains
            authorized_domains = [
                t for t in self.authorized_targets 
                if t.startswith('.') or not any(c in t for c in ['/', ':', '?'])
            ]
            
            for auth_domain in authorized_domains:
                if auth_domain.startswith('.'):
                    # Wildcard domain
                    if domain.endswith(auth_domain[1:]):
                        return True
                elif domain == auth_domain:
                    return True
            
            return False
        
        except Exception:
            return False
    
    def _is_ip_range_authorized(self, target: str) -> bool:
        """Check if target IP is in authorized IP ranges."""
        try:
            # Try to parse as IP
            target_ip = ipaddress.ip_address(target)
            
            # Check against authorized IP ranges
            for auth_target in self.authorized_targets:
                try:
                    if '/' in auth_target:
                        # CIDR range
                        network = ipaddress.ip_network(auth_target, strict=False)
                        if target_ip in network:
                            return True
                    else:
                        # Single IP
                        auth_ip = ipaddress.ip_address(auth_target)
                        if target_ip == auth_ip:
                            return True
                except ValueError:
                    continue
            
            return False
        
        except ValueError:
            # Not an IP address
            return False
    
    def _is_public_resource(self, target: str) -> bool:
        """Check if target is a public resource that can be safely read."""
        try:
            # Allow certain public APIs and services for read-only operations
            public_domains = [
                'api.github.com',
                'httpbin.org',
                'jsonplaceholder.typicode.com'
            ]
            
            if target.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                domain = urlparse(target).hostname
                return domain in public_domains
            
            return target in public_domains
        
        except Exception:
            return False
    
    def _perform_additional_checks(self, checks: Dict, target: str, operation: OperationType):
        """Perform additional security checks based on parameters."""
        # Check for obviously malicious payloads
        if 'payload' in checks:
            malicious_patterns = ['drop table', 'exec xp_cmdshell', 'rm -rf', 'format c:']
            payload = checks['payload'].lower()
            for pattern in malicious_patterns:
                if pattern in payload:
                    raise PermissionError(f"Malicious payload detected: {pattern}")
        
        # Check file upload sizes
        if 'file_size' in checks:
            max_size = 10 * 1024 * 1024  # 10MB
            if checks['file_size'] > max_size:
                raise PermissionError(f"File size too large: {checks['file_size']}")
        
        # Check request rate for the target
        if operation in [OperationType.ACTIVE_SCAN, OperationType.DESTRUCTIVE_TEST]:
            # Additional rate limiting for specific targets
            pass
    
    def _log_authorization_attempt(self, target: str, user_id: str, operation: OperationType, tool_name: str):
        """Log authorization attempt for security monitoring."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'target': target,
            'operation': operation.value,
            'tool': tool_name,
            'source_ip': 'unknown'  # Would be filled by middleware
        }
        
        # Use security logger
        security_logger = logging.getLogger('security.authorization')
        security_logger.info(f"Authorization attempt: {json.dumps(log_entry)}")

# Global authorization manager
authorization_manager = AuthorizationManager()
