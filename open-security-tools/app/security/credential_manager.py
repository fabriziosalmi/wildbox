"""
Secure Credential Management System
Handles API keys, secrets, and sensitive configuration data securely.
"""

import os
import json
import logging
from typing import Dict, Optional, Any
from pathlib import Path
from cryptography.fernet import Fernet
import keyring

logger = logging.getLogger(__name__)

class SecureCredentialManager:
    """Secure credential management with encryption and key rotation support."""
    
    def __init__(self):
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self._validate_required_env_vars()
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get encryption key from secure storage or create new one."""
        try:
            # Try to get from keyring first
            key = keyring.get_password("wildbox-security-api", "encryption_key")
            if key:
                return key.encode()
            
            # Create new key if none exists
            new_key = Fernet.generate_key()
            keyring.set_password("wildbox-security-api", "encryption_key", new_key.decode())
            return new_key
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.warning(f"Keyring unavailable, using environment variable: {e}")
            # Fallback to environment variable
            env_key = os.getenv('ENCRYPTION_KEY')
            if not env_key:
                raise ValueError("No encryption key found. Set ENCRYPTION_KEY environment variable.")
            return env_key.encode()
    
    def _validate_required_env_vars(self):
        """Validate that required environment variables are set."""
        required_vars = [
            'JWT_SECRET_KEY',
            'DATABASE_URL',
            'REDIS_URL'
        ]
        
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {missing_vars}")
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for external service."""
        env_var_map = {
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'shodan': 'SHODAN_API_KEY',
            'censys': 'CENSYS_API_KEY',
            'hibp': 'HIBP_API_KEY',
            'urlvoid': 'URLVOID_API_KEY',
            'abuseipdb': 'ABUSEIPDB_API_KEY',
            'otx': 'OTX_API_KEY'
        }
        
        env_var = env_var_map.get(service.lower())
        if not env_var:
            logger.warning(f"Unknown service: {service}")
            return None
        
        api_key = os.getenv(env_var)
        if not api_key:
            logger.warning(f"API key not configured for service: {service}")
            return None
        
        return api_key
    
    def get_database_credentials(self) -> Dict[str, str]:
        """Get database connection credentials."""
        return {
            'url': os.getenv('DATABASE_URL', ''),
            'username': os.getenv('DB_USERNAME', ''),
            'password': os.getenv('DB_PASSWORD', ''),
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': os.getenv('DB_PORT', '5432'),
            'database': os.getenv('DB_NAME', 'security_api')
        }
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data for storage."""
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
    
    def validate_api_key_format(self, service: str, api_key: str) -> bool:
        """Validate API key format for known services."""
        validators = {
            'virustotal': lambda k: len(k) == 64 and k.isalnum(),
            'shodan': lambda k: len(k) == 32 and k.isalnum(),
            'censys': lambda k: len(k) >= 32,
            'hibp': lambda k: len(k) >= 16
        }
        
        validator = validators.get(service.lower())
        if validator:
            return validator(api_key)
        return True  # Unknown service, assume valid
    
    def mask_sensitive_value(self, value: str) -> str:
        """Mask sensitive values for logging."""
        if not value or len(value) < 8:
            return "****"
        return f"{value[:4]}****{value[-4:]}"

# Global instance
credential_manager = SecureCredentialManager()
