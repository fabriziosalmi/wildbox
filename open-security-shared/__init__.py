"""
Wildbox Shared Utilities Package

Provides common functionality across all Wildbox microservices:
- Authentication and authorization
- Security middleware
- Configuration management
- Database utilities
"""

from .auth_utils import (
    verify_password,
    get_password_hash,
    create_access_token,
    verify_access_token,
    verify_api_key,
    get_api_key_from_header,
    get_bearer_token_from_header,
    AuthConfig,
)

__version__ = "1.0.0"
__all__ = [
    "verify_password",
    "get_password_hash",
    "create_access_token",
    "verify_access_token",
    "verify_api_key",
    "get_api_key_from_header",
    "get_bearer_token_from_header",
    "AuthConfig",
]
