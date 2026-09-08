"""
Wildbox Shared Utilities Package

Provides common functionality across all Wildbox microservices:
- Authentication and authorization
- Security middleware
- Configuration management
- Database utilities
"""

from .auth_utils import (
    AuthConfig,
    create_access_token,
    get_api_key_from_header,
    get_bearer_token_from_header,
    get_password_hash,
    verify_access_token,
    verify_api_key,
    verify_password,
)
from .errors import (
    REQUEST_ID_HEADER,
    error_body,
    error_response,
    get_request_id,
    install_error_handlers,
)
from .observability import install_observability, metrics_response, outcome_counter
from .tenancy import scope_query, scope_select, team_filter

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
    "team_filter",
    "scope_query",
    "scope_select",
    "install_error_handlers",
    "error_body",
    "error_response",
    "get_request_id",
    "REQUEST_ID_HEADER",
    "install_observability",
    "metrics_response",
    "outcome_counter",
]
