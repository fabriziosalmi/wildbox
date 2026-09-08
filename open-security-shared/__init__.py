"""
Wildbox Shared Utilities Package

Provides common functionality across all Wildbox microservices:
- Authentication and authorization
- Security middleware
- Configuration management
- Database utilities

Every name below is resolved lazily (PEP 562). Importing this package must not
drag in the dependencies of submodules the caller never touches: services
install it with ``pip install --no-deps`` -- deliberately, so the shared package
cannot silently change a service's dependency tree -- and each service pins only
what it actually uses.

Eager imports here broke that. ``from .auth_utils import ...`` at module level
meant that merely importing ``open_security_shared.errors`` also imported
auth_utils, hence ``jose``, which tools, identity, responder and agents do not
install. ``import app.main`` then died with ModuleNotFoundError: No module named
'jose' and the service could not start at all.

With lazy resolution, ``from open_security_shared import install_error_handlers``
imports only ``errors``; a service that wants ``verify_password`` gets
``auth_utils`` and is expected to pin python-jose itself.
"""

from typing import TYPE_CHECKING

__version__ = "1.0.0"

# name -> submodule that defines it
_EXPORTS = {
    "AuthConfig": "auth_utils",
    "create_access_token": "auth_utils",
    "get_api_key_from_header": "auth_utils",
    "get_bearer_token_from_header": "auth_utils",
    "get_password_hash": "auth_utils",
    "verify_access_token": "auth_utils",
    "verify_api_key": "auth_utils",
    "verify_password": "auth_utils",
    "REQUEST_ID_HEADER": "errors",
    "error_body": "errors",
    "error_response": "errors",
    "get_request_id": "errors",
    "install_error_handlers": "errors",
    "install_observability": "observability",
    "metrics_response": "observability",
    "outcome_counter": "observability",
    "scope_query": "tenancy",
    "scope_select": "tenancy",
    "team_filter": "tenancy",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str):
    """Import the defining submodule on first access (PEP 562)."""
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(f".{module_name}", __name__)
    value = getattr(module, name)
    globals()[name] = value  # cache, so this runs once per name
    return value


def __dir__():
    return sorted(set(globals()) | set(_EXPORTS))


if TYPE_CHECKING:  # pragma: no cover - for type checkers and IDEs only
    # noqa: F401 -- re-exported lazily at runtime via __getattr__ above.
    from .auth_utils import (  # noqa: F401
        AuthConfig,
        create_access_token,
        get_api_key_from_header,
        get_bearer_token_from_header,
        get_password_hash,
        verify_access_token,
        verify_api_key,
        verify_password,
    )
    from .errors import (  # noqa: F401
        REQUEST_ID_HEADER,
        error_body,
        error_response,
        get_request_id,
        install_error_handlers,
    )
    from .observability import (  # noqa: F401
        install_observability,
        metrics_response,
        outcome_counter,
    )
    from .tenancy import scope_query, scope_select, team_filter  # noqa: F401
