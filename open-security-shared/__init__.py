"""
Wildbox Shared Utilities Package

What the Wildbox services share: the gateway's identity headers and scopes
(``gateway_auth``, ``scopes``), tenancy filters, the error contract, request
metrics, the rule for serving API docs, and a circuit breaker.

Every name below is resolved lazily (PEP 562). Importing this package must not
drag in the dependencies of submodules the caller never touches: the package
has no dependency of its own, each group of modules has an extra
(``pyproject.toml``), and a service installs the package with the extras of the
modules it imports -- offline (``pip install --no-index``), so the shared
package cannot change a service's dependency tree, only fail the image build
when the service's own lock does not provide what those extras require.

Eager imports here broke that. This file once imported a module of JWT
helpers at module level, so merely importing ``open_security_shared.errors``
also imported ``jose``, which tools, identity, responder and agents did not
install. ``import app.main`` then died with ModuleNotFoundError: No module named
'jose' and the service could not start at all. (That module, ``auth_utils``,
was imported by no service and is gone, #665.)

With lazy resolution, ``from open_security_shared import install_error_handlers``
imports only ``errors``, and ``install_observability`` only ``observability``.
"""

from typing import TYPE_CHECKING

__version__ = "1.0.0"

# name -> submodule that defines it
_EXPORTS = {
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
