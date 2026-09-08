"""
Exception handlers for the tools service.

The canonical error contract now lives in ``open_security_shared.errors`` so that
every Wildbox service answers with the same body (WILDBO-API-02). This module is
kept as a thin re-export: the shape it used to define -- ``{"error": {"code",
"message", "type", "request_id"}}`` -- is the shape the shared module adopted, so
nothing about the tools service's responses changes.

Prefer importing from the shared package directly in new code::

    from open_security_shared.errors import install_error_handlers
"""

from open_security_shared.errors import (  # noqa: F401  (re-exported)
    error_body,
    error_response,
    get_request_id,
    http_exception_handler,
    install_error_handlers,
    pydantic_validation_exception_handler,
    unhandled_exception_handler as general_exception_handler,
    validation_exception_handler,
)

# The Starlette and FastAPI HTTPException classes share a handler.
starlette_http_exception_handler = http_exception_handler

__all__ = [
    "http_exception_handler",
    "starlette_http_exception_handler",
    "validation_exception_handler",
    "pydantic_validation_exception_handler",
    "general_exception_handler",
    "install_error_handlers",
    "error_body",
    "error_response",
    "get_request_id",
]
