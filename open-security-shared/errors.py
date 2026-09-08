"""
Canonical error contract for every Wildbox HTTP service.

One shape, served by all services, so a caller can extract the message with a
single expression regardless of which service answered:

    {"error": {"code": 404, "message": "...", "type": "HTTPException",
               "request_id": "..."}}

This is the shape the tools service already used; it is the only one of the four
that previously existed which carries ``request_id``, the field an operator needs
to correlate a user-visible failure with a log line.

Install it once per service::

    from open_security_shared.errors import install_error_handlers
    install_error_handlers(app)

``install_error_handlers`` registers handlers for HTTPException (both the FastAPI
and the Starlette class), RequestValidationError, pydantic ValidationError and
the unhandled-exception catch-all, so no route can answer with a different shape.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

# Header carrying the correlation id across services. The gateway generates it;
# services read it and fall back to a locally generated one.
REQUEST_ID_HEADER = "X-Request-ID"


def get_request_id(request: Optional[Request]) -> str:
    """Return the correlation id for this request, or 'unknown'."""
    if request is None:
        return "unknown"
    rid = getattr(request.state, "request_id", None)
    if rid:
        return str(rid)
    try:
        return request.headers.get(REQUEST_ID_HEADER) or "unknown"
    except Exception:  # pragma: no cover - defensive, request may be malformed
        return "unknown"


def error_body(
    code: int,
    message: str,
    error_type: str = "HTTPException",
    request_id: str = "unknown",
    details: Optional[Any] = None,
) -> Dict[str, Any]:
    """Build the canonical error body."""
    body: Dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "type": error_type,
            "request_id": request_id,
        }
    }
    if details is not None:
        body["error"]["details"] = details
    return body


def error_response(
    code: int,
    message: str,
    error_type: str = "HTTPException",
    request_id: str = "unknown",
    details: Optional[Any] = None,
    headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=code,
        content=error_body(code, message, error_type, request_id, details),
        headers=headers,
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    request_id = get_request_id(request)
    logger.warning(
        "HTTP exception: %s",
        exc.status_code,
        extra={
            "request_id": request_id,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "path": str(request.url.path),
        },
    )
    return error_response(
        code=exc.status_code,
        message=str(exc.detail),
        error_type="HTTPException",
        request_id=request_id,
        headers=getattr(exc, "headers", None),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    request_id = get_request_id(request)
    logger.warning(
        "Validation error",
        extra={"request_id": request_id, "path": str(request.url.path)},
    )
    return error_response(
        code=422,
        message="Request validation failed",
        error_type="ValidationError",
        request_id=request_id,
        details=exc.errors(),
    )


async def pydantic_validation_exception_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    request_id = get_request_id(request)
    return error_response(
        code=422,
        message="Data validation failed",
        error_type="ValidationError",
        request_id=request_id,
        details=exc.errors(),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last resort. The message is deliberately generic; the detail is in the log."""
    request_id = get_request_id(request)
    logger.error(
        "Unhandled exception: %s",
        exc,
        exc_info=True,
        extra={"request_id": request_id, "path": str(request.url.path)},
    )
    return error_response(
        code=500,
        message="An internal error occurred",
        error_type="InternalServerError",
        request_id=request_id,
    )


def install_error_handlers(app: FastAPI) -> None:
    """Register the canonical error handlers on a FastAPI application."""
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValidationError, pydantic_validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
