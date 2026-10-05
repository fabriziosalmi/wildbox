"""
Canonical error contract for every Wildbox HTTP service.

One shape, served by all services, so a caller can extract the message with a
single expression regardless of which service answered:

    {"error": {"code": 404, "message": "...", "type": "HTTPException",
               "request_id": "..."}}

This is the shape the tools service already used; it is the only one of the four
that previously existed which carries ``request_id``, the field an operator needs
to correlate a user-visible failure with a log line.

The fields:

``code``
    The HTTP status, as an integer.
``message``
    Always a non-empty string a person can read. Never the ``str()`` of a dict
    or a list.
``type``
    ``HTTPException``, ``ValidationError`` or ``InternalServerError``.
``request_id``
    The correlation id of the request.
``details``
    Present only when the error carries structured data, and then that data as
    JSON: the list of field errors of a validation error, or the ``detail`` an
    endpoint raised when it is a dict or a list.

What ``HTTPException(detail=...)`` becomes:

- a string: ``message`` is the string, and there is no ``details``;
- a dict: ``message`` is its ``reason``, else its ``message``, else its
  ``error`` (the first of the three that is a non-empty string), else the
  status phrase; ``details`` is the dict;
- a list, a tuple or a set: ``message`` is the status phrase and ``details``
  is the list of its items;
- an Enum member: its value, by these same rules;
- an empty string: ``message`` is the status phrase;
- anything else (a number, for instance): ``message`` is its ``str()``.

The status phrase is the standard one for the status ("Forbidden" for 403). A
machine-readable code that an endpoint puts in its dict, as the gateway
authentication dependency does (``{"error": ..., "message": ..., "code":
"GATEWAY_AUTH_REQUIRED"}``), is therefore at ``error.details.code``;
``error.code`` is always the HTTP status.

Install it once per service::

    from open_security_shared.errors import install_error_handlers
    install_error_handlers(app)

``install_error_handlers`` registers handlers for HTTPException (both the FastAPI
and the Starlette class), RequestValidationError, pydantic ValidationError and
the unhandled-exception catch-all, so no route can answer with a different shape.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from http import HTTPStatus
from typing import Any, Dict, Mapping, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
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


# The keys of a dict detail that hold its explanation, in order of preference.
# fastapi-users answers {"code": ..., "reason": ...}; the gateway
# authentication dependency {"error": <title>, "message": <explanation>,
# "code": ...}.
_MESSAGE_KEYS = ("reason", "message", "error")


def _status_phrase(status_code: int) -> str:
    """The standard phrase for a status: what Starlette uses for no detail."""
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "Request failed"


def _as_json(value: Any) -> Optional[Any]:
    """`value` as data a JSON response can carry, or None if it cannot be.

    A handler that raised here would turn the endpoint's own status into a 500,
    so a detail that cannot be encoded loses its details, not its status.
    """
    try:
        encoded = jsonable_encoder(value)
        json.dumps(encoded, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        logger.warning("Error detail is not JSON-serializable; details omitted")
        return None
    return encoded


def message_and_details(detail: Any, status_code: int) -> Tuple[str, Optional[Any]]:
    """What an HTTPException's `detail` becomes in the canonical body.

    Returns `(message, details)`. See the module docstring for the rules. The
    message used to be `str(detail)` except for a dict with a `reason`, so any
    other dict reached the client as a Python dict literal, and its fields,
    the machine-readable code among them, could not be read (#655).
    """
    # fastapi-users raises its codes as a str Enum (ErrorCode), whose str()
    # is the member name, "ErrorCode.REGISTER_USER_ALREADY_EXISTS", not the
    # code (#589).
    if isinstance(detail, Enum):
        detail = detail.value
    if isinstance(detail, Mapping):
        for key in _MESSAGE_KEYS:
            candidate = detail.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate, _as_json(detail)
        return _status_phrase(status_code), _as_json(detail)
    if isinstance(detail, (list, tuple, set, frozenset)):
        return _status_phrase(status_code), _as_json(list(detail))
    message = "" if detail is None else str(detail)
    return (message if message.strip() else _status_phrase(status_code)), None


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
    message, details = message_and_details(exc.detail, exc.status_code)
    return error_response(
        code=exc.status_code,
        message=message,
        error_type="HTTPException",
        request_id=request_id,
        details=details,
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
