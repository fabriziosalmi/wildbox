"""
API-key scopes, as the gateway forwards them (#637).

The gateway decides whether a credential may make a request: it maps the
request to the scope it requires and refuses an API key that lacks it
(``open-security-gateway/nginx/lua/auth_handler.lua``). It then tells the
service what it decided on, in two headers it sets itself and strips from
whatever the client sent:

``X-Wildbox-Auth-Type``
    ``session`` for a login session (a JWT), ``api_key`` for an API key. A
    Wildbox service that calls another one on a caller's behalf, with the
    gateway secret, says ``service``: the caller's credential was checked on
    the route that started the work.

``X-Wildbox-Scopes``
    The scopes of the API key, separated by single spaces, for example
    ``data:ingest`` or ``tools:read data:read``. A key that is not limited
    carries ``*``. The header is absent for a session and for a service,
    which are not limited by scopes, and for a key that holds no scope at
    all, which may do nothing that requires one.

This module is what a service uses to check a scope a second time, so that a
mistake in the gateway's map does not go unnoticed. It has no dependency: the
FastAPI services reach it through ``gateway_auth.require_scope``, guardian
(Django) imports it directly.

Everything here fails closed. A header that is malformed is an error, not an
empty list; an auth type that is missing or unknown satisfies no scope.

The hierarchy in ``scope_satisfied`` is the gateway's ``scopes_satisfy``,
line for line. The two are held together by
``open-security-gateway/test/scope_vectors.txt``, which the gateway's harness
and this package's tests both check.
"""

import re
from typing import Iterable, Optional, Tuple

AUTH_TYPE_HEADER = "X-Wildbox-Auth-Type"
SCOPES_HEADER = "X-Wildbox-Scopes"

AUTH_TYPE_SESSION = "session"
AUTH_TYPE_API_KEY = "api_key"
AUTH_TYPE_SERVICE = "service"
AUTH_TYPES = (AUTH_TYPE_SESSION, AUTH_TYPE_API_KEY, AUTH_TYPE_SERVICE)

# The types that are not limited by scopes when they carry no scopes header.
_UNSCOPED_TYPES = (AUTH_TYPE_SESSION, AUTH_TYPE_SERVICE)

UNRESTRICTED_SCOPE = "*"

# What the gateway forwards: "*", or a name with an optional ":action".
_SCOPE = re.compile(r"\*|[a-z][a-z0-9_-]*(?::[a-z][a-z0-9_-]*)?")
_MAX_SCOPES_HEADER_LENGTH = 2048
_MAX_SCOPES = 64


class GatewayCredentialError(ValueError):
    """The gateway's description of the credential cannot be read."""


def parse_auth_type(value: Optional[str]) -> Optional[str]:
    """The auth type the gateway stated, or None when it stated none.

    Raises:
        GatewayCredentialError: the header is present but is not one of
            AUTH_TYPES.
    """
    if value is None:
        return None
    if value not in AUTH_TYPES:
        raise GatewayCredentialError("unknown auth type")
    return value


def parse_scopes(value: Optional[str]) -> Optional[Tuple[str, ...]]:
    """The scopes the gateway forwarded, or None when it forwarded none.

    The header is a list of scopes separated by single spaces. Anything else
    -- an empty value, doubled or surrounding spaces, another separator, a
    character no scope has -- is refused rather than read leniently: a
    list that was misread is a set of permissions nobody granted.

    Raises:
        GatewayCredentialError: the header is present and malformed.
    """
    if value is None:
        return None
    if not value or len(value) > _MAX_SCOPES_HEADER_LENGTH:
        raise GatewayCredentialError("malformed scopes")
    scopes = value.split(" ")
    if len(scopes) > _MAX_SCOPES:
        raise GatewayCredentialError("malformed scopes")
    for scope in scopes:
        if not _SCOPE.fullmatch(scope):
            raise GatewayCredentialError("malformed scopes")
    return tuple(scopes)


def scope_satisfied(granted: Iterable[str], required: str) -> bool:
    """Whether the granted scopes satisfy the required one.

    The gateway's hierarchy (``scopes_satisfy`` in auth_handler.lua):
    ``admin`` and ``*`` satisfy everything; ``write`` satisfies ``read``;
    ``<resource>:admin`` satisfies every action on the resource; a generic
    scope satisfies the resource scopes of its level; ``<resource>:delete``
    is satisfied only by itself and the admin scopes.
    """
    held = set(granted)
    if required in held or "admin" in held or UNRESTRICTED_SCOPE in held:
        return True

    resource, separator, action = required.partition(":")
    if not separator:
        if required == "read":
            return "read" in held or "write" in held
        return False  # "write" and "admin" are satisfied above or not at all

    if f"{resource}:admin" in held:
        return True
    if action == "read":
        return bool(
            held
            & {
                f"{resource}:read",
                f"{resource}:write",
                f"{resource}:execute",
                "read",
                "write",
            }
        )
    if action in ("write", "execute"):
        return bool(held & {f"{resource}:write", f"{resource}:execute", "write"})
    if action == "ingest":
        return bool(held & {f"{resource}:ingest", f"{resource}:write", "write"})
    return False  # "delete" and anything else: explicit, or an admin scope


_READ_METHODS = ("GET", "HEAD", "OPTIONS")


def scope_for_method(
    method: str, read: str, write: str, delete: Optional[str] = None
) -> str:
    """The scope a request needs on a route the gateway maps by method.

    ``read`` for GET, HEAD and OPTIONS, ``delete`` for DELETE when the route
    names one, ``write`` for every other method: the gateway's rule
    (``required_scope_for_request`` in auth_handler.lua).
    """
    if method in _READ_METHODS:
        return read
    if method == "DELETE" and delete:
        return delete
    return write


def credential_allows(
    auth_type: Optional[str],
    scopes: Optional[Iterable[str]],
    required: str,
) -> bool:
    """Whether a credential the gateway described may do what needs ``required``.

    ``auth_type`` and ``scopes`` are the parsed headers (parse_auth_type,
    parse_scopes).

    - No auth type: nothing says what the credential is, so it satisfies
      nothing. A gateway from before these headers, or a caller that holds
      the gateway secret and does not say what it is, is refused wherever a
      scope is required.
    - Scopes present: they decide, whatever the type.
    - No scopes: a session or a service is not limited; an API key holds no
      scope.
    """
    if auth_type not in AUTH_TYPES:
        return False
    if scopes is not None:
        return scope_satisfied(scopes, required)
    return auth_type in _UNSCOPED_TYPES
