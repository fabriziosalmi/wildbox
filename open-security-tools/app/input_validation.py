"""Input validation middleware and utilities for enhanced security."""

import re
import json
from typing import Any, Dict, List, Union
from fastapi import Request, HTTPException, status
from pydantic import AnyUrl, BaseModel
import pydantic_core
import logging

from .log_safety import error_site
from .url_guard import is_local_hostname, parse_target_url

logger = logging.getLogger(__name__)


def _pydantic_url_types() -> tuple:
    """The classes a validated pydantic URL field holds.

    ``AnyUrl`` is the base of ``HttpUrl``, ``AnyHttpUrl`` and the other
    single-host URL types. The multi-host types (``PostgresDsn`` and the
    like) share only a private base class, so it is looked up by name; the
    ``pydantic_core`` classes cover values built by the core directly.
    """
    import pydantic.networks

    types = [AnyUrl, pydantic_core.Url, pydantic_core.MultiHostUrl]
    for name in ("_BaseUrl", "_BaseMultiHostUrl"):
        base = getattr(pydantic.networks, name, None)
        if isinstance(base, type):
            types.append(base)
    return tuple(types)


_PYDANTIC_URL_TYPES = _pydantic_url_types()

class InputSanitizer:
    """Utility class for input sanitization and validation."""

    # Names of cloud metadata services, refused before any lookup.
    BLOCKED_HOSTNAMES = frozenset({
        'metadata.google.internal',
        'metadata.internal', 'instance-data',
    })
    
    # Dangerous patterns that should be blocked
    DANGEROUS_PATTERNS = [
        # SQL injection patterns
        r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into)",
        r"(?i)('|\"|;).*(-{2}|#|\/\*)",
        
        # XSS patterns
        r"(?i)<script[^>]*>.*?</script>",
        r"(?i)javascript:",
        r"(?i)on\w+\s*=",
        
        # Command injection patterns
        r"[;&|`$\(\){}]",
        r"(?i)(wget|curl|nc|netcat|bash|sh|cmd|powershell)",
        
        # Path traversal patterns
        r"\.\.[\\/]",
        r"(?i)etc[\\/]passwd",
        r"(?i)windows[\\/]system32",
        
        # File inclusion patterns
        r"(?i)(file|http|ftp|data)://",
        
        # XXE patterns
        r"(?i)<!entity",
        r"(?i)<!doctype.*entity",
    ]
    
    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 1000) -> str:
        """Sanitize a string input."""
        if not isinstance(value, str):
            raise ValueError("Input must be a string")
        
        # Length check
        if len(value) > max_length:
            raise ValueError(f"Input too long (max {max_length} characters)")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, value):
                logger.warning(f"Blocked dangerous pattern in input: {pattern}")
                raise ValueError("Input contains potentially dangerous content")
        
        # Basic HTML entity encoding for output safety
        value = value.replace("&", "&amp;")
        value = value.replace("<", "&lt;")
        value = value.replace(">", "&gt;")
        value = value.replace('"', "&quot;")
        value = value.replace("'", "&#x27;")
        
        return value.strip()
    
    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any], max_depth: int = 5) -> Dict[str, Any]:
        """Sanitize dictionary inputs recursively."""
        if max_depth <= 0:
            raise ValueError("Maximum nesting depth exceeded")
        
        sanitized = {}
        for key, value in data.items():
            # Sanitize the key
            if not isinstance(key, str):
                key = str(key)
            
            # Length limit for keys
            if len(key) > 100:
                raise ValueError("Key too long")
            
            sanitized_key = cls.sanitize_string(key, max_length=100)
            
            # Sanitize the value based on type
            if isinstance(value, str):
                sanitized[sanitized_key] = cls.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[sanitized_key] = cls.sanitize_dict(value, max_depth - 1)
            elif isinstance(value, list):
                sanitized[sanitized_key] = cls.sanitize_list(value, max_depth - 1)
            elif isinstance(value, (int, float, bool)) or value is None:
                sanitized[sanitized_key] = value
            else:
                # Convert unknown types to string and sanitize
                sanitized[sanitized_key] = cls.sanitize_string(str(value))
        
        return sanitized
    
    @classmethod
    def sanitize_list(cls, data: List[Any], max_depth: int = 5) -> List[Any]:
        """Sanitize list inputs recursively."""
        if max_depth <= 0:
            raise ValueError("Maximum nesting depth exceeded")
        
        # Limit list size
        if len(data) > 1000:
            raise ValueError("List too large (max 1000 items)")
        
        sanitized = []
        for item in data:
            if isinstance(item, str):
                sanitized.append(cls.sanitize_string(item))
            elif isinstance(item, dict):
                sanitized.append(cls.sanitize_dict(item, max_depth - 1))
            elif isinstance(item, list):
                sanitized.append(cls.sanitize_list(item, max_depth - 1))
            elif isinstance(item, (int, float, bool)) or item is None:
                sanitized.append(item)
            else:
                sanitized.append(cls.sanitize_string(str(item)))
        
        return sanitized

    @classmethod
    def validate_url(cls, url: str) -> str:
        """Validate a URL that a tool will connect to. Blocks SSRF attempts.

        Leading and trailing whitespace is stripped and the stripped URL is
        returned. The structure is checked by ``parse_target_url``, the same
        parser ``SecurityValidator.validate_url`` uses (scheme, no user info,
        port range, no control characters or whitespace, canonical host
        spelling), and the host is then resolved: every address it resolves
        to must be public.
        """
        if not isinstance(url, str):
            raise ValueError("URL must be a string")

        url = url.strip()
        target = parse_target_url(url)

        if is_local_hostname(target.host) or target.host in cls.BLOCKED_HOSTNAMES:
            raise ValueError(f"URL hostname '{target.host}' is blocked (SSRF protection)")

        # Resolve hostname to IP and validate
        cls._validate_ip_not_private(target.host)

        return url

    # Fallback list of field names that carry a URL a tool will connect to.
    #
    # This is no longer the primary mechanism. Fields declared as ``UrlField``
    # (see below) are validated by the schema itself, so the guard travels with
    # the declaration and a newly added field is protected by construction. This
    # list remains as a safety net for fields still typed as plain ``str``: it is
    # matched by name, which is exactly why it failed to cover
    # api_security_tester's ``api_base_url`` and ``api_specification``
    # (WILDBO-INPT-01).
    #
    # Anything whose name ends in _url, or which is one of these, is checked.
    URL_REQUEST_FIELDS = (
        "target_url", "url", "file_url", "app_url", "download_url",
        "api_base_url", "api_specification", "base_url", "endpoint", "webhook_url",
        "callback_url", "feed_url", "proxy",
    )

    # How deep the guard follows nested models, lists and dicts. Tool inputs
    # are a few levels deep at most; anything deeper is refused rather than
    # left unchecked.
    URL_WALK_MAX_DEPTH = 16

    @classmethod
    def is_url_field_name(cls, name: object) -> bool:
        """True if a field (or dict key) of this name carries a URL to fetch."""
        if not isinstance(name, str):
            return False
        name = name.lower()
        return (
            name in cls.URL_REQUEST_FIELDS
            or name in ("urls", "uri", "uris")
            or name.endswith(("_url", "_uri", "_urls", "_uris"))
        )

    @classmethod
    def validate_request_urls(cls, input_obj) -> None:
        """SSRF guard for tool inputs.

        Walk a validated tool-input object and check every URL a tool may
        connect to, so it cannot be pointed at private, internal or
        cloud-metadata hosts. Raises ValueError for the first refused URL.

        The walk follows nested models, lists, tuples, sets and dict values
        to any depth up to ``URL_WALK_MAX_DEPTH``. What is checked:

        * every value of a pydantic URL type (``HttpUrl``, ``AnyUrl``,
          ``AnyHttpUrl`` and the other ``Url`` types), wherever it sits and
          whatever the field is called. The declared type says the value is
          a URL, so it is checked in full: its string form goes through
          :meth:`validate_url`, which also refuses a scheme other than
          http(s). These used to be skipped because they are not ``str``
          (#610);
        * every ``str`` that starts with ``http://`` or ``https://`` and sits
          under a field or dict key named like a URL carrier (see
          :meth:`is_url_field_name`), including the items of a list held by
          such a field. Other strings are left to the tool: a free-text field
          or an indicator sent to a third-party API may legitimately contain
          a URL that nobody fetches.
        """
        cls._walk_request_urls(input_obj, url_named=False, depth=0, seen=set())

    @classmethod
    def _walk_request_urls(cls, value, *, url_named: bool, depth: int, seen: set) -> None:
        if depth > cls.URL_WALK_MAX_DEPTH:
            raise ValueError("Tool input is nested too deeply to validate")

        if isinstance(value, _PYDANTIC_URL_TYPES):
            cls.validate_url(str(value))
            return

        if isinstance(value, str):
            if url_named and re.match(r'^https?://', value.strip(), re.IGNORECASE):
                cls.validate_url(value)
            return

        if value is None or isinstance(value, (bool, int, float, bytes)):
            return

        # Containers: guard against reference cycles in dicts and lists.
        marker = id(value)
        if marker in seen:
            return
        seen.add(marker)

        if isinstance(value, BaseModel):
            fields = dict(value)  # declared fields, then extra ones
            for name, item in fields.items():
                cls._walk_request_urls(
                    item, url_named=cls.is_url_field_name(name), depth=depth + 1, seen=seen
                )
        elif isinstance(value, dict):
            for key, item in value.items():
                cls._walk_request_urls(
                    item, url_named=cls.is_url_field_name(key), depth=depth + 1, seen=seen
                )
        elif isinstance(value, (list, tuple, set, frozenset)):
            # The items of a list carry the name of the field that holds it.
            for item in value:
                cls._walk_request_urls(item, url_named=url_named, depth=depth + 1, seen=seen)

    @classmethod
    def validate_ip(cls, ip_str: str) -> str:
        """Validate an IP address. Blocks private/internal ranges."""
        if not isinstance(ip_str, str):
            raise ValueError("IP must be a string")

        ip_str = ip_str.strip()

        # Strip CIDR notation for validation (but allow it in output)
        ip_part = ip_str.split('/')[0]
        cls._validate_ip_not_private(ip_part)
        return ip_str

    @classmethod
    def _validate_ip_not_private(cls, host: str) -> None:
        """Check that a host (IP or hostname) does not resolve to a private IP."""
        import ipaddress
        import socket

        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            # It's a hostname, try to resolve it
            try:
                resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
                for family, _type, _proto, _canonname, sockaddr in resolved:
                    addr = ipaddress.ip_address(sockaddr[0])
                    if cls._is_blocked_ip(addr):
                        raise ValueError(
                            f"Hostname '{host}' resolves to blocked IP {addr} (SSRF protection)"
                        )
                return
            except socket.gaierror as exc:
                # Fail CLOSED. This used to return (allow) on the reasoning that
                # external DNS may be unreachable at validation time -- but a host
                # that cannot be resolved cannot be scanned either, so allowing it
                # buys nothing and hands an attacker who controls a nameserver a
                # trivial bypass: answer SERVFAIL for the validation lookup and
                # 127.0.0.1 for the request moments later (WILDBO-INPT-02).
                raise ValueError(
                    f"Hostname '{host}' could not be resolved; refusing to connect "
                    "(SSRF protection)"
                ) from exc

        if cls._is_blocked_ip(addr):
            raise ValueError(f"IP address {addr} is in a blocked range (SSRF protection)")

    @staticmethod
    def _is_blocked_ip(addr) -> bool:
        """Return True if the IP address is private, loopback, link-local, or cloud metadata."""
        import ipaddress
        # Cloud metadata endpoints
        CLOUD_METADATA_IPS = {
            ipaddress.ip_address('169.254.169.254'),  # AWS/GCP/Azure metadata
            ipaddress.ip_address('fd00::c2b6:a9ff:fe52:2ea5'),  # Azure IPv6 metadata
        }
        if addr in CLOUD_METADATA_IPS:
            return True
        # not is_global also covers ranges the flags below miss, such as
        # shared address space (100.64.0.0/10), matching the host check in
        # SecurityValidator._validate_public_host.
        return (
            not addr.is_global
            or addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )

    @classmethod
    def validate_filename(cls, filename: str) -> str:
        """Validate and sanitize filename inputs."""
        if not isinstance(filename, str):
            raise ValueError("Filename must be a string")
        
        filename = filename.strip()
        
        # Block path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            raise ValueError("Filename contains invalid characters")
        
        # Block dangerous extensions
        dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr',
            '.sh', '.bash', '.zsh', '.fish', '.ps1'
        ]
        
        for ext in dangerous_extensions:
            if filename.lower().endswith(ext):
                raise ValueError(f"Dangerous file extension: {ext}")
        
        # Length check
        if len(filename) > 255:
            raise ValueError("Filename too long")
        
        return filename


async def validate_request_input(request: Request, call_next):
    """Middleware to validate and sanitize request inputs."""
    try:
        # Get request body if it exists
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            
            if "application/json" in content_type:
                # Read and parse JSON body
                body = await request.body()
                if body:
                    try:
                        json_data = json.loads(body)
                        # Sanitize JSON data
                        if isinstance(json_data, dict):
                            sanitized_data = InputSanitizer.sanitize_dict(json_data)
                        elif isinstance(json_data, list):
                            sanitized_data = InputSanitizer.sanitize_list(json_data)
                        else:
                            sanitized_data = json_data
                        
                        # Store sanitized data for use in the endpoint
                        request.state.sanitized_json = sanitized_data
                        
                    except json.JSONDecodeError:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid JSON format"
                        )
                    except ValueError as e:
                        logger.warning(f"Input validation failed: {error_site(e)}")
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Input validation failed: {str(e)}"
                        )
        
        # Continue processing
        response = await call_next(request)
        return response
        
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Input validation middleware error: {error_site(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during input validation"
        )


# ---------------------------------------------------------------------------
# Schema-carried SSRF validation
# ---------------------------------------------------------------------------
#
# The name-based sweep above is a safety net. The primary mechanism is this
# annotated type: declare a URL-bearing field as ``UrlField`` and the guard is
# part of the schema, so it cannot be forgotten when a new tool or a new field
# is added (WILDBO-INPT-01)::
#
#     from app.input_validation import UrlField
#
#     class MyToolInput(BaseToolInput):
#         api_base_url: UrlField = Field(..., description="Base URL of the API")
#
# Validation runs at request-parsing time, before the tool function is entered,
# and rejects private, loopback, link-local and cloud-metadata targets.

from typing import Annotated  # noqa: E402

from pydantic import AfterValidator  # noqa: E402


def _validate_public_url(value: str) -> str:
    """Pydantic validator: the value must be an http(s) URL to a public host."""
    if value is None:
        return value
    return InputSanitizer.validate_url(value)


UrlField = Annotated[str, AfterValidator(_validate_public_url)]
