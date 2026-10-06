"""The URL guard: which URLs a tool may be pointed at (SSRF protection).

This module also held ``validate_request_input``, a middleware that ran
every JSON body through ``InputSanitizer.sanitize_dict`` and answered 400
with the text of the error. The application never installed it (it is not
among the middlewares ``app.main.create_app`` adds), and nothing else called
it, the three ``sanitize_*`` methods or their list of patterns: they are
gone (#774). Had it been installed it would have refused every request that
carries a URL, which its patterns match.
"""

import re
from typing import Optional
from pydantic import AnyUrl, BaseModel
import pydantic_core

from open_security_shared.target_policy import METADATA_HOSTNAMES, is_blocked_address

from .url_guard import is_local_hostname, parse_target_url

# The refusals of the URL guard. None repeats the URL, its host or the
# address the host resolves to: the answer goes back to the caller with the
# field the URL was in, and the texts are also what a tool reports when it
# checks a URL itself (#774). They are the sentences they were, less the
# value each one quoted.
LOCAL_HOST = "URL hostname is blocked (SSRF protection)"
RESOLVES_INSIDE = "Hostname resolves to a blocked IP address (SSRF protection)"
DOES_NOT_RESOLVE = (
    "Hostname could not be resolved; refusing to connect (SSRF protection)"
)
BLOCKED_ADDRESS = "IP address is in a blocked range (SSRF protection)"
URL_WALK_TOO_DEEP = "Tool input is nested too deeply to validate"


class UrlRefused(ValueError):
    """A URL in a tool input is refused.

    ``reason`` is the text of the refusal. ``field`` is the field of the
    input the URL was found under: the top-level one, also for a URL nested
    in a model, a list or a dictionary below it.
    """

    def __init__(self, reason: str, field: Optional[str] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field


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

    # Names of cloud metadata services, refused before any lookup. The list
    # is the shared target policy's, which guardian's scans use too (#748).
    BLOCKED_HOSTNAMES = METADATA_HOSTNAMES
    
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
            raise ValueError(LOCAL_HOST)

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
        cls._walk_request_urls(
            input_obj, url_named=False, depth=0, seen=set(), field=None
        )

    @classmethod
    def _refuse_url(cls, url: str, field: Optional[str]) -> None:
        """validate_url, with the field the URL is under in what it raises."""
        try:
            cls.validate_url(url)
        except UrlRefused:
            raise
        except ValueError as exc:
            # The texts are this module's and the URL parser's own: fixed
            # sentences about the URL's structure, none with the URL in it.
            raise UrlRefused(str(exc), field) from exc

    @classmethod
    def _walk_request_urls(
        cls, value, *, url_named: bool, depth: int, seen: set, field: Optional[str]
    ) -> None:
        if depth > cls.URL_WALK_MAX_DEPTH:
            raise ValueError(URL_WALK_TOO_DEEP)

        if isinstance(value, _PYDANTIC_URL_TYPES):
            cls._refuse_url(str(value), field)
            return

        if isinstance(value, str):
            if url_named and re.match(r'^https?://', value.strip(), re.IGNORECASE):
                cls._refuse_url(value, field)
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
                    item,
                    url_named=cls.is_url_field_name(name),
                    depth=depth + 1,
                    seen=seen,
                    # The field of the input itself: what is below it keeps it.
                    field=name if field is None and isinstance(name, str) else field,
                )
        elif isinstance(value, dict):
            for key, item in value.items():
                cls._walk_request_urls(
                    item,
                    url_named=cls.is_url_field_name(key),
                    depth=depth + 1,
                    seen=seen,
                    field=key if field is None and isinstance(key, str) else field,
                )
        elif isinstance(value, (list, tuple, set, frozenset)):
            # The items of a list carry the name of the field that holds it.
            for item in value:
                cls._walk_request_urls(
                    item, url_named=url_named, depth=depth + 1, seen=seen, field=field
                )

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
                        raise ValueError(RESOLVES_INSIDE)
                return
            except socket.gaierror as exc:
                # Fail CLOSED. This used to return (allow) on the reasoning that
                # external DNS may be unreachable at validation time -- but a host
                # that cannot be resolved cannot be scanned either, so allowing it
                # buys nothing and hands an attacker who controls a nameserver a
                # trivial bypass: answer SERVFAIL for the validation lookup and
                # 127.0.0.1 for the request moments later (WILDBO-INPT-02).
                raise ValueError(DOES_NOT_RESOLVE) from exc

        if cls._is_blocked_ip(addr):
            raise ValueError(BLOCKED_ADDRESS)

    @staticmethod
    def _is_blocked_ip(addr) -> bool:
        """Return True if the IP address is private, loopback, link-local, or cloud metadata.

        The classification is ``open_security_shared.target_policy``'s, the
        one implementation for this service and for guardian's scans (#748):
        cloud metadata addresses, and everything that is not globally
        reachable (which also covers shared address space, 100.64.0.0/10,
        matching the host check in SecurityValidator._validate_public_host).
        This method stays the name the URL guard, ``app.safe_http`` and
        ``app.target_policy`` call it by.
        """
        return is_blocked_address(addr)

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
