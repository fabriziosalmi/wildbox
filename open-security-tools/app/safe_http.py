"""HTTP clients for tools that fetch a URL the caller supplied.

The SSRF guard on tool inputs (``InputSanitizer.validate_request_urls``)
checks the URL a caller sends. It cannot see what happens after the first
request: a public URL that answers ``302 Location: http://169.254.169.254/``
sends a client that follows redirects straight to the metadata service, and
a host name whose DNS answer changes between the check and the connection
(DNS rebinding) reaches an address that was never checked (#610).

This module moves the check to the place where the connection is made, so
it applies to every hop and to the address actually dialed.

aiohttp (:func:`guarded_session`)
    * :class:`GuardedConnector` checks the scheme, host and port of every
      request it opens a connection for. aiohttp calls the connector once
      per hop, so redirect targets are checked exactly like the first URL.
      IP literals are refused here when they are not public, because aiohttp
      does not pass them to the resolver.
    * :class:`GuardedResolver` resolves host names and refuses the name when
      any address in the answer is not public. aiohttp connects to the
      addresses the resolver returns, so the checked addresses are the ones
      dialed: the resolution is pinned and a rebinding answer cannot slip in
      between the check and the connection.
    * Automatic redirects are capped at :data:`MAX_REDIRECTS`; a redirect
      loop ends there with :class:`UnsafeTargetError`.

requests (:func:`guarded_requests_session`)
    :class:`GuardedRequestsSession` validates the URL of every request it
    sends, including each redirect hop (``requests`` sends each hop through
    ``Session.send``), with :meth:`InputSanitizer.validate_url`: structure,
    blocked names and DNS resolution of every address. Redirects are capped
    at :data:`MAX_REDIRECTS` (``requests.TooManyRedirects`` past that).
    The resolution is not pinned: urllib3 (or a proxy taken from the
    environment) resolves the name again when it connects. A rebinding
    attack needs a nameserver that answers a public address for the check
    and a private one a moment later; the aiohttp path does not have this
    window, so new code should use :func:`guarded_session`.

A refused target raises :class:`UnsafeTargetError`, a ``ValueError``.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, List, Optional

import aiohttp
import requests
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import DefaultResolver

from .input_validation import InputSanitizer
from .url_guard import is_local_hostname, parse_target_url

# Redirect hops a guarded client follows on its own. Enough for the usual
# http -> https -> canonical host -> login page chain; a loop stops here.
MAX_REDIRECTS = 5


class UnsafeTargetError(ValueError):
    """A connection was refused because its target is not a public host."""


def is_blocked_address(addr: Any) -> bool:
    """True if a tool must not connect to this IP address.

    The single policy for this module, shared with
    ``InputSanitizer.validate_url``: private, loopback, link-local, reserved,
    multicast, unspecified, shared and cloud-metadata addresses are refused.
    """
    return InputSanitizer._is_blocked_ip(addr)


def check_target_origin(url: str) -> None:
    """Check scheme, host and port of ``url`` without any network I/O.

    Host names are only checked against the names that always mean an
    internal host; their addresses are checked by the resolver. IP literals
    are checked here. Raises :class:`UnsafeTargetError`.
    """
    try:
        target = parse_target_url(url)
    except ValueError as exc:
        raise UnsafeTargetError(f"Refused target {url!r}: {exc}") from exc
    if (
        is_local_hostname(target.host)
        or target.host in InputSanitizer.BLOCKED_HOSTNAMES
    ):
        raise UnsafeTargetError(
            f"Refused target host '{target.host}' (SSRF protection)"
        )
    if target.ip is not None and is_blocked_address(target.ip):
        raise UnsafeTargetError(f"Refused target address {target.ip} (SSRF protection)")


class GuardedResolver(AbstractResolver):
    """Resolve with the default resolver; refuse names with a blocked address.

    The whole answer is refused, not filtered: a name that resolves to both
    a public and a private address is treated as hostile.
    """

    def __init__(self, inner: Optional[AbstractResolver] = None) -> None:
        self._inner = inner if inner is not None else DefaultResolver()

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> List[ResolveResult]:
        name = host.lower().rstrip(".")
        if is_local_hostname(name) or name in InputSanitizer.BLOCKED_HOSTNAMES:
            raise UnsafeTargetError(f"Refused target host '{host}' (SSRF protection)")
        results = await self._inner.resolve(host, port, family)
        if not results:
            raise UnsafeTargetError(
                f"Host '{host}' did not resolve; refusing to connect"
            )
        for result in results:
            try:
                addr = ipaddress.ip_address(result["host"])
            except ValueError as exc:
                raise UnsafeTargetError(
                    f"Host '{host}' resolved to an invalid address"
                ) from exc
            if is_blocked_address(addr):
                raise UnsafeTargetError(
                    f"Host '{host}' resolves to blocked address {addr} (SSRF protection)"
                )
        return results

    async def close(self) -> None:
        await self._inner.close()


class GuardedConnector(aiohttp.TCPConnector):
    """A TCP connector that refuses non-public targets on every connection."""

    def __init__(
        self, *args: Any, resolver: Optional[AbstractResolver] = None, **kwargs: Any
    ) -> None:
        super().__init__(*args, resolver=GuardedResolver(resolver), **kwargs)

    async def connect(self, req: Any, traces: Any, timeout: Any) -> Any:
        check_target_origin(str(req.url.origin()))
        return await super().connect(req, traces, timeout)


def _redirect_limit(limit: int) -> aiohttp.TraceConfig:
    """Trace hook that stops automatic redirects after ``limit`` hops."""

    async def on_redirect(session: Any, ctx: Any, params: Any) -> None:
        ctx.redirects = getattr(ctx, "redirects", 0) + 1
        if ctx.redirects > limit:
            raise UnsafeTargetError(f"Too many redirects (limit {limit})")

    trace = aiohttp.TraceConfig()
    trace.on_request_redirect.append(on_redirect)
    return trace


def guarded_session(
    *,
    ssl: Any = True,
    limit: int = 100,
    limit_per_host: int = 0,
    max_redirects: int = MAX_REDIRECTS,
    resolver: Optional[AbstractResolver] = None,
    **session_kwargs: Any,
) -> aiohttp.ClientSession:
    """An ``aiohttp.ClientSession`` for fetching caller-supplied URLs.

    Takes the usual session arguments (``timeout``, ``headers``,
    ``cookie_jar``...) except ``connector``, which it builds itself, and
    ``trust_env``, which stays off: a proxy taken from the environment
    would resolve the target itself, outside the guard. ``ssl``, ``limit``
    and ``limit_per_host`` go to the connector. ``resolver`` replaces the
    resolver whose answers are checked (tests use it to fake DNS).
    """
    if "connector" in session_kwargs:
        raise TypeError("guarded_session builds its own connector")
    if session_kwargs.pop("trust_env", False):
        raise TypeError("guarded_session does not take proxies from the environment")
    trace_configs = [
        _redirect_limit(max_redirects),
        *(session_kwargs.pop("trace_configs", None) or []),
    ]
    connector = GuardedConnector(
        ssl=ssl, limit=limit, limit_per_host=limit_per_host, resolver=resolver
    )
    return aiohttp.ClientSession(
        connector=connector, trace_configs=trace_configs, **session_kwargs
    )


class GuardedRequestsSession(requests.Session):
    """A ``requests`` session that validates every URL it sends to."""

    def __init__(self, max_redirects: int = MAX_REDIRECTS) -> None:
        super().__init__()
        self.max_redirects = max_redirects

    def send(
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        try:
            InputSanitizer.validate_url(request.url)
        except ValueError as exc:
            raise UnsafeTargetError(f"Refused target {request.url!r}: {exc}") from exc
        return super().send(request, **kwargs)


def guarded_requests_session(
    max_redirects: int = MAX_REDIRECTS,
) -> GuardedRequestsSession:
    """A ``requests.Session`` for fetching caller-supplied URLs."""
    return GuardedRequestsSession(max_redirects=max_redirects)
