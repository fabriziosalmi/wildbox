"""Structural validation of URLs that a tool is about to connect to.

Both URL validators in this service (``SecurityValidator.validate_url`` and
``InputSanitizer.validate_url``) parse through :func:`parse_target_url`, so
they agree on what a well-formed target is.

The checks are structural, not pattern based. Matching injection patterns
against a whole URL refused ordinary targets (``http://``, query strings,
host names containing ``sh``; see #561) while letting through the forms that
matter for SSRF: user info, control characters and numeric host spellings
that ``ipaddress`` does not recognize but resolvers turn into loopback.

What this module guarantees for an accepted URL:

* it is a ``str`` of bounded length with no control characters and no
  whitespace anywhere (no header injection, no parser disagreement on
  embedded spaces or tabs);
* its scheme is one of the allowed schemes;
* it has a host and no user info (``user:pass@host`` is refused);
* its port, if any, is in 1..65535;
* its host is either a canonical IP literal (dotted-quad IPv4 or bracketed
  IPv6) or a DNS name that encodes to ASCII under IDNA/UTS #46 and consists
  of valid labels. Hosts that a URL parser or resolver would read as an IPv4
  address in another spelling (``2130706433``, ``0x7f000001``,
  ``017700000001``, ``127.1``) are refused rather than normalized.

Whether the host is *public* is left to the caller, because the two callers
differ: one checks IP literals and local names only, the other also resolves
the name. This module performs no network I/O.

The rules for a host (its spelling, the labels of a name, what reads as a
number, the names that mean this machine) and the parser of a bare host,
:func:`parse_host`, live in ``open_security_shared.target_policy``, which
guardian's scans use too (#748). They are imported here under the names
this service has always used; what stays in this module is the URL around
the host, and the IDNA encoding of a host that is not ASCII, which needs the
``idna`` package the shared module does without.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable
from urllib.parse import urlsplit

import idna
from open_security_shared.target_policy import (  # noqa: F401 - re-exported
    IPAddress,
    ParsedTarget,
    canonical_hostname,
    is_local_hostname,
    parse_host,
)
from open_security_shared.target_policy import looks_numeric as _looks_numeric
from open_security_shared.target_policy import (
    reject_control_and_space as _reject_control_and_space,
)

DEFAULT_ALLOWED_SCHEMES = ("http", "https")
DEFAULT_MAX_LENGTH = 2048


def _encode_hostname(host: str) -> str:
    """Return the ASCII form of a DNS host name, or raise ValueError."""
    if host.isascii():
        ascii_host = host.lower()
    else:
        try:
            ascii_host = idna.encode(host, uts46=True).decode("ascii")
        except (idna.IDNAError, UnicodeError) as exc:
            raise ValueError(
                "URL host is not a valid internationalized domain name"
            ) from exc
        ascii_host = ascii_host.lower()

    # The trailing dot, the length and the labels: one rule for the host of
    # a URL and for a bare host.
    return canonical_hostname(ascii_host)


def parse_target_url(
    url: object,
    *,
    allowed_schemes: Iterable[str] = DEFAULT_ALLOWED_SCHEMES,
    max_length: int = DEFAULT_MAX_LENGTH,
) -> ParsedTarget:
    """Parse ``url`` and check its structure. Raise ValueError if refused."""
    if not isinstance(url, str) or not url:
        raise ValueError("URL must be a non-empty string")
    if len(url) > max_length:
        raise ValueError(f"URL too long (max {max_length} characters)")
    _reject_control_and_space(url)

    try:
        parts = urlsplit(url)
    except ValueError as exc:  # e.g. an unbalanced "[" in the netloc
        raise ValueError(f"Invalid URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in {s.lower() for s in allowed_schemes}:
        raise ValueError(f"Invalid URL scheme: {parts.scheme or '(none)'}")

    netloc = parts.netloc
    if not netloc:
        raise ValueError("URL must have a hostname")
    # User info is refused outright: "https://trusted.example@evil.example/"
    # reads as one host and connects to another, and credentials have no
    # place in a scan target.
    if "@" in netloc:
        raise ValueError("URL must not contain user info")

    # urlsplit raises ValueError for a port that is not ASCII digits ("+80",
    # "-1", " 80") or is above 65535; port 0 is parsed but cannot be dialed.
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("URL port is invalid") from exc
    if port == 0:
        raise ValueError("URL port is invalid")

    hostname = parts.hostname
    if not hostname:
        raise ValueError("URL must have a hostname")

    if netloc.startswith("["):
        # Brackets are only for IPv6 literals. A zone id ("%25eth0") is
        # refused: it only makes sense for link-local addresses.
        if "%" in hostname:
            raise ValueError("URL host must not carry an IPv6 zone id")
        try:
            ip = ipaddress.IPv6Address(hostname)
        except ValueError as exc:
            raise ValueError("URL host is not a valid IPv6 address") from exc
        return ParsedTarget(scheme=scheme, host=str(ip), port=port, ip=ip)

    host = _encode_hostname(hostname)

    if _looks_numeric(host):
        # Accept only the canonical dotted-quad spelling. Everything else
        # that a client would read as IPv4 (fewer parts, hex, octal, leading
        # zeros, out-of-range parts) is refused instead of normalized, so no
        # two components can disagree on which address it means.
        try:
            ip4 = ipaddress.IPv4Address(host)
        except ValueError as exc:
            raise ValueError(
                "URL host must be a dotted-quad IPv4 address or a domain name"
            ) from exc
        # Compare with the host as written, too: a non-ASCII spelling such as
        # fullwidth digits maps to a dotted quad under UTS #46, but the URL
        # handed back to the caller still carries the original spelling.
        if str(ip4) != host or hostname.rstrip(".") != host:
            raise ValueError(
                "URL host must be a dotted-quad IPv4 address or a domain name"
            )
        return ParsedTarget(scheme=scheme, host=host, port=port, ip=ip4)

    return ParsedTarget(scheme=scheme, host=host, port=port, ip=None)
