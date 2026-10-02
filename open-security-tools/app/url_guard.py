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
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Optional, Union
from urllib.parse import urlsplit

import idna

DEFAULT_ALLOWED_SCHEMES = ("http", "https")
DEFAULT_MAX_LENGTH = 2048

# A DNS label after IDNA encoding: letters, digits and hyphens, not starting
# or ending with a hyphen. Underscores are accepted because real host names
# carry them (service records, some cloud endpoints) and they do not change
# how a name resolves.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

# A label that a WHATWG URL parser treats as a number when it is the last
# label of the host: decimal, 0x-prefixed hex (possibly empty), or octal.
_NUMERIC_LABEL_RE = re.compile(r"^(?:[0-9]+|0[xX][0-9a-fA-F]*)$")

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass(frozen=True)
class ParsedTarget:
    """The parts of an accepted URL that callers need for host checks."""

    scheme: str
    host: str  # lower-case ASCII, no trailing dot, no brackets
    port: Optional[int]
    ip: Optional[IPAddress]  # set when the host is an IP literal


def _reject_control_and_space(url: str) -> None:
    for ch in url:
        if ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            raise ValueError("URL must not contain whitespace or control characters")


def _looks_numeric(host: str) -> bool:
    """True if a WHATWG URL parser would treat ``host`` as an IPv4 address.

    The rule (URL Standard, "ends in a number") looks at the last label: if
    it is a decimal, hex or octal number, the whole host goes through the
    IPv4 parser, which accepts 1 to 4 parts in any of those bases. Clients
    and ``inet_aton`` behave the same way, so ``127.1`` or ``0x7f000001``
    reach loopback even though ``ipaddress`` refuses to parse them.
    """
    last = host.rsplit(".", 1)[-1]
    return bool(_NUMERIC_LABEL_RE.match(last))


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

    # One trailing dot is the fully qualified spelling of the same name
    # (``localhost.`` is ``localhost``); drop it so the checks below and the
    # caller's host checks see the canonical form.
    if ascii_host.endswith("."):
        ascii_host = ascii_host[:-1]

    if not ascii_host or len(ascii_host) > 253:
        raise ValueError("URL host has an invalid length")
    for label in ascii_host.split("."):
        if not _LABEL_RE.match(label):
            raise ValueError("URL host is not a valid domain name")
    return ascii_host


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


def is_local_hostname(host: str) -> bool:
    """True for names that always mean this machine (RFC 6761)."""
    host = host.lower().rstrip(".")
    return host == "localhost" or host.endswith(".localhost")
