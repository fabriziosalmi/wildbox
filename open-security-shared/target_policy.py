"""
Which network targets a service may connect to for a caller (#614, #748).

Two services scan what a caller names: the tools service (its network
tools) and guardian (asset discovery and port scans). Both run inside the
stack's networks, so a target that is internal to the deployment (the
stack's own services, the Docker host, the cloud metadata service, the
operator's LAN) is refused unless the operator allows it. This module is
the one implementation of that decision. It was the core of the tools
service's ``app/target_policy.py``; guardian had none.

The decision
============

Refused, unless the operator's allowlist covers it:

* an IP address that is private, loopback, link-local, unspecified,
  multicast, reserved or shared (100.64.0.0/10), a cloud metadata address,
  or one that is not globally reachable for another reason
  (:func:`is_blocked_address`), including an IPv4 address embedded in an
  IPv6 one (IPv4-mapped, 6to4, NAT64: :func:`embedded_ipv4`);
* a range with any such address in it: a range that only partly overlaps
  an internal one is refused whole;
* a range of more than ``MAX_TARGET_ADDRESSES`` addresses, allow-listed or
  not;
* a host name that resolves to any such address (every answer is checked)
  or that does not resolve at all;
* the deployment's own names (:func:`is_internal_name`): every
  single-label name, ``localhost`` and the special suffixes, and the cloud
  metadata names.

A host is parsed by :func:`parse_host`, which refuses every spelling of an
address but the canonical one: a resolver reads ``127.1``, ``0x7f000001``,
``2130706433`` and ``017700000001`` as loopback, and ``ipaddress`` does not
parse them, so they would otherwise pass as names.

The allowlist
=============

:func:`parse_allowlist` reads an operator's setting: comma-separated CIDR
ranges, IP addresses and, where the service scans by name, host names. Each
service has a setting of its own (``TOOLS_ALLOWED_INTERNAL_TARGETS``,
``GUARDIAN_ALLOWED_INTERNAL_TARGETS``) and passes its name, which the
error for a bad entry carries. A service does not read the other's: what
one may scan says nothing about the other, and they run on different
networks of the production overlay.

How a service uses it
=====================

:class:`TargetPolicy` holds an allowlist and answers with a
:class:`Refusal`, or ``None``. Nothing here raises for a refused target or
writes a message for a caller: the reason is data (:class:`Reason`, and the
address, host or count it is about), and each service words its own
refusal from it. A response is then never built from the text of an
exception.

This module needs the standard library only, so a service installs the
package without an extra to use it (guardian is Django and installs none).

``tests/shared/target_policy_vectors.json`` holds the cases every user of
this module must agree on. The shared package's tests, the tools service's
and guardian's each run them through their own entry point.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Callable, FrozenSet, Iterable, List, Optional, Tuple, Union

# The largest range a single input may name: a /22 in IPv4, a /118 in IPv6.
# The tools service's network_scanner sweeps at most 1024 hosts (its
# MAX_HOSTS) and iot_security_scanner 256, and one guardian discovery sweeps
# no more, so nothing a service scans is lost; a larger request is refused
# instead of being expanded (a /8 is 16 million addresses, an IPv6 /64 more
# than memory holds).
MAX_TARGET_ADDRESSES = 1024

# The addresses cloud providers serve instance metadata on.
CLOUD_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure metadata
        ipaddress.ip_address("fd00::c2b6:a9ff:fe52:2ea5"),  # Azure IPv6 metadata
    }
)

# Names of cloud metadata services, refused before any lookup.
METADATA_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.internal",
        "instance-data",
    }
)

# Name suffixes that never belong to a public host: RFC 6761 (localhost),
# RFC 6762 (local), RFC 8375 (home.arpa), the private-use TLD ICANN reserved
# in 2024 (internal), and the common localdomain.
INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".home.arpa")

# NAT64 well-known prefix (RFC 6052): the low 32 bits are an IPv4 address.
_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")

# A DNS label after IDNA encoding: letters, digits and hyphens, not starting
# or ending with a hyphen. Underscores are accepted because real host names
# carry them (service records, some cloud endpoints) and they do not change
# how a name resolves.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

# A label that a WHATWG URL parser treats as a number when it is the last
# label of the host: decimal, 0x-prefixed hex (possibly empty), or octal.
_NUMERIC_LABEL_RE = re.compile(r"^(?:[0-9]+|0[xX][0-9a-fA-F]*)$")

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


# --- addresses ------------------------------------------------------------------


def is_blocked_address(addr: IPAddress) -> bool:
    """True if the IP address is private, loopback, link-local, or cloud metadata."""
    if addr in CLOUD_METADATA_ADDRESSES:
        return True
    # not is_global also covers ranges the flags below miss, such as
    # shared address space (100.64.0.0/10).
    return (
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def embedded_ipv4(addr: IPAddress) -> Optional[ipaddress.IPv4Address]:
    """The IPv4 address an IPv6 one carries (IPv4-mapped, 6to4, NAT64), or None."""
    if addr.version != 6:
        return None
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr.sixtofour is not None:
        return addr.sixtofour
    if addr in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def is_internal_address(
    addr: IPAddress, blocked: Callable[[IPAddress], bool] = is_blocked_address
) -> bool:
    """True for an address the policy refuses unless it is allow-listed.

    ``blocked`` is the classifier; a service with a classifier of its own
    (the tools service's URL guard and its target policy share one) passes
    it, so the two cannot disagree. Python versions disagree on which of the
    IPv6 prefixes that embed an IPv4 address are global, so the embedded
    address is classified too.
    """
    if blocked(addr):
        return True
    embedded = embedded_ipv4(addr)
    return embedded is not None and blocked(embedded)


# --- names ----------------------------------------------------------------------


def is_local_hostname(host: str) -> bool:
    """True for names that always mean this machine (RFC 6761)."""
    host = host.lower().rstrip(".")
    return host == "localhost" or host.endswith(".localhost")


def is_internal_name(host: str) -> bool:
    """True for a name that only an internal resolver can answer for.

    Every single-label name (``wildbox-redis``, ``postgres``, ``gateway``:
    the names Docker and Kubernetes resolve for their services, which no
    public name is), ``localhost`` and the special suffixes, and the cloud
    metadata names. ``host`` is the canonical form returned by
    :func:`parse_host`.
    """
    host = host.lower().rstrip(".")
    return (
        "." not in host
        or is_local_hostname(host)
        or host in METADATA_HOSTNAMES
        or host.endswith(INTERNAL_SUFFIXES)
    )


# --- parsing a host -------------------------------------------------------------


@dataclass(frozen=True)
class ParsedTarget:
    """The parts of an accepted URL or host that callers need for host checks."""

    scheme: str
    host: str  # lower-case ASCII, no trailing dot, no brackets
    port: Optional[int]
    ip: Optional[IPAddress]  # set when the host is an IP literal


def reject_control_and_space(value: str) -> None:
    """Raise ValueError for whitespace or a control character anywhere."""
    for ch in value:
        if ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            raise ValueError("URL must not contain whitespace or control characters")


def looks_numeric(host: str) -> bool:
    """True if a WHATWG URL parser would treat ``host`` as an IPv4 address.

    The rule (URL Standard, "ends in a number") looks at the last label: if
    it is a decimal, hex or octal number, the whole host goes through the
    IPv4 parser, which accepts 1 to 4 parts in any of those bases. Clients
    and ``inet_aton`` behave the same way, so ``127.1`` or ``0x7f000001``
    reach loopback even though ``ipaddress`` refuses to parse them.
    """
    last = host.rsplit(".", 1)[-1]
    return bool(_NUMERIC_LABEL_RE.match(last))


def canonical_hostname(ascii_host: str) -> str:
    """The canonical form of an ASCII, lower-case DNS name, or raise ValueError.

    One trailing dot is the fully qualified spelling of the same name
    (``localhost.`` is ``localhost``); it is dropped so the checks here and
    the caller's host checks see the canonical form.
    """
    if ascii_host.endswith("."):
        ascii_host = ascii_host[:-1]

    if not ascii_host or len(ascii_host) > 253:
        raise ValueError("URL host has an invalid length")
    for label in ascii_host.split("."):
        if not _LABEL_RE.match(label):
            raise ValueError("URL host is not a valid domain name")
    return ascii_host


def parse_host(host: object) -> ParsedTarget:
    """Parse a bare host: an IP literal or a DNS name, nothing around it.

    A bare host is held to the same spelling rules as the host of a URL: no
    whitespace or control characters, a valid DNS name, and only the
    canonical dotted-quad spelling for anything a resolver would read as
    IPv4 (``127.1``, ``0x7f000001`` and ``2130706433`` are refused rather
    than normalized).

    Two rules are stricter than for a URL host, because the value is handed
    to the socket layer as written rather than through a URL parser:

    * a name must be ASCII (use the ``xn--`` form): Python's socket module
      encodes a non-ASCII name with IDNA 2003, which maps some characters
      differently from the UTS #46 encoding a URL host is checked with, so
      the checked name and the dialed name could differ;
    * an IPv6 literal is written without brackets, as sockets take it.

    The returned ``scheme`` is empty and ``port`` is ``None``.
    """
    if not isinstance(host, str) or not host:
        raise ValueError("Host must be a non-empty string")
    if len(host) > 253 + 1:
        raise ValueError("Host has an invalid length")
    reject_control_and_space(host)

    if ":" in host:
        # Only an IPv6 literal contains a colon. A zone id ("%eth0") only
        # makes sense for link-local addresses and is refused.
        if "%" in host:
            raise ValueError("Host must not carry an IPv6 zone id")
        try:
            ip6 = ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise ValueError("Host is not a valid IPv6 address or host name") from exc
        return ParsedTarget(scheme="", host=str(ip6), port=None, ip=ip6)

    if not host.isascii():
        raise ValueError(
            "Host name must be ASCII; write an internationalized name in its "
            "xn-- form"
        )
    ascii_host = canonical_hostname(host.lower())

    if looks_numeric(ascii_host):
        # IPv4Address accepts the canonical dotted quad only: no leading
        # zeros, no fewer parts, no hex or octal.
        try:
            ip4 = ipaddress.IPv4Address(ascii_host)
        except ValueError as exc:
            raise ValueError(
                "Host must be a dotted-quad IPv4 address or a domain name"
            ) from exc
        return ParsedTarget(scheme="", host=ascii_host, port=None, ip=ip4)

    return ParsedTarget(scheme="", host=ascii_host, port=None, ip=None)


def resolve_host(host: str) -> Optional[List[IPAddress]]:
    """Every address ``host`` resolves to, or None if it does not resolve.

    None also for an answer that is not an address: nothing of it can be
    checked, so nothing of it is used.
    """
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    addresses: List[IPAddress] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        try:
            # An IPv6 sockaddr may carry a zone ("fe80::1%eth0"); drop it.
            addresses.append(ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0]))
        except ValueError:
            return None
    return addresses or None


# --- the allowlist --------------------------------------------------------------


@dataclass(frozen=True)
class Allowlist:
    """The internal ranges and names an operator allows a service to scan."""

    networks: Tuple[IPNetwork, ...] = ()
    names: FrozenSet[str] = frozenset()

    def covers_address(self, addr: IPAddress) -> bool:
        return any(addr in net for net in self.networks if net.version == addr.version)

    def __bool__(self) -> bool:
        return bool(self.networks or self.names)


def parse_allowlist(
    raw: Optional[str], setting: str, *, names: bool = True
) -> Allowlist:
    """Parse an operator allowlist. Raise ValueError naming a bad entry.

    ``setting`` is the name of the variable the value came from; the error
    carries it, so the operator knows which line to fix. Entries are
    separated by commas; blank entries are ignored. An entry is a CIDR range
    (host bits must be zero, so a typo such as 10.0.0.1/8 is caught), an IP
    address, or an ASCII host name.

    With ``names=False`` a host name is an error too: a service that scans
    addresses only (guardian) would accept the entry and never match it.
    """
    networks: List[IPNetwork] = []
    listed_names = set()
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=True))
            continue
        except ValueError as exc:
            if "/" in entry or ":" in entry:
                raise ValueError(
                    f"{setting}: {entry!r} is not a valid CIDR range or IP address ({exc})"
                ) from exc
        try:
            parsed = parse_host(entry)
        except ValueError as exc:
            raise ValueError(
                f"{setting}: {entry!r} is not a CIDR range, an IP address "
                f"or a host name ({exc})"
            ) from exc
        if parsed.ip is not None:  # pragma: no cover - ip_network took it above
            networks.append(ipaddress.ip_network(parsed.ip))
        elif not names:
            raise ValueError(
                f"{setting}: {entry!r} is a host name; this setting takes CIDR "
                "ranges and IP addresses only"
            )
        else:
            listed_names.add(parsed.host)
    return Allowlist(networks=tuple(networks), names=frozenset(listed_names))


# --- the decision ---------------------------------------------------------------


class Reason(str, Enum):
    """Why a target is refused."""

    # Not a host: the parser's reason is in ``Refusal.detail``.
    INVALID = "invalid"
    # More addresses than one request may name: ``Refusal.count`` of them.
    TOO_LARGE = "too_large"
    # An internal address, or a range with one in it: ``Refusal.address``.
    INTERNAL_ADDRESS = "internal_address"
    # A name of the deployment itself: ``Refusal.host``, never looked up.
    INTERNAL_NAME = "internal_name"
    # A name that does not resolve, or resolves to an internal address. One
    # reason for both: two would tell a caller which internal names exist.
    UNRESOLVABLE = "unresolvable"


@dataclass(frozen=True)
class Refusal:
    """A refused target: the reason, and what it is about."""

    reason: Reason
    host: str = ""
    address: Optional[IPAddress] = None
    count: int = 0
    detail: str = ""


class TargetPolicy:
    """The decision for one allowlist. Its methods answer; none raises."""

    __slots__ = ("allowlist", "blocked", "max_addresses")

    def __init__(
        self,
        allowlist: Optional[Allowlist] = None,
        *,
        blocked: Callable[[IPAddress], bool] = is_blocked_address,
        max_addresses: int = MAX_TARGET_ADDRESSES,
    ) -> None:
        self.allowlist = allowlist if allowlist is not None else Allowlist()
        self.blocked = blocked
        self.max_addresses = max_addresses

    def allows(self, addr: IPAddress) -> bool:
        """True for a public address, or an internal one the allowlist covers."""
        return not is_internal_address(
            addr, self.blocked
        ) or self.allowlist.covers_address(addr)

    def refuse_addresses(self, addresses: Iterable[IPAddress]) -> Optional[Refusal]:
        """The refusal for the first address that is not allowed, or None."""
        for addr in addresses:
            if not self.allows(addr):
                return Refusal(Reason.INTERNAL_ADDRESS, address=addr)
        return None

    def refuse_network(self, network: IPNetwork) -> Optional[Refusal]:
        """The refusal for a range, or None if every address of it is allowed.

        The size comes first, so a range that would not fit in memory is
        refused without being expanded. Then every address: a range that
        only partly overlaps an internal one, or the allowlist, is refused.
        """
        if network.num_addresses > self.max_addresses:
            return Refusal(Reason.TOO_LARGE, count=network.num_addresses)
        return self.refuse_addresses(iter(network))

    def check_host(self, value: object) -> Tuple[List[IPAddress], Optional[Refusal]]:
        """Check one host (IP literal or name): ``(addresses, None)`` or
        ``([], refusal)``.

        For an IP literal the address is the literal itself; for a name,
        every address it resolves to. A caller that connects should dial one
        of the returned addresses, so the address checked is the one used.
        """
        try:
            parsed = parse_host(value)
        except ValueError as exc:
            return [], Refusal(Reason.INVALID, detail=str(exc))

        if parsed.ip is not None:
            if not self.allows(parsed.ip):
                return [], Refusal(Reason.INTERNAL_ADDRESS, address=parsed.ip)
            return [parsed.ip], None

        host = parsed.host
        if host in self.allowlist.names:
            # Allowed by name: whatever it resolves to. Still resolved, so a
            # caller that connects gets an address to dial.
            addresses = resolve_host(host)
            if addresses is None:
                return [], Refusal(Reason.UNRESOLVABLE, host=host)
            return addresses, None
        if is_internal_name(host):
            return [], Refusal(Reason.INTERNAL_NAME, host=host)
        addresses = resolve_host(host)
        if addresses is None or not all(self.allows(addr) for addr in addresses):
            return [], Refusal(Reason.UNRESOLVABLE, host=host)
        return addresses, None
