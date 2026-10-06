"""Which network targets a tool may scan (#614).

The URL guard (``InputSanitizer.validate_request_urls``, ``app.safe_http``)
covers tools that fetch URLs. Network tools take a host, an IP address, a
CIDR range, a DNS server or a container image instead, and connect to it
with raw sockets, a database driver, dnspython or a subprocess. This module
is the policy for those inputs.

What is internal, what the allowlist covers and how a host is parsed are
decided by ``open_security_shared.target_policy``, the implementation this
service shares with guardian's asset discovery and port scans (#748). What
is here is this service's side of it: which input fields of which tool are
targets and what kind of value each holds, the setting the allowlist is
read from, the words of a refusal, and the three paths that enforce it.

The policy
==========

A tool may not be pointed at an internal target. Refused, unless the
operator allows it (below):

* IP addresses that are private, loopback, link-local, unspecified,
  multicast, reserved or shared (100.64.0.0/10), or that are not globally
  reachable for another reason (``InputSanitizer._is_blocked_ip``, the
  check the URL guard uses, which is the shared module's), including an
  IPv4 address embedded in an IPv6 one (IPv4-mapped, 6to4, NAT64);
* a CIDR range or an address range with any such address in it;
* a host name that resolves to any such address (every answer is checked,
  as ``GuardedResolver`` does), or that does not resolve at all;
* the deployment's own names: every single-label name (``wildbox-redis``,
  ``postgres``, ``gateway``: the names Docker and Kubernetes resolve for
  their services, which no public name is), ``localhost`` and the special
  suffixes ``.localhost``, ``.local``, ``.internal``, ``.localdomain`` and
  ``.home.arpa``, and the cloud metadata names.

A CIDR or address range may hold at most :data:`MAX_TARGET_ADDRESSES`
addresses (a /22 in IPv4), so a request cannot make a tool expand a /8
or an IPv6 /64.

The operator allowlist
======================

``TOOLS_ALLOWED_INTERNAL_TARGETS`` is a comma-separated list of CIDR ranges,
IP addresses and host names (empty by default). A target the policy refuses
is accepted if it is covered by the list: an IP address inside a listed
range, a range whose internal addresses are all inside listed ranges, a
host name listed by name, or a host name whose internal addresses are all
inside listed ranges. A listed name is matched exactly (no subdomains). The
list is parsed when the service and the worker start (``app.config``), and
an entry that is not a CIDR, an IP address or a host name stops them.

The authorization manager of #564 has a target list of its own
(``authorized_targets``, read from ``AUTHORIZED_TARGETS_FILE``). It is not
reused here, on purpose: it narrows, this widens. It names the targets a
caller who acts through a tool (sql_injection_scanner) may attack, among
public ones, and never lifts the SSRF guard; this list names the internal
ranges any caller may scan. Merging them would open an internal lab range
to every scanner as a side effect of authorizing one web target, or the
reverse.

Where it is enforced
====================

:func:`enforce_target_policy` is the one entry point. It runs the URL guard
and then this policy on a validated tool input, and is called before any
tool runs on the three paths that run one: the synchronous endpoint
(``app.api.router``), the Celery task (``app.tasks``) and each step of
security_automation_orchestrator. Which input fields are network targets is
declared in :data:`NETWORK_TARGET_FIELDS`, per tool, with the kind of value
each field holds; ``tests/unit/test_target_policy.py`` fails when a tool
has a host-like field that is neither declared there nor listed in
:data:`REVIEWED_NON_TARGET_FIELDS` with the reason it is not a target.

dns_enumerator also applies the policy to targets the remote side chooses:
the name servers it attempts a zone transfer from, which come from a DNS
answer. It connects to the address that was checked.

What remains
============

The check resolves a host name, and most tools then resolve the same name
again when they connect. A name whose DNS answer changes between the two
lookups (DNS rebinding, with a TTL of zero) can still reach an internal
address in that window. Pinning the checked address would mean rewriting
each tool's connection code; the window is documented instead, and the
tools that already connect to a checked address (whois_lookup's referral
server, dns_enumerator's zone transfers, the HTTP clients of
``app.safe_http``) have no such window. container_security_scanner hands
the image reference to trivy, which talks to the registry checked here but
follows the registry's own redirects and token endpoints itself.
"""

from __future__ import annotations

import ipaddress
import logging
from enum import Enum
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Tuple

from open_security_shared import target_policy as shared_policy
from open_security_shared.target_policy import (  # noqa: F401 - re-exported
    MAX_TARGET_ADDRESSES,
    Allowlist,
    IPAddress,
    IPNetwork,
    Reason,
    Refusal,
    TargetPolicy,
    is_internal_name,
)
from open_security_shared.target_policy import (  # noqa: F401 - re-exported
    embedded_ipv4 as _embedded_ipv4,
)

from .input_validation import InputSanitizer

logger = logging.getLogger(__name__)

ALLOWLIST_ENV = "TOOLS_ALLOWED_INTERNAL_TARGETS"

# MAX_TARGET_ADDRESSES, the largest range a single input may name (a /22 in
# IPv4, a /118 in IPv6), is the shared module's: network_scanner sweeps at
# most 1024 hosts (its MAX_HOSTS) and iot_security_scanner 256, so nothing a
# tool scans is lost; a larger request is refused instead of being expanded.


class TargetRefused(ValueError):
    """A tool input names a target the policy does not allow."""


class TargetKind(str, Enum):
    """What a network target field holds, which decides how it is parsed."""

    # An IP literal or a host name, connected to as written.
    HOST = "host"
    # pki_certificate_manager's domain: a host, "host:port" or a URL whose
    # host is taken the way the tool takes it.
    HOST_PORT_OR_URL = "host_port_or_url"
    # An IP literal only (dnspython takes name servers as addresses).
    IP = "ip"
    # An IP literal or a CIDR range.
    IP_OR_CIDR = "ip_or_cidr"
    # network_scanner's network: an IP, a CIDR range or "a.b.c.d-e".
    NETWORK = "network"
    # A container image reference; its registry host is the target.
    IMAGE_REF = "image_ref"


# The input fields of each tool that name a host the tool connects to. A
# field holding a list is checked item by item. Keep this in step with the
# tools: tests/unit/test_target_policy.py fails when a tool has a host-like
# field that is neither here nor in REVIEWED_NON_TARGET_FIELDS.
NETWORK_TARGET_FIELDS: Dict[str, Dict[str, TargetKind]] = {
    "ca_analyzer": {"target": TargetKind.HOST},
    "container_security_scanner": {"image_name": TargetKind.IMAGE_REF},
    "database_security_analyzer": {"host": TargetKind.HOST},
    "dns_enumerator": {"dns_servers": TargetKind.IP},
    "iot_security_scanner": {
        "target_ip": TargetKind.HOST,
        "ip_range": TargetKind.IP_OR_CIDR,
    },
    "network_port_scanner": {"target": TargetKind.HOST},
    "network_scanner": {"network": TargetKind.NETWORK},
    "network_vulnerability_scanner": {"target": TargetKind.HOST},
    "pki_certificate_manager": {"domain": TargetKind.HOST_PORT_OR_URL},
    "port_scanner": {"target": TargetKind.HOST},
    "ssl_analyzer": {"target": TargetKind.HOST},
}

# Host-like input fields that were reviewed and are not network targets,
# with the reason. URL fields are not listed: the URL guard checks them.
REVIEWED_NON_TARGET_FIELDS: Dict[Tuple[str, str], str] = {
    ("blockchain_security_analyzer", "contract_address"): (
        "a contract address sent to a fixed block explorer API"
    ),
    ("ct_log_scanner", "domain"): "a query parameter of the fixed crt.sh API",
    ("database_security_analyzer", "connection_string"): (
        "declared but not read; the tool connects to host"
    ),
    ("digital_footprint_analyzer", "target_identifier"): (
        "looked up on fixed public services; never connected to"
    ),
    ("dns_enumerator", "target_domain"): (
        "a name queried through dns_servers (which are checked); the zone "
        "transfer name servers are checked by the tool itself"
    ),
    ("dns_enumerator", "subdomain_wordlist"): "the name of a built-in word list",
    ("dns_security_checker", "domain"): "a name queried over DNS; never connected to",
    ("email_harvester", "domain"): (
        "fetched as https://<domain> after InputSanitizer.validate_url"
    ),
    ("ip_geolocation", "ip_address"): "the path of a fixed third-party API URL",
    ("iot_security_scanner", "port_scan_range"): "ports on the checked targets",
    ("network_vulnerability_scanner", "port_range"): "ports on the checked target",
    ("social_engineering_toolkit", "target"): "analyzed offline; no connection is made",
    ("subdomain_scanner", "domain"): "a name queried over DNS; never connected to",
    ("vulnerability_db_scanner", "target"): (
        "a product or CVE keyword sent to the fixed NVD/OSV APIs"
    ),
    ("whois_lookup", "domain"): (
        "sent to the registry's WHOIS server; referral servers are checked "
        "by the tool itself"
    ),
}


# --- the allowlist ------------------------------------------------------------


def parse_allowlist(raw: Optional[str]) -> Allowlist:
    """Parse the operator allowlist. Raise ValueError naming a bad entry.

    Entries are separated by commas; blank entries are ignored. An entry is
    a CIDR range (host bits must be zero, so a typo such as 10.0.0.1/8 is
    caught), an IP address, or an ASCII host name.
    """
    return shared_policy.parse_allowlist(raw, ALLOWLIST_ENV)


@lru_cache(maxsize=8)
def _parsed_allowlist(raw: str) -> Allowlist:
    allowlist = parse_allowlist(raw)
    logger.info(
        "Network target policy: %d internal range(s) and %d host name(s) allowed by %s",
        len(allowlist.networks),
        len(allowlist.names),
        ALLOWLIST_ENV,
    )
    return allowlist


def current_allowlist() -> Allowlist:
    """The allowlist the service was configured with."""
    from .config import settings

    return _parsed_allowlist(settings.tools_allowed_internal_targets or "")


# --- address checks ------------------------------------------------------------


def _is_blocked(addr: IPAddress) -> bool:
    # Looked up on each call: the URL guard, app.safe_http and this policy
    # classify an address through the one name, InputSanitizer._is_blocked_ip.
    return InputSanitizer._is_blocked_ip(addr)


def _policy(allowlist: Allowlist) -> TargetPolicy:
    """The shared decision, for this allowlist and this service's classifier."""
    return TargetPolicy(allowlist, blocked=_is_blocked)


def is_internal_address(addr: IPAddress) -> bool:
    """True for an address the policy refuses unless it is allow-listed."""
    return shared_policy.is_internal_address(addr, _is_blocked)


def _unresolvable(host: str) -> str:
    # One message for "does not resolve" and "resolves inside": two would
    # tell a caller which internal names exist.
    return (
        f"Target host '{host}' is refused: it does not resolve, or resolves to "
        f"an internal address (network target policy; operators can allow "
        f"internal targets with {ALLOWLIST_ENV})"
    )


def _refused_address(value: str) -> str:
    return (
        f"Target '{value}' is a private, loopback, link-local, multicast, reserved "
        f"or otherwise internal address (network target policy; operators can "
        f"allow internal targets with {ALLOWLIST_ENV})"
    )


def check_host(value: str, allowlist: Optional[Allowlist] = None) -> List[IPAddress]:
    """Check one host (IP literal or name) and return the addresses checked.

    For an IP literal that is the address itself; for a name, every address
    it resolves to. A caller that connects should dial one of the returned
    addresses, so the address checked is the one used. Raise TargetRefused.
    """
    if allowlist is None:
        allowlist = current_allowlist()
    addresses, refusal = _policy(allowlist).check_host(value)
    if refusal is None:
        return addresses
    if refusal.reason is Reason.INVALID:
        raise TargetRefused(f"Target {value!r} is not a valid host: {refusal.detail}")
    if refusal.reason is Reason.INTERNAL_ADDRESS:
        raise TargetRefused(_refused_address(value))
    if refusal.reason is Reason.INTERNAL_NAME:
        raise TargetRefused(
            f"Target host '{refusal.host}' is an internal or deployment service name "
            f"(network target policy; operators can allow internal targets "
            f"with {ALLOWLIST_ENV})"
        )
    raise TargetRefused(_unresolvable(refusal.host))


def _refuse_range(refusal: Optional[Refusal], value: str) -> None:
    """Raise TargetRefused for the refusal of a range, in this service's words."""
    if refusal is None:
        return
    if refusal.reason is Reason.TOO_LARGE:
        raise TargetRefused(
            f"Target range '{value}' has {refusal.count} addresses; at most "
            f"{MAX_TARGET_ADDRESSES} may be scanned in one request"
        )
    raise TargetRefused(
        f"Target range '{value}' includes {refusal.address}, a private, loopback, "
        f"link-local, multicast, reserved or otherwise internal address "
        f"(network target policy; operators can allow internal targets "
        f"with {ALLOWLIST_ENV})"
    )


def _check_addresses(
    addresses: Iterable[IPAddress], value: str, allowlist: Allowlist
) -> None:
    _refuse_range(_policy(allowlist).refuse_addresses(addresses), value)


def _reject_space_and_control(value: str) -> None:
    # No target of any kind contains whitespace or a control character, and
    # a resolver may read what follows a space as something else
    # (inet_aton accepts "127.0.0.1 anything").
    if any(ch.isspace() or not ch.isprintable() for ch in value):
        raise TargetRefused(
            f"Target {value!r} must not contain whitespace or control characters"
        )


def check_ip(value: str, allowlist: Allowlist) -> None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TargetRefused(f"Target {value!r} must be an IP address") from exc
    if not _policy(allowlist).allows(addr):
        raise TargetRefused(_refused_address(value))


def check_cidr(value: str, allowlist: Allowlist) -> None:
    """An IP address or a CIDR range, bounded, with no internal address."""
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise TargetRefused(
            f"Target {value!r} must be an IP address or a CIDR range"
        ) from exc
    # ip_network accepts what it prints back; "010.0.0.1/24" and friends
    # are already refused by the ipaddress module itself.
    _refuse_range(_policy(allowlist).refuse_network(net), value)


def check_network(value: str, allowlist: Allowlist) -> None:
    """network_scanner's syntax: an IP, a CIDR range or "a.b.c.d-e"."""
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        pass
    else:
        check_cidr(value, allowlist)
        return

    base, sep, last = value.rpartition(".")
    start_text, dash, end_text = last.partition("-")
    if not (sep and dash and start_text.isdecimal() and end_text.isdecimal()):
        raise TargetRefused(
            f"Target {value!r} must be an IP address, a CIDR range or a range "
            "such as 192.0.2.1-20"
        )
    start, end = int(start_text), int(end_text)
    try:
        first = ipaddress.IPv4Address(f"{base}.{start}")
        ipaddress.IPv4Address(f"{base}.{end}")
    except ValueError as exc:
        raise TargetRefused(f"Target {value!r} is not a valid address range") from exc
    if end < start:
        raise TargetRefused(
            f"Target {value!r}: the end of the range is before its start"
        )
    count = end - start + 1
    if count > MAX_TARGET_ADDRESSES:  # pragma: no cover - at most 256 by syntax
        raise TargetRefused(f"Target range '{value}' is too large")
    _check_addresses((first + i for i in range(count)), value, allowlist)


def host_of_host_port_or_url(value: str) -> str:
    """The host pki_certificate_manager connects to, taken the way it does."""
    host = value
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0]
    if ":" in host:
        host = host.partition(":")[0]
    return host


def registry_of_image(value: str) -> Optional[str]:
    """The registry host of an image reference, or None for Docker Hub.

    The rule of the Docker reference grammar, which trivy follows
    (go-containerregistry): the part before the first "/" is a registry
    when it contains "." or ":" or is "localhost"; otherwise the image is
    on Docker Hub. A port is dropped.
    """
    first, slash, _rest = value.partition("/")
    if not slash:
        return None
    if "." in first or ":" in first or first == "localhost":
        return first.partition(":")[0]
    return None


def check_value(kind: TargetKind, value: object, allowlist: Allowlist) -> None:
    """Check one value of a declared target field. Raise TargetRefused."""
    if value is None or value == "":
        return
    if not isinstance(value, str):
        raise TargetRefused(f"Target {value!r} must be a string")
    _reject_space_and_control(value)
    if kind is TargetKind.HOST:
        check_host(value, allowlist)
    elif kind is TargetKind.HOST_PORT_OR_URL:
        check_host(host_of_host_port_or_url(value), allowlist)
    elif kind is TargetKind.IP:
        check_ip(value, allowlist)
    elif kind is TargetKind.IP_OR_CIDR:
        check_cidr(value, allowlist)
    elif kind is TargetKind.NETWORK:
        check_network(value, allowlist)
    elif kind is TargetKind.IMAGE_REF:
        registry = registry_of_image(value)
        if registry is not None:
            check_host(registry, allowlist)
    else:  # pragma: no cover - every kind is handled above
        raise TargetRefused(f"Unknown target kind {kind!r}")


def check_network_targets(
    tool_name: str, input_obj, allowlist: Optional[Allowlist] = None
) -> None:
    """Check the declared network target fields of one tool input."""
    fields = NETWORK_TARGET_FIELDS.get(tool_name)
    if not fields:
        return
    if allowlist is None:
        allowlist = current_allowlist()
    for field, kind in fields.items():
        value = getattr(input_obj, field, None)
        if isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                check_value(kind, item, allowlist)
        else:
            check_value(kind, value, allowlist)


def enforce_target_policy(tool_name: str, input_obj) -> None:
    """Every target check that runs before a tool does. Raise TargetRefused.

    The URL guard first (every URL the input carries), then the network
    target policy for the tool's declared target fields. Called by the
    synchronous endpoint, the Celery task and the orchestrator's steps.
    """
    try:
        InputSanitizer.validate_request_urls(input_obj)
    except ValueError as exc:
        raise TargetRefused(str(exc)) from exc
    check_network_targets(tool_name, input_obj)
