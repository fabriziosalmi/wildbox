"""What a discovery may sweep and a port scan may reach (#724, #748).

``assets/assets/discover/`` queued whatever it was given as
``network_range``: a string that is not a network was found out by the
worker, three retries later, and ``10.0.0.0/8`` was sixteen million
connection attempts in one task. A discovery rule checked that its networks
parse, and not their size (#724).

And nothing looked at where a range is (#748). ``guardian-worker`` runs
inside the stack's networks, so a team's owner or admin could sweep them:
the worker's own loopback, PostgreSQL, Redis and identity next to it, the
Docker host, a cloud provider's metadata address. The tools service has
refused such targets since 0.11.0 (#614); guardian now applies the same
policy, from the same implementation, ``open_security_shared.target_policy``:

* one sweep covers at most ``MAX_SCAN_ADDRESSES`` addresses, which is that
  module's ``MAX_TARGET_ADDRESSES`` and not a number of guardian's own;
* an internal address is not scanned: private, loopback, link-local,
  multicast, reserved, shared and cloud-metadata addresses, IPv4 and IPv6,
  an IPv4 address embedded in an IPv6 one included. A range with one such
  address in it is refused whole, however much of it is public;
* unless the operator lists the range in
  ``GUARDIAN_ALLOWED_INTERNAL_TARGETS`` (``guardian/scan_targets.py``),
  which is empty by default. A range a caller names must lie inside the
  listed ranges entirely.

guardian scans addresses only: a network in CIDR notation, or the address
of an asset. It resolves no name, so there is none to check here.

The request that asks for a discovery, the rule that schedules one and the
task that runs it all go through ``check_network``; the request for a port
scan, the scan an asset gets when it is created and the task that scans go
through ``check_address``. A target is so refused where it is typed and,
for a rule or an asset stored before the check existed (or before the
operator narrowed the list), where the scan would run.

Recording an asset is not scanning it: an asset at an internal address is
stored like any other, which is what an inventory is for. It is not port
scanned.

The ports of a scan are bounded like the addresses of a discovery (#775):
``check_port_range`` takes one port or a range of at most ``MAX_SCAN_PORTS``,
each a TCP port number, and refuses anything else before a socket is opened.
"""

import ipaddress
import re

from django.conf import settings
from open_security_shared.target_policy import (
    MAX_TARGET_ADDRESSES,
    Reason,
    TargetPolicy,
)

from guardian.scan_targets import ALLOWLIST_VARIABLE

#: The most addresses one discovery sweeps: a /22 of IPv4, a /118 of IPv6.
#: The bound the tools service puts on a scan target, from the module both
#: services share.
MAX_SCAN_ADDRESSES = MAX_TARGET_ADDRESSES

#: The most networks one discovery rule lists.
MAX_RULE_NETWORKS = 32

#: The most ports one port scan tries. A port that does not answer costs the
#: scan its connection timeout, one second, and a task has thirty minutes
#: (CELERY_TASK_TIME_LIMIT): 1,024 unanswered ports are seventeen of them.
MAX_SCAN_PORTS = 1024

#: The highest TCP port number.
MAX_PORT = 65535

# "443" or "1-1000": the digits 0 to 9 only, so that int() is never handed a
# sign, an underscore, a space inside the number or a digit of another script.
_PORT_RANGE = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")

#: What a discovery does with a host that answers: record it ("basic"), or
#: also scan its ports ("comprehensive").
SCAN_TYPES = ("basic", "comprehensive")

# What follows the subject of a refused target. It names the setting: the
# caller cannot change it, and has to know what to ask the operator for.
_INTERNAL = (
    "an internal address (private, loopback, link-local, multicast, reserved "
    "or cloud metadata). guardian scans an internal address only if the "
    f"operator of this deployment lists its range in {ALLOWLIST_VARIABLE}."
)


class NetworkRefused(ValueError):
    """A range no discovery sweeps; the message says why, for the caller."""


def scan_policy():
    """The target policy with the ranges this deployment's operator allows."""
    return TargetPolicy(settings.SCAN_ALLOWED_INTERNAL_TARGETS)


def check_network(value):
    """``(network, None)`` if a discovery may sweep ``value``, else
    ``(None, why)``.

    The refusal is a message written here, for the caller: a view or a
    serializer answers with it as it is. It is returned, not raised, so that
    no text of an exception is ever what a response is built from.
    """
    if not isinstance(value, str) or not value.strip():
        return None, (
            "A network in CIDR notation is required, for example 192.0.2.0/24."
        )
    try:
        # A zone ("fe80::%eth0/64") names an interface of the worker, which
        # is not the caller's to choose; ipaddress would take it.
        if "%" in value:
            raise ValueError(value)
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None, f"{value.strip()[:64]!r} is not a network in CIDR notation."
    refusal = scan_policy().refuse_network(network)
    if refusal is None:
        return network, None
    if refusal.reason is Reason.TOO_LARGE:
        return None, (
            f"{network} has more than {MAX_SCAN_ADDRESSES} addresses, the most one "
            "discovery sweeps (a /22 of IPv4, a /118 of IPv6). Split it into "
            "smaller networks."
        )
    if network.num_addresses == 1:
        return None, f"{network.network_address} is {_INTERNAL}"
    return None, f"{network} includes {refusal.address}, {_INTERNAL}"


def scan_network(value):
    """The network ``value`` names, if a discovery may sweep it.

    Raises NetworkRefused for anything that is not a network in CIDR
    notation (or a single address) of at most MAX_SCAN_ADDRESSES addresses,
    none of them internal unless the operator allows it. For the task that
    runs a discovery; a request is answered from ``check_network``.
    """
    network, refusal = check_network(value)
    if refusal is not None:
        raise NetworkRefused(refusal)
    return network


def check_address(value):
    """``(address, None)`` if a port scan may reach ``value``, else
    ``(None, why)``.

    ``value`` is an asset's address. As for ``check_network``, the refusal
    is a message written here and returned, not raised.
    """
    text = str(value).strip() if value is not None else ""
    if not text:
        return None, "The asset has no IP address to scan."
    try:
        # No zone here either ("fe80::1%eth0").
        if "%" in text:
            raise ValueError(text)
        address = ipaddress.ip_address(text)
    except ValueError:
        return None, f"{text[:64]!r} is not an IP address."
    if not scan_policy().allows(address):
        return None, f"{address} is {_INTERNAL}"
    return address, None


def check_port_range(value):
    """``(ports, None)`` if a port scan may try ``value``, else ``(None, why)``.

    ``value`` is one port (``"443"``) or a range with both ends (``"1-1000"``)
    of at most MAX_SCAN_PORTS ports, each from 1 to MAX_PORT. It was parsed
    with ``int`` and nothing else: ``"1-4000000000"`` was four thousand million
    connection attempts in one task, ``"0-70000"`` handed the socket ports
    that do not exist, and anything that is not a number failed the task
    with a ValueError (#775). As for ``check_address``, the refusal is a
    message written here and returned, not raised.
    """
    text = value.strip() if isinstance(value, str) else ""
    match = _PORT_RANGE.fullmatch(text)
    if match is None:
        return None, (
            "A port range is one port or two joined by a hyphen, for example "
            "443 or 1-1000."
        )
    first = int(match.group(1))
    last = int(match.group(2)) if match.group(2) is not None else first
    if not 1 <= first <= MAX_PORT or not 1 <= last <= MAX_PORT:
        return None, f"A port is a number from 1 to {MAX_PORT}."
    if first > last:
        return None, f"The port range {first}-{last} ends before it starts."
    if last - first + 1 > MAX_SCAN_PORTS:
        return None, (
            f"The port range {first}-{last} has more than {MAX_SCAN_PORTS} ports, "
            "the most one port scan tries. Split it into smaller ranges."
        )
    return range(first, last + 1), None
