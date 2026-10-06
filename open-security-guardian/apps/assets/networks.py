"""What a discovery may sweep (#724).

``assets/assets/discover/`` queued whatever it was given as
``network_range``: a string that is not a network was found out by the
worker, three retries later, and ``10.0.0.0/8`` was sixteen million
connection attempts in one task. A discovery rule checked that its networks
parse, and not their size.

One sweep covers at most ``MAX_SCAN_ADDRESSES`` addresses, the bound the
tools service puts on a scan target (``MAX_TARGET_ADDRESSES`` in
open-security-tools/app/target_policy.py: its network scanner sweeps no
more). The request that asks for a discovery, the rule that schedules one
and the task that runs it all go through ``scan_network``, so a range is
refused where it is typed and, for a rule stored before the check existed,
where it would run.
"""

import ipaddress

#: The most addresses one discovery sweeps: a /22 of IPv4, a /118 of IPv6.
MAX_SCAN_ADDRESSES = 1024

#: The most networks one discovery rule lists.
MAX_RULE_NETWORKS = 32

#: What a discovery does with a host that answers: record it ("basic"), or
#: also scan its ports ("comprehensive").
SCAN_TYPES = ("basic", "comprehensive")


class NetworkRefused(ValueError):
    """A range no discovery sweeps; the message says why, for the caller."""


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
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None, f"{value.strip()[:64]!r} is not a network in CIDR notation."
    if network.num_addresses > MAX_SCAN_ADDRESSES:
        return None, (
            f"{network} has more than {MAX_SCAN_ADDRESSES} addresses, the most one "
            "discovery sweeps (a /22 of IPv4, a /118 of IPv6). Split it into "
            "smaller networks."
        )
    return network, None


def scan_network(value):
    """The network ``value`` names, if a discovery may sweep it.

    Raises NetworkRefused for anything that is not a network in CIDR
    notation (or a single address) of at most MAX_SCAN_ADDRESSES addresses.
    For the task that runs a discovery; a request is answered from
    ``check_network``.
    """
    network, refusal = check_network(value)
    if refusal is not None:
        raise NetworkRefused(refusal)
    return network
