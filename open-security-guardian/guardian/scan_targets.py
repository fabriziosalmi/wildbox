"""The internal ranges guardian may scan, from the environment (#748).

guardian's asset discovery and port scans connect to the addresses a team's
owner or admin names, from ``guardian-worker``, which sits inside the
stack's networks: on the flat ``wildbox`` network with every other service
in ``docker-compose.yml``, on ``data`` (PostgreSQL, Redis, identity) and
``egress`` in the production overlay. An internal address is therefore
refused (``apps/assets/networks.py``, with the policy the tools service
uses: ``open_security_shared.target_policy``) unless the operator lists it
here.

``GUARDIAN_ALLOWED_INTERNAL_TARGETS`` is a comma-separated list of CIDR
ranges and IP addresses, empty by default:

* empty or unset: no internal address is scanned. That is the default
  although scanning one's own LAN is what many deployments use guardian
  for, because no default can tell the LAN from the stack: Docker takes the
  stack's networks from the same private ranges (172.16.0.0/12 and
  192.168.0.0/16 by default), so "private addresses are allowed" would
  allow PostgreSQL, Redis and identity too. Only the operator knows which
  ranges are the ones to scan;
* ``192.168.50.0/24,10.20.0.0/16``: those ranges are scanned, and nothing
  else that is internal. A range a caller names must lie inside them
  entirely.

It is guardian's own setting. ``TOOLS_ALLOWED_INTERNAL_TARGETS`` is not
read: what the tools service may scan says nothing about guardian, whose
worker is on other networks in the production overlay, and one variable
for both would open a range to the second service as a side effect of
opening it to the first.

A host name is not an entry: guardian scans addresses, never names, so a
name would be accepted and match nothing. A CIDR range must have its host
bits zero (``10.0.0.1/8`` is a typo, not a range). Anything else raises
ImproperlyConfigured when the settings load, so a typo stops guardian and
its worker at start-up instead of leaving a lab unscanned, or a range open
that was not meant.
"""

import os

from django.core.exceptions import ImproperlyConfigured
from open_security_shared.target_policy import Allowlist, parse_allowlist

ALLOWLIST_VARIABLE = "GUARDIAN_ALLOWED_INTERNAL_TARGETS"


def allowed_internal_targets(environ=None) -> Allowlist:
    """The allowlist the environment configures; empty when unset.

    Raises ImproperlyConfigured, naming the variable and the entry, for an
    entry that is not a CIDR range or an IP address.
    """
    environ = os.environ if environ is None else environ
    try:
        return parse_allowlist(
            environ.get(ALLOWLIST_VARIABLE), ALLOWLIST_VARIABLE, names=False
        )
    except ValueError as exc:
        raise ImproperlyConfigured(str(exc)) from exc
