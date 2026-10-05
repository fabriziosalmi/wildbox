"""guardian's own request throttle, from the environment (#645).

``GUARDIAN_RATE_LIMIT_USER`` is the number of requests one user may make to
guardian per period: ``1000/hour`` unless set. It is a second, narrower
limit under the gateway's ``RATE_LIMIT_PER_HOUR``, which is per team: one
member of a team cannot use up guardian for the others.

* ``<count>/<period>``, the period one of ``second``, ``minute``, ``hour``
  or ``day`` (``sec``, ``min`` and the first letters are accepted too), the
  count a whole number from 1 to 999,999,999: ``1000/hour``, ``20/minute``;
* ``off``: no throttle in guardian, the gateway's limit only;
* empty or unset: the default, so compose can pass ``${NAME:-}``.

Anything else raises ImproperlyConfigured when the settings load, so a typo
stops guardian at start-up. Django REST Framework reads a rate only when a
request arrives: a malformed one used to start cleanly and then answer 500
to every request.

``API_RATE_LIMIT`` is the name the variable had. It is still read when
``GUARDIAN_RATE_LIMIT_USER`` is not set, for a guardian run from its own
``.env``; docker-compose.yml never passed it, so there it had no effect.
It used to set a second rate as well, for anonymous callers, which is gone:
see apps/core/throttling.py.
"""

import os
import re

from django.core.exceptions import ImproperlyConfigured

USER_RATE_VARIABLE = "GUARDIAN_RATE_LIMIT_USER"
LEGACY_RATE_VARIABLE = "API_RATE_LIMIT"
USER_RATE_DEFAULT = "1000/hour"

# DRF takes the period from its first letter, so "hour", "h" and "hamster"
# are the same to it. Only the spellings below are accepted here.
_PERIODS = {
    "s": "second",
    "sec": "second",
    "second": "second",
    "m": "minute",
    "min": "minute",
    "minute": "minute",
    "h": "hour",
    "hour": "hour",
    "d": "day",
    "day": "day",
}
_RATE = re.compile(r"([1-9][0-9]{0,8})/([a-z]+)")


def parse_rate(value, variable):
    """The DRF rate for ``value``, or None for ``off``.

    Raises ImproperlyConfigured naming ``variable`` for anything else.
    """
    text = value.strip().lower()
    if text == "off":
        return None
    match = _RATE.fullmatch(text)
    period = _PERIODS.get(match.group(2)) if match else None
    if period is None:
        raise ImproperlyConfigured(
            f"{variable}={value!r}: expected <count>/<period> with a count from "
            "1 to 999999999 and a period of second, minute, hour or day "
            "(for example 1000/hour), or 'off'"
        )
    return f"{match.group(1)}/{period}"


def user_rate(environ=None):
    """The per-user rate as DRF reads it, or None when the throttle is off."""
    environ = os.environ if environ is None else environ
    for variable in (USER_RATE_VARIABLE, LEGACY_RATE_VARIABLE):
        value = environ.get(variable)
        if value and value.strip():
            return parse_rate(value, variable)
    return parse_rate(USER_RATE_DEFAULT, USER_RATE_VARIABLE)
