"""The origins a browser may call guardian from, from the environment (#665).

``docker-compose.prod.yml`` has always passed the deployment's
``CORS_ORIGINS`` to guardian as ``CORS_ALLOWED_ORIGINS``, and the list was
written in ``guardian/settings.py``: the value changed nothing. A production
guardian allowed the development origins below, with credentials, and not
the one the operator had named.

``CORS_ALLOWED_ORIGINS`` is now read, by the grammar the gateway reads
``CORS_ORIGINS`` with (``open-security-gateway/nginx/lua/cors.lua``,
``parse_origins``), because under the production overlay the two are one
value and a value the gateway starts on must not stop guardian:

* a comma-separated list of origins (``https://a.example.com,
  https://b.example.com``): entries are trimmed, empty ones dropped;
* or a JSON list of strings (``["https://a.example.com"]``), the other form
  the gateway and identity accept. A value that starts with ``[`` is read as
  JSON and nothing else: one that is not a JSON list is refused. ``[]``
  allows nobody;
* empty, or blank: nobody. That is the right value behind the gateway, where
  the dashboard calls guardian on the dashboard's own origin and no request
  is cross-origin.

An origin is a scheme (``http`` or ``https``), a host name or address and an
optional port, as a browser sends it: no path, no trailing slash, no user, no
wildcard, not ``null``. It is kept in lower case. The gateway refuses a
trailing slash too, so the two do not differ on it. An entry that is not an
origin raises ImproperlyConfigured when the settings load, naming the entry,
so guardian stops at start-up rather than allowing something other than what
was written. A wildcard is refused on purpose: guardian answers with
``Access-Control-Allow-Credentials``.

One difference from the gateway, for a variable that is not set at all: the
gateway then allows nobody, and guardian the development origins below, for
a guardian run from a checkout or in the development stack, which passes
nothing. The production overlay always sets the variable.
"""

import json
import re

from django.core.exceptions import ImproperlyConfigured

VARIABLE = "CORS_ALLOWED_ORIGINS"

DEVELOPMENT_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:80",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1",
)

# cors.lua's normalize_origin, pattern for pattern: a host of letters,
# digits, dots and hyphens, or an IPv6 literal, and a port of one to five
# digits.
_HOST = re.compile(r"https?://([a-z0-9.-]+)(?::[0-9]{1,5})?")
_IPV6 = re.compile(r"https?://\[[0-9a-f:]+\](?::[0-9]{1,5})?")
# What Lua's %s matches, which is what the gateway trims.
_BLANK = " \t\n\v\f\r"
_FORMS = (
    "Write origins such as https://dashboard.example.com (scheme, host and "
    "optional port; no path, no trailing slash, no wildcard), separated by "
    'commas or as a JSON list (["https://dashboard.example.com"]); leave '
    "the variable empty to allow no cross-origin request."
)


def _origin(entry):
    """``entry`` as an origin in lower case, or raise naming it."""
    if isinstance(entry, str):
        origin = entry.lower()
        host = _HOST.fullmatch(origin)
        if host:
            name = host.group(1)
            if name[0] not in ".-" and name[-1] not in ".-" and ".." not in name:
                return origin
        elif _IPV6.fullmatch(origin):
            return origin
    shown = entry if isinstance(entry, str) else json.dumps(entry)
    raise ImproperlyConfigured(f"{VARIABLE}: {shown[:80]!r} is not an origin. {_FORMS}")


def _entries(value):
    """The entries of the variable, before any of them is checked."""
    if value.lstrip(_BLANK).startswith("["):
        try:
            decoded = json.loads(value)
        except ValueError:
            decoded = None
        if not isinstance(decoded, list):
            raise ImproperlyConfigured(
                f"{VARIABLE} starts like a JSON list and is not one. {_FORMS}"
            )
        return decoded
    trimmed = (entry.strip(_BLANK) for entry in value.split(","))
    return [entry for entry in trimmed if entry]


def allowed_origins(value):
    """The list for django-cors-headers' CORS_ALLOWED_ORIGINS.

    ``value`` is the variable as the environment has it: None when unset.
    """
    if value is None:
        return list(DEVELOPMENT_ORIGINS)
    if not value.strip(_BLANK):
        return []
    origins = []
    for entry in _entries(value):
        origin = _origin(entry)
        if origin not in origins:
            origins.append(origin)
    return origins
