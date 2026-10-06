"""The origins a browser may call guardian from, from the environment (#665).

``docker-compose.prod.yml`` has always passed the deployment's
``CORS_ORIGINS`` to guardian as ``CORS_ALLOWED_ORIGINS``, and the list was
written in ``guardian/settings.py``: the value changed nothing. A production
guardian allowed the development origins below, with credentials, and not
the one the operator had named.

``CORS_ALLOWED_ORIGINS`` is now read:

* unset: the development origins, for a guardian run from a checkout or in
  the development stack, which passes nothing;
* set, a comma-separated list of origins (``https://dashboard.example.com``):
  exactly those. A trailing slash is dropped;
* set and empty: none. That is the right value behind the gateway, where the
  dashboard calls guardian on the dashboard's own origin and no request is
  cross-origin.

An entry that is not an origin (``*``, a host with no scheme, a URL with a
path) raises ImproperlyConfigured when the settings load, naming the entry,
so guardian stops at start-up rather than allowing something other than
what was written. A wildcard is refused on purpose: guardian answers with
``Access-Control-Allow-Credentials``.
"""

from urllib.parse import urlsplit

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


def _origin(entry):
    """``entry`` as an origin, or raise ImproperlyConfigured naming it."""
    text = entry[:-1] if entry.endswith("/") else entry
    try:
        parts = urlsplit(text)
        valid = (
            parts.scheme in ("http", "https")
            and bool(parts.hostname)
            and not (parts.path or parts.query or parts.fragment)
            and parts.username is None
            and "*" not in text
        )
        # .port raises ValueError for a port that is not a number.
        valid = valid and (parts.port is None or parts.port > 0)
    except ValueError:
        valid = False
    if not valid:
        raise ImproperlyConfigured(
            f"{VARIABLE}: {entry!r} is not an origin. Write each one as "
            "scheme://host or scheme://host:port (https://dashboard.example.com), "
            "separated by commas; leave the variable empty to allow no "
            "cross-origin request."
        )
    return text


def allowed_origins(value):
    """The list for django-cors-headers' CORS_ALLOWED_ORIGINS.

    ``value`` is the variable as the environment has it: None when unset.
    """
    if value is None:
        return list(DEVELOPMENT_ORIGINS)
    origins = []
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        origin = _origin(entry)
        if origin not in origins:
            origins.append(origin)
    return origins
