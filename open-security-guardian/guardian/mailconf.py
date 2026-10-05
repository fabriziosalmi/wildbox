"""What guardian needs to send an e-mail, read and checked at start-up (#705).

Three things, each of which was a way for a notification to go nowhere
without anybody noticing:

* **A mail server.** ``EMAIL_BACKEND`` defaulted to Django's console
  backend, and Compose passed guardian no mail setting at all: every e-mail
  was printed to the worker's log, a team's asset names and findings with
  it, and recorded as sent. guardian now sends by SMTP or not at all.
  ``EMAIL_HOST`` empty means there is no mail server: a notification is then
  recorded as not sent, with that reason (apps.core.notifications).
  ``EMAIL_BACKEND`` is not read.
* **The addresses.** guardian holds none: it asks identity who may be told
  about a team (``GUARDIAN_TEAM_CONTACTS_URL``), with a secret of its own
  (``GUARDIAN_CONTACTS_SECRET``). Without the secret it can only e-mail the
  addresses a team typed into an alert rule or a report schedule.
* **The public address of the dashboard**, for the links in an e-mail
  (``GUARDIAN_BASE_URL``). Unset, an e-mail carries no link: a relative
  path in an e-mail opens nothing.

A value that cannot work raises ImproperlyConfigured, so a typo stops
guardian at start-up instead of dropping e-mail later. No message here
echoes a secret.
"""

from __future__ import annotations

import os
import re
from email.utils import parseaddr
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

EMAIL_PORT_DEFAULT = 587
#: Seconds guardian waits for the mail server. Django's default is to wait
#: for ever, which would hold a worker on a server that stopped answering.
EMAIL_TIMEOUT_SECONDS = 30

BASE_URL_VARIABLE = "GUARDIAN_BASE_URL"

TEAM_CONTACTS_URL_VARIABLE = "GUARDIAN_TEAM_CONTACTS_URL"
#: identity's name on the Compose network, and its route (app/team_contacts.py).
TEAM_CONTACTS_URL_DEFAULT = "http://open-security-identity:8001/internal/team-contacts"
TEAM_CONTACTS_SECRET_VARIABLE = "GUARDIAN_CONTACTS_SECRET"
TEAM_CONTACTS_SECRET_MIN_LENGTH = 32

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")
# A host name or an IPv4 address, or an IPv6 address (two colons at least,
# so that "host:25" is not taken for one).
_HOST = re.compile(r"[A-Za-z0-9._-]+|(?:[0-9A-Fa-f]*:){2,}[0-9A-Fa-f.]*")
_ADDRESS = re.compile(r"[^@\s<>\"',;]+@[A-Za-z0-9.-]+")


def _text(environ, name):
    return (environ.get(name) or "").strip()


def _flag(environ, name):
    """True, False, or None when the variable is unset or empty."""
    value = _text(environ, name).lower()
    if not value:
        return None
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ImproperlyConfigured(f"{name}={value!r}: expected true or false")


def _http_url(environ, name, *, path_allowed):
    """An absolute http(s) URL from the environment, or '' when unset.

    No credentials, query or fragment: none of them belongs in an address
    guardian writes into an e-mail or sends a secret to.
    """
    value = _text(environ, name)
    if not value:
        return ""
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name}: not a URL ({exc})") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ImproperlyConfigured(
            f"{name}={value!r}: expected an absolute URL, http:// or https:// "
            "and a host name"
        )
    if parts.username or parts.password or "@" in parts.netloc:
        raise ImproperlyConfigured(f"{name}: a URL with credentials is not accepted")
    if parts.query or parts.fragment:
        raise ImproperlyConfigured(
            f"{name}={value!r}: a query string or a fragment is not accepted"
        )
    if any(character.isspace() for character in value):
        raise ImproperlyConfigured(f"{name}={value!r}: a URL has no white space")
    if port is not None and not 1 <= port <= 65535:
        raise ImproperlyConfigured(f"{name}={value!r}: the port is out of range")
    if not path_allowed and parts.path not in ("", "/"):
        raise ImproperlyConfigured(
            f"{name}={value!r}: expected the address the dashboard is served "
            "at, scheme and host only (https://wildbox.example.com), not a path"
        )
    return value


def public_base_url(environ=None):
    """The address users open the dashboard at, without a trailing slash.

    '' when ``GUARDIAN_BASE_URL`` is unset: e-mails then carry no link. It
    is what a link in an e-mail starts with, so it has to be an address a
    browser can open: absolute, http or https, and nothing after the host
    (the dashboard is served at the root of the gateway).
    """
    environ = os.environ if environ is None else environ
    return _http_url(environ, BASE_URL_VARIABLE, path_allowed=False).rstrip("/")


def mail_settings(environ=None):
    """Django's e-mail settings, from the environment.

    ``EMAIL_HOST`` empty: no mail server, and nothing else is read. Set, it
    needs a sender (``DEFAULT_FROM_EMAIL``): there is no default one, since
    an address under somebody else's domain is refused by the server or
    lands in a spam folder.
    """
    environ = os.environ if environ is None else environ
    settings = {
        # Always SMTP: the console backend prints a team's data to the log
        # and reports it sent.
        "EMAIL_BACKEND": "django.core.mail.backends.smtp.EmailBackend",
        "EMAIL_HOST": "",
        "EMAIL_PORT": EMAIL_PORT_DEFAULT,
        "EMAIL_USE_TLS": False,
        "EMAIL_USE_SSL": False,
        "EMAIL_HOST_USER": "",
        "EMAIL_HOST_PASSWORD": "",
        "EMAIL_TIMEOUT": EMAIL_TIMEOUT_SECONDS,
        "DEFAULT_FROM_EMAIL": "",
    }
    host = _text(environ, "EMAIL_HOST")
    if not host:
        return settings
    if not _HOST.fullmatch(host):
        raise ImproperlyConfigured(
            f"EMAIL_HOST={host!r}: expected the mail server's host name or "
            "address alone; the port goes in EMAIL_PORT"
        )

    port = _text(environ, "EMAIL_PORT") or str(EMAIL_PORT_DEFAULT)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ImproperlyConfigured(f"EMAIL_PORT={port!r}: expected 1 to 65535")

    use_ssl = _flag(environ, "EMAIL_USE_SSL") or False
    use_tls = _flag(environ, "EMAIL_USE_TLS")
    if use_tls is None:
        # STARTTLS unless the connection is TLS from the start.
        use_tls = not use_ssl
    if use_tls and use_ssl:
        raise ImproperlyConfigured(
            "EMAIL_USE_TLS and EMAIL_USE_SSL are both true: a server takes "
            "STARTTLS (usually port 587) or TLS from the start (usually 465), "
            "not both"
        )

    user = _text(environ, "EMAIL_HOST_USER")
    # Not stripped: a password may end with a space. Never echoed.
    password = environ.get("EMAIL_HOST_PASSWORD") or ""
    if bool(user) != bool(password):
        raise ImproperlyConfigured(
            "EMAIL_HOST_USER and EMAIL_HOST_PASSWORD go together: set both, or "
            "neither for a server that takes mail without a login"
        )
    if user and not (use_tls or use_ssl):
        raise ImproperlyConfigured(
            "EMAIL_HOST_USER is set while EMAIL_USE_TLS and EMAIL_USE_SSL are "
            "both false: the password would cross the network in clear text"
        )

    sender = _text(environ, "DEFAULT_FROM_EMAIL")
    # One address: parseaddr reads the first of a list and drops the rest.
    if not _ADDRESS.fullmatch(parseaddr(sender)[1]) or any(
        character in sender for character in ",;\r\n"
    ):
        raise ImproperlyConfigured(
            "DEFAULT_FROM_EMAIL is required with EMAIL_HOST: the address "
            "guardian sends from, 'guardian@example.com' or "
            "'Wildbox Guardian <guardian@example.com>'"
        )

    settings.update(
        EMAIL_HOST=host,
        EMAIL_PORT=int(port),
        EMAIL_USE_TLS=use_tls,
        EMAIL_USE_SSL=use_ssl,
        EMAIL_HOST_USER=user,
        EMAIL_HOST_PASSWORD=password,
        DEFAULT_FROM_EMAIL=sender,
    )
    return settings


def team_contacts_settings(environ=None):
    """(URL, secret) guardian asks identity for a team's contacts with.

    The secret is None when ``GUARDIAN_CONTACTS_SECRET`` is unset: guardian
    then asks nothing. It is not the gateway's secret and must not be: the
    worker that holds it reaches outside the stack, and the gateway's secret
    lets its holder speak as any user to every service.
    """
    environ = os.environ if environ is None else environ
    url = (
        _http_url(environ, TEAM_CONTACTS_URL_VARIABLE, path_allowed=True)
        or TEAM_CONTACTS_URL_DEFAULT
    )
    secret = environ.get(TEAM_CONTACTS_SECRET_VARIABLE) or ""
    if not secret.strip():
        return url, None
    if len(secret) < TEAM_CONTACTS_SECRET_MIN_LENGTH:
        raise ImproperlyConfigured(
            f"{TEAM_CONTACTS_SECRET_VARIABLE} must be at least "
            f"{TEAM_CONTACTS_SECRET_MIN_LENGTH} characters; generate one with "
            "'openssl rand -hex 32' and give identity the same value"
        )
    if secret == (environ.get("GATEWAY_INTERNAL_SECRET") or None):
        raise ImproperlyConfigured(
            f"{TEAM_CONTACTS_SECRET_VARIABLE} must not be the value of "
            "GATEWAY_INTERNAL_SECRET: generate a separate one with "
            "'openssl rand -hex 32'"
        )
    return url, secret
