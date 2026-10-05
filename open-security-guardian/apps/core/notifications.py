"""Who guardian e-mails about a team's data, and whether the e-mail went (#705).

guardian's e-mails had no address to go to. Its users are identity's,
mirrored by id alone (apps.core.gateway_middleware), so the SLA and
assignment e-mails addressed to ``assigned_to.email`` reached nobody;
compliance notifications named no recipient at all; and with no mail server
configured, which is how Compose started guardian, Django's console backend
printed each message to the log and guardian recorded it as sent.

Every e-mail guardian sends about a team's data now goes through
``notify_team``, which decides three things in one place.

**Who.** In this order:

1. the addresses the team itself typed into the alert rule or the report
   schedule concerned, if any;
2. the member the notification is for (a vulnerability's assignee), while
   guardian still counts them as a member of the team (#676) *and* identity
   says they have an active account in it;
3. otherwise the team's owners and admins, as identity lists them now.

Never a platform-wide address (#678): there is none to fall back to.

**Where the addresses come from.** From identity, when the e-mail is about
to be sent (``POST /internal/team-contacts``), not from a copy. guardian
could have mirrored an address from a header the gateway forwards, as it
mirrors the user's id; that was weighed and not done:

* a copy is as old as the member's last request to guardian. A member who
  changed their address (#569), was demoted, or whose account was
  deactivated would have gone on receiving their team's findings at the old
  address until they next opened guardian, or for the whole membership
  window if they never did. identity's answer is true when it is given;
* an owner who never opened guardian would be unknown to it, and a team
  whose admins do not use guardian would have nobody to tell;
* the address would have travelled in a header on every request to every
  service behind the gateway, and sat in the gateway's cache.

So no address is stored on a user here, and none is logged: only counts.
What is kept is the record of where a notification was addressed, on the
row a team reads (an alert rule's notifications).

The worker asks with a secret of its own, ``GUARDIAN_CONTACTS_SECRET``, not
the gateway's: see open-security-identity/app/team_contacts.py. identity's
answer is checked again here, entry by entry, before any of it is used: it
is where a team's data is about to be sent.

**Whether it went.** A notification is *sent* when the mail server accepted
it. Otherwise it is *not sent*, with the reason, and the caller records
that where the team can read it: no mail server configured, nobody to
tell, identity not reachable, the server refusing. ``Delivery.retry`` says
whether trying again later can help.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from html import unescape
from typing import Iterable, Optional, Sequence

import requests
from apps.core.tenancy import is_current_member, normalize_team_id
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

#: The header the worker presents GUARDIAN_CONTACTS_SECRET in; identity's
#: app/team_contacts.py names the same (tests/scripts pins the two).
CONTACTS_SECRET_HEADER = "X-Guardian-Contacts-Secret"
#: (connect, read) seconds. identity is on the same network.
CONTACTS_TIMEOUT = (3, 5)
#: The most users identity answers for in one request.
CONTACTS_MAX_USER_IDS = 200

ROLE_OWNER = "owner"
ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
ROLES = (ROLE_OWNER, ROLE_ADMIN, ROLE_MEMBER)
#: Who receives what has no recipient of its own.
DEFAULT_RECIPIENT_ROLES = (ROLE_OWNER, ROLE_ADMIN)

#: Who a notification was addressed to.
AUDIENCE_NAMED = "named"
AUDIENCE_MEMBER = "member"
AUDIENCE_ADMINS = "owners_and_admins"
AUDIENCE_NOBODY = ""

# Why a notification was not sent. Read by people, and matched by the SLA
# check to tell a standing condition from one worth another try.
NO_MAIL_SERVER = "no mail server is configured"
NO_TEAM = "the row belongs to no team, so there is nobody to tell"
NO_CONTACTS_SECRET = (
    "guardian is not set up to ask identity for addresses (GUARDIAN_CONTACTS_SECRET)"
)
IDENTITY_UNAVAILABLE = "identity could not be asked for the addresses"
IDENTITY_NOT_UNDERSTOOD = "identity's answer about the addresses was not understood"
NO_MEMBER_ADDRESS = "the member has no active account with an address in the team"
NO_DEFAULT_RECIPIENTS = (
    "the team has no owner or admin with an active account and an address"
)
DELIVERY_FAILED = "delivery failed"


@dataclass(frozen=True)
class Contact:
    """A member of a team that may be e-mailed about it, as identity says."""

    user_id: str
    email: str
    role: str


class ContactsUnavailable(Exception):
    """identity gave no usable answer; ``retry`` if asking again can help."""

    def __init__(self, reason, retry=False):
        super().__init__(reason)
        self.reason = reason
        self.retry = retry


@dataclass(frozen=True)
class Delivery:
    """What became of one notification."""

    sent: bool
    #: The addresses it was addressed to, sent or not.
    recipients: tuple = ()
    audience: str = AUDIENCE_NOBODY
    #: Why it was not sent; empty when it was.
    reason: str = ""
    #: Not sent, and trying again later can help (identity or the mail
    #: server did not answer). False for what only a person can change.
    retry: bool = False

    @property
    def outcome(self):
        return "sent" if self.sent else f"not sent ({self.reason})"


# --- the mail server -----------------------------------------------------------


def mail_problem():
    """Why guardian cannot send e-mail at all, or '' if it can.

    ``EMAIL_HOST`` empty is a deployment without a mail server. It used to
    have the console backend instead, which "sent" everything to the log.
    """
    return "" if settings.EMAIL_HOST else NO_MAIL_SERVER


# --- identity: who may be told about a team ------------------------------------


def _session():
    session = requests.Session()
    # Not through a proxy from the environment: the worker may have one for
    # what it fetches outside, and this request carries a secret.
    session.trust_env = False
    return session


def _ask_identity(payload):
    """POST one question to identity's team-contacts route; its JSON answer."""
    secret = settings.TEAM_CONTACTS_SECRET
    if not secret:
        raise ContactsUnavailable(NO_CONTACTS_SECRET)
    try:
        with _session() as session:
            response = session.post(
                settings.TEAM_CONTACTS_URL,
                json=payload,
                headers={CONTACTS_SECRET_HEADER: secret},
                timeout=CONTACTS_TIMEOUT,
                # A redirect is not identity's answer, and following one
                # would send the secret somewhere else.
                allow_redirects=False,
            )
    except requests.RequestException as exc:
        logger.error("Team contacts: identity not reached (%s)", type(exc).__name__)
        raise ContactsUnavailable(IDENTITY_UNAVAILABLE, retry=True) from exc
    if response.status_code != 200:
        logger.error("Team contacts: identity answered %s", response.status_code)
        # 5xx: identity is starting, or has no secret yet. 4xx: the secrets
        # differ or the request is not one it accepts; a person fixes that.
        raise ContactsUnavailable(
            IDENTITY_UNAVAILABLE, retry=response.status_code >= 500
        )
    try:
        return response.json()
    except ValueError as exc:
        raise ContactsUnavailable(IDENTITY_NOT_UNDERSTOOD) from exc


def _checked_contacts(body, team_id, user_ids, roles):
    """identity's answer as Contacts, or ContactsUnavailable.

    Nothing in it is used unchecked. An answer about another team, or an
    entry for a user or a role that was not asked for, refuses the whole
    answer: a notification not sent, rather than a team's data sent on an
    answer that is wrong somewhere. An entry whose address guardian cannot
    write to is left out, as a member without one.
    """
    wanted_users = {str(user_id) for user_id in user_ids} if user_ids else None
    wanted_roles = set(roles) if roles else None
    try:
        if not isinstance(body, dict) or set(body) != {"team_id", "contacts"}:
            raise ValueError("unexpected fields")
        if uuid.UUID(str(body["team_id"])) != team_id:
            raise ValueError("another team")
        if not isinstance(body["contacts"], list):
            raise ValueError("contacts is not a list")
        contacts, unusable = [], 0
        for entry in body["contacts"]:
            if not isinstance(entry, dict) or set(entry) != {
                "user_id",
                "email",
                "role",
            }:
                raise ValueError("unexpected contact fields")
            user_id = str(uuid.UUID(str(entry["user_id"])))
            role, email = entry["role"], entry["email"]
            if role not in ROLES or not isinstance(email, str):
                raise ValueError("unknown role or address type")
            if wanted_users is not None and user_id not in wanted_users:
                raise ValueError("a user that was not asked for")
            if wanted_roles is not None and role not in wanted_roles:
                raise ValueError("a role that was not asked for")
            if not _is_one_address(email):
                unusable += 1
                continue
            contacts.append(Contact(user_id=user_id, email=email, role=role))
    except (ValueError, TypeError, KeyError) as exc:
        logger.error("Team contacts: answer refused (%s)", exc)
        raise ContactsUnavailable(IDENTITY_NOT_UNDERSTOOD) from exc
    if unusable:
        logger.warning(
            "Team contacts: %d member(s) of team %s have an address guardian "
            "cannot write to",
            unusable,
            team_id,
        )
    return contacts


def _is_one_address(email):
    """True for one plain address: what may go in a To header."""
    if any(character in email for character in '\r\n,;<>" '):
        return False
    try:
        validate_email(email)
    except ValidationError:
        return False
    return True


def team_contacts(team_id, *, user_ids=None, roles=None):
    """The members of ``team_id`` identity says may be e-mailed about it.

    Either ``user_ids`` (identity's user ids) or ``roles``. Active accounts
    in that team only; identity decides, and the answer is checked again
    here. Raises ContactsUnavailable when there is no answer to trust.
    """
    team_id = normalize_team_id(team_id)
    if team_id is None:
        raise ContactsUnavailable(NO_TEAM)
    if bool(user_ids) == bool(roles):
        raise ValueError("team_contacts takes user_ids or roles")
    payload = {"team_id": str(team_id)}
    if user_ids:
        user_ids = sorted({str(uuid.UUID(str(user_id))) for user_id in user_ids})
        if len(user_ids) > CONTACTS_MAX_USER_IDS:
            raise ValueError("too many users in one question")
        payload["user_ids"] = user_ids
    else:
        roles = sorted(set(roles))
        payload["roles"] = roles
    return _checked_contacts(_ask_identity(payload), team_id, user_ids, roles)


def _identity_id(user):
    """identity's id of a mirrored user: its username, when that is a UUID."""
    try:
        return str(uuid.UUID(str(user.username)))
    except (ValueError, AttributeError, TypeError):
        return None


class TeamDirectory:
    """identity's answers, remembered for the length of one task.

    A sweep over many rows asks once per team and member, not once per row.
    Nothing outlives the task: the next one asks again, so an address that
    changed, a role that was taken away or an account that was deactivated
    is not used a sweep later.
    """

    def __init__(self):
        self._members = {}
        self._admins = {}

    def member_address(self, team_id, user):
        """The address of ``user`` as a member of ``team_id``, or None.

        None unless guardian still counts them as a member of the team
        (#676) and identity says they have an active account in it. A row
        without a team has no team to be a member of.
        """
        team_id = normalize_team_id(team_id)
        if user is None or team_id is None:
            return None
        identity_id = _identity_id(user)
        if identity_id is None or not is_current_member(user, team_id):
            return None
        key = (team_id, identity_id)
        if key not in self._members:
            contacts = team_contacts(team_id, user_ids=[identity_id])
            self._members[key] = contacts[0].email if contacts else None
        return self._members[key]

    def default_addresses(self, team_id):
        """The addresses of the team's owners and admins, as identity lists them."""
        team_id = normalize_team_id(team_id)
        if team_id is None:
            raise ContactsUnavailable(NO_TEAM)
        if team_id not in self._admins:
            contacts = team_contacts(team_id, roles=DEFAULT_RECIPIENT_ROLES)
            self._admins[team_id] = _unique(contact.email for contact in contacts)
        return self._admins[team_id]


def _unique(addresses: Iterable[str]):
    seen, unique = set(), []
    for address in addresses:
        address = (address or "").strip()
        if address and address.lower() not in seen:
            seen.add(address.lower())
            unique.append(address)
    return tuple(unique)


# --- links ---------------------------------------------------------------------

#: The dashboard pages an e-mail may link to: what the e-mail is about, and
#: the route that shows it (open-security-dashboard/src/app/<route>/page.tsx;
#: tests/unit/test_notification_links.py fails for a route that is not
#: there). The dashboard has a page per kind of thing, not per row: the link
#: opens the team's list, and the e-mail names the row. A kind without a
#: page here gets no link.
DASHBOARD_ROUTES = {
    "vulnerabilities": "/vulnerabilities",
}

#: The path the gateway serves guardian's API under (wildbox_gateway.conf),
#: for an e-mail that names an API route.
GATEWAY_API_PREFIX = "/api/v1/guardian"


def dashboard_link(kind):
    """The address of the dashboard page for ``kind``, or None.

    None when ``GUARDIAN_BASE_URL`` is unset (a relative path in an e-mail
    opens nothing) and for a kind the dashboard has no page for.
    """
    route = DASHBOARD_ROUTES.get(kind)
    if not settings.BASE_URL or not route:
        return None
    return f"{settings.BASE_URL}{route}"


def gateway_api_path(guardian_path):
    """guardian's ``/api/v1/<x>`` as a client of the gateway writes it."""
    from apps.core.pagination import API_ROOT

    if not guardian_path.startswith(API_ROOT + "/"):
        raise ValueError(f"{guardian_path!r} is not a path of guardian's API")
    return GATEWAY_API_PREFIX + guardian_path[len(API_ROOT) :]


def gateway_api_url(guardian_path):
    """The same, in full when GUARDIAN_BASE_URL is set, else the path alone."""
    return f"{settings.BASE_URL}{gateway_api_path(guardian_path)}"


# --- sending --------------------------------------------------------------------


def _resolve(team_id, named, member, fallback, directory):
    """(addresses, audience, reason, retry) for one notification."""
    named = _unique(named or ())
    if named:
        return named, AUDIENCE_NAMED, "", False
    if normalize_team_id(team_id) is None:
        return (), AUDIENCE_NOBODY, NO_TEAM, False
    try:
        if member is not None:
            address = directory.member_address(team_id, member)
            if address:
                return (address,), AUDIENCE_MEMBER, "", False
            if not fallback:
                return (), AUDIENCE_NOBODY, NO_MEMBER_ADDRESS, False
        elif not fallback:
            return (), AUDIENCE_NOBODY, NO_MEMBER_ADDRESS, False
        addresses = directory.default_addresses(team_id)
    except ContactsUnavailable as exc:
        return (), AUDIENCE_NOBODY, exc.reason, exc.retry
    if not addresses:
        return (), AUDIENCE_NOBODY, NO_DEFAULT_RECIPIENTS, False
    return addresses, AUDIENCE_ADMINS, "", False


def notify_team(
    team_id,
    subject,
    text,
    html=None,
    *,
    named: Optional[Sequence[str]] = None,
    member=None,
    fallback=True,
    directory: Optional[TeamDirectory] = None,
    kind="general",
):
    """E-mail one notification about ``team_id``'s data; what became of it.

    ``named``: the addresses the team typed into the rule or schedule
    concerned. ``member``: the mirrored user the notification is for.
    ``fallback``: tell the team's owners and admins when neither gives an
    address; False for a notification that is only meaningful to the member
    (an assignment). ``team_id`` None is a row written before guardian kept
    a team: it has no owners and admins, and only ``named`` can address it.

    Never raises for a notification that could not be sent: the Delivery
    says so, and why.
    """
    subject = " ".join(str(subject).split())
    recipients, audience, reason, retry = _resolve(
        team_id, named, member, fallback, directory or TeamDirectory()
    )
    # No mail server is the reason that matters when there is none, whoever
    # the notification was for.
    problem = mail_problem() or reason
    if problem:
        logger.warning(
            "Notification not sent (%s), %s: %s [%d recipient(s)]",
            kind,
            problem,
            subject,
            len(recipients),
        )
        return Delivery(
            sent=False,
            recipients=recipients,
            audience=audience,
            reason=problem,
            retry=retry and problem == reason,
        )

    message = EmailMultiAlternatives(
        subject=subject,
        body=text,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=list(recipients),
    )
    if html:
        message.attach_alternative(html, "text/html")
    try:
        accepted = message.send(fail_silently=False)
    except Exception as exc:  # noqa: BLE001 - recorded as not sent, never raised
        # The class only: a server's refusal can quote the addresses.
        logger.error(
            "Notification not sent (%s), delivery failed with %s: %s",
            kind,
            type(exc).__name__,
            subject,
        )
        accepted = 0
    if not accepted:
        return Delivery(
            sent=False,
            recipients=recipients,
            audience=audience,
            reason=DELIVERY_FAILED,
            retry=True,
        )
    logger.info(
        "Notification sent (%s): %s to %d recipient(s)", kind, subject, len(recipients)
    )
    return Delivery(sent=True, recipients=recipients, audience=audience)


def notify_team_from_template(team_id, subject, template, context, **kwargs):
    """``notify_team`` with an HTML template: the text part is its text."""
    html = render_to_string(template, context)
    return notify_team(team_id, subject, _as_text(html), html, **kwargs)


def _as_text(html):
    lines = (line.strip() for line in unescape(strip_tags(html)).splitlines())
    return "\n".join(line for line in lines if line) + "\n"
