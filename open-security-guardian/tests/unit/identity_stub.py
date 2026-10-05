"""identity's ``POST /internal/team-contacts``, stood in for guardian's tests (#705).

guardian asks identity who may be e-mailed about a team
(apps.core.notifications). The unit tests reach no network, so this answers
in identity's place, at the HTTP layer: guardian's own code builds the
request and checks the answer, as in production.

It answers as identity's route does (open-security-identity/app/
team_contacts.py): members of the team asked about, with an active account
and an address, selected by user id or by role, and nothing without the
secret. ``tests/shared/team_contacts_vectors.json`` holds cases both sides
run, identity's route in its own unit tests and this stand-in in
``test_identity_stub.py``, so the two cannot drift apart unnoticed.
"""

import uuid

from apps.core.notifications import CONTACTS_SECRET_HEADER
from django.contrib.auth.models import User

SECRET = "contacts-secret-for-the-unit-tests-0123456789"
URL = "http://identity.test.invalid:8001/internal/team-contacts"
ROLES = ("owner", "admin", "member")


class Response:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body


class Identity:
    """The accounts and memberships identity holds, and the questions it got."""

    def __init__(self):
        self.memberships = []
        self.asked = []
        #: Set to an exception to raise, or a Response to answer with,
        #: instead of answering: identity down, or answering nonsense.
        self.fault = None

    # --- what identity knows ---------------------------------------------------

    def add(self, team_id, user_id, email, role="member", active=True):
        self.memberships.append(
            {
                "team_id": str(team_id),
                "user_id": str(user_id),
                "email": email,
                "role": role,
                "active": active,
            }
        )

    def member(self, team_id, email, role="member", active=True, seen=True):
        """A member of ``team_id`` in identity, mirrored in guardian.

        ``seen`` False is a member who never called guardian: identity
        knows them, guardian has no membership row for them.
        """
        from apps.core.models import TeamMembership

        user = User.objects.create(username=str(uuid.uuid4()))
        if seen:
            TeamMembership.objects.create(team_id=team_id, user=user)
        self.add(team_id, user.username, email, role=role, active=active)
        return user

    def _of(self, user):
        return [row for row in self.memberships if row["user_id"] == user.username]

    def change_address(self, user, email):
        for row in self._of(user):
            row["email"] = email

    def change_role(self, user, team_id, role):
        for row in self._of(user):
            if row["team_id"] == str(team_id):
                row["role"] = role

    def deactivate(self, user):
        for row in self._of(user):
            row["active"] = False

    def remove(self, user, team_id):
        self.memberships = [
            row
            for row in self.memberships
            if not (row["user_id"] == user.username and row["team_id"] == str(team_id))
        ]

    # --- the route -------------------------------------------------------------

    def answer(self, payload):
        """What identity's route answers to a request body it accepts."""
        team_id = str(uuid.UUID(payload["team_id"]))
        user_ids = payload.get("user_ids")
        roles = payload.get("roles")
        if (user_ids is None) == (roles is None) or set(payload) - {
            "team_id",
            "user_ids",
            "roles",
        }:
            return Response(422, {"detail": "invalid request"})
        if roles is not None and (not roles or set(roles) - set(ROLES)):
            return Response(422, {"detail": "invalid roles"})
        if user_ids is not None and not user_ids:
            return Response(422, {"detail": "invalid user_ids"})
        contacts = []
        for row in self.memberships:
            if row["team_id"] != team_id or not row["active"] or not row["email"]:
                continue
            if user_ids is not None and row["user_id"] not in user_ids:
                continue
            if roles is not None and row["role"] not in roles:
                continue
            contacts.append(
                {"user_id": row["user_id"], "email": row["email"], "role": row["role"]}
            )
        return Response(200, {"team_id": team_id, "contacts": contacts})

    def post(self, url, json=None, headers=None, timeout=None, allow_redirects=True):
        """``requests.Session.post``, as guardian calls it."""
        self.asked.append(
            {
                "url": url,
                "json": json,
                "headers": dict(headers or {}),
                "timeout": timeout,
                "allow_redirects": allow_redirects,
            }
        )
        if isinstance(self.fault, Exception):
            raise self.fault
        if self.fault is not None:
            return self.fault
        if url != URL:
            return Response(404, {"detail": "Not Found"})
        if (headers or {}).get(CONTACTS_SECRET_HEADER) != SECRET:
            return Response(403, {"detail": "Invalid contacts secret"})
        return self.answer(json)

    # A session is used as a context manager.
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    trust_env = False
