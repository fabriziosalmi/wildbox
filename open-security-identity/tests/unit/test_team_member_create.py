"""A team owner or admin creates an account directly in the team (#573).

POST /api/v1/admin/teams/{team_id}/members creates a new account whose only
membership is that team, with an initial password the administrator chose;
the account must change it before it can do anything else. The database,
the user store and Redis are stubs here, so this needs neither PostgreSQL
nor Redis.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import internal, user_manager  # noqa: E402
from app.api_v1.endpoints import users  # noqa: E402
from app.auth import verify_password  # noqa: E402
from app.config import settings  # noqa: E402
from app.models import TeamMembership, TeamRole, User  # noqa: E402
from app.schemas import TeamMemberCreate  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from fastapi_users import exceptions  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402

TEAM_ID = uuid.uuid4()
INITIAL_PASSWORD = "initial-password-0123"
NEW_EMAIL = "new.member@example.com"


def run(coro):
    return asyncio.run(coro)


def make_caller(is_superuser=False):
    return SimpleNamespace(id=uuid.uuid4(), is_superuser=is_superuser)


class EndpointDb:
    """The endpoint's session: the caller's membership, then the new one."""

    def __init__(self, caller_role, team_exists=True):
        self.caller = (
            SimpleNamespace(role=caller_role) if caller_role is not None else None
        )
        self.team_exists = team_exists
        self.queries = 0

    async def execute(self, _query):
        self.queries += 1
        if self.queries == 1:
            return SimpleNamespace(scalar_one_or_none=lambda: self.caller)
        joined = SimpleNamespace(
            role=self.created_role, joined_at=datetime.now(timezone.utc)
        )
        return SimpleNamespace(scalar_one=lambda: joined)

    async def get(self, _model, _id):
        return SimpleNamespace(id=TEAM_ID) if self.team_exists else None


class ManagerStub:
    def __init__(self, db, error=None):
        self.db = db
        self.error = error
        self.calls = []

    async def create_team_member(self, email, password, team_id, role):
        self.calls.append((email, password, team_id, role))
        if self.error:
            raise self.error
        self.db.created_role = role
        return SimpleNamespace(
            id=uuid.uuid4(),
            email=email,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            must_change_password=True,
        )


def create(caller_role, role="member", superuser=False, team_exists=True, error=None):
    db = EndpointDb(caller_role, team_exists)
    manager = ManagerStub(db, error)
    body = TeamMemberCreate(email=NEW_EMAIL, password=INITIAL_PASSWORD, role=role)
    try:
        result = run(
            users.create_team_member(
                TEAM_ID,
                body,
                current_user=make_caller(superuser),
                db=db,
                user_manager=manager,
            )
        )
    except HTTPException as exc:
        return exc, manager
    return result, manager


# -- who may create which role -------------------------------------------------


@pytest.mark.parametrize(
    "caller_role, role",
    [("owner", "member"), ("owner", "admin"), ("admin", "member")],
)
def test_an_owner_or_admin_creates_a_lower_role(caller_role, role):
    result, manager = create(caller_role, role)
    assert result["role"] == role
    assert result["team_id"] == str(TEAM_ID)
    assert result["user"]["email"] == NEW_EMAIL
    assert result["user"]["must_change_password"] is True
    assert manager.calls == [(NEW_EMAIL, INITIAL_PASSWORD, TEAM_ID, role)]


@pytest.mark.parametrize("caller_role", ["member", None])
def test_a_member_or_an_outsider_is_refused(caller_role):
    exc, manager = create(caller_role)
    assert exc.status_code == 403
    # Refused for not managing the team, before any role is considered.
    assert exc.detail == "Owner or Admin role required"
    assert manager.calls == []


@pytest.mark.parametrize(
    "caller_role, role",
    [
        ("admin", "admin"),
        ("admin", "owner"),
        ("owner", "owner"),
    ],
)
def test_a_role_at_or_above_the_callers_is_refused(caller_role, role):
    exc, manager = create(caller_role, role)
    assert exc.status_code == 403
    assert role in exc.detail
    assert manager.calls == []


def test_a_superuser_creates_an_admin_in_any_team():
    result, manager = create(None, "admin", superuser=True)
    assert result["role"] == "admin"
    assert len(manager.calls) == 1


def test_a_superuser_cannot_create_an_owner():
    exc, manager = create(None, "owner", superuser=True)
    assert exc.status_code == 403
    assert manager.calls == []


def test_a_superuser_gets_404_for_a_team_that_does_not_exist():
    exc, manager = create(None, superuser=True, team_exists=False)
    assert exc.status_code == 404
    assert manager.calls == []


def test_a_registered_email_answers_409_without_saying_more():
    exc, _ = create("owner", error=exceptions.UserAlreadyExists())
    assert exc.status_code == 409
    assert NEW_EMAIL not in exc.detail
    assert "registered" not in exc.detail and "exists" not in exc.detail


def test_an_unknown_role_is_refused_by_the_schema():
    with pytest.raises(ValueError):
        TeamMemberCreate(email=NEW_EMAIL, password=INITIAL_PASSWORD, role="viewer")


def test_a_short_initial_password_is_refused_by_the_schema():
    with pytest.raises(ValueError):
        TeamMemberCreate(email=NEW_EMAIL, password="short", role="member")


def test_the_role_rule_ranks_owner_admin_member():
    assign = users.assignable_role
    assert not assign("owner", users.SUPERUSER_RANK)
    assert assign("admin", users.SUPERUSER_RANK)
    assert assign("admin", users.TEAM_ROLE_RANK["owner"])
    assert not assign("admin", users.TEAM_ROLE_RANK["admin"])
    assert assign("member", users.TEAM_ROLE_RANK["admin"])
    assert not assign("member", users.TEAM_ROLE_RANK["member"])
    assert not assign("superuser", users.SUPERUSER_RANK)


# -- UserManager.create_team_member ----------------------------------------------


class FakeSession:
    def __init__(self, fail_commit=False):
        self.added = []
        self.commits = 0
        self.rollbacks = 0
        self.fail_commit = fail_commit

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        for obj in self.added:
            if isinstance(obj, User) and obj.id is None:
                obj.id = uuid.uuid4()

    async def commit(self):
        if self.fail_commit:
            raise IntegrityError("INSERT", {}, Exception("duplicate email"))
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    async def refresh(self, _obj):
        pass


class FakeUserDb:
    def __init__(self, existing=None, fail_commit=False):
        self.existing = existing
        self.session = FakeSession(fail_commit)
        self.looked_up = []

    async def get_by_email(self, email):
        self.looked_up.append(email)
        return self.existing


def make_manager(user_db, monkeypatch):
    manager = user_manager.UserManager(user_db)

    async def no_personal_team(*_args, **_kwargs):
        raise AssertionError("on_after_register must not run for a team member")

    monkeypatch.setattr(manager, "on_after_register", no_personal_team)
    return manager


def test_the_account_is_created_in_the_team_only_and_flagged(monkeypatch):
    user_db = FakeUserDb()
    manager = make_manager(user_db, monkeypatch)
    user = run(
        manager.create_team_member(NEW_EMAIL, INITIAL_PASSWORD, TEAM_ID, "member")
    )

    assert user.email == NEW_EMAIL
    assert user.must_change_password is True
    assert user.is_superuser is False
    assert verify_password(INITIAL_PASSWORD, user.hashed_password)
    assert user.hashed_password != INITIAL_PASSWORD
    memberships = [o for o in user_db.session.added if isinstance(o, TeamMembership)]
    assert [(m.user_id, m.team_id, m.role) for m in memberships] == [
        (user.id, TEAM_ID, "member")
    ]
    # One transaction for the user and its membership; no personal team.
    assert user_db.session.commits == 1
    assert len(user_db.session.added) == 2


def test_a_registered_email_creates_nothing(monkeypatch):
    user_db = FakeUserDb(existing=SimpleNamespace(email=NEW_EMAIL))
    manager = make_manager(user_db, monkeypatch)
    with pytest.raises(exceptions.UserAlreadyExists):
        run(manager.create_team_member(NEW_EMAIL, INITIAL_PASSWORD, TEAM_ID, "member"))
    assert user_db.session.added == []
    assert user_db.looked_up == [NEW_EMAIL]


def test_a_concurrent_registration_of_the_email_is_a_conflict(monkeypatch):
    user_db = FakeUserDb(fail_commit=True)
    manager = make_manager(user_db, monkeypatch)
    with pytest.raises(exceptions.UserAlreadyExists):
        run(manager.create_team_member(NEW_EMAIL, INITIAL_PASSWORD, TEAM_ID, "member"))
    assert user_db.session.rollbacks == 1


def test_the_password_goes_through_validate_password(monkeypatch):
    user_db = FakeUserDb()
    manager = make_manager(user_db, monkeypatch)
    seen = []

    async def validate(password, user):
        seen.append(password)
        raise exceptions.InvalidPasswordException(reason="too weak")

    monkeypatch.setattr(manager, "validate_password", validate)
    with pytest.raises(exceptions.InvalidPasswordException):
        run(manager.create_team_member(NEW_EMAIL, INITIAL_PASSWORD, TEAM_ID, "member"))
    assert seen == [INITIAL_PASSWORD]
    assert user_db.session.added == []


def test_changing_the_password_lifts_the_flag(monkeypatch):
    writes = []

    async def update(self, user, update_dict):
        writes.append(dict(update_dict))
        return user

    monkeypatch.setattr(user_manager.UserManager, "_update", update)
    manager = user_manager.UserManager(None)
    run(manager.set_password(SimpleNamespace(), "a-new-long-password"))
    assert writes == [
        {"password": "a-new-long-password", "must_change_password": False}
    ]


# -- the gate on a flagged account's requests ----------------------------------


def gate(user, method, path):
    request = SimpleNamespace(method=method, url=SimpleNamespace(path=path))
    return run(user_manager.require_password_changed(request, user))


FLAGGED = SimpleNamespace(must_change_password=True)
CLEARED = SimpleNamespace(must_change_password=False)
P = settings.api_v1_prefix


@pytest.mark.parametrize(
    "method, path",
    [
        ("POST", f"{P}/admin/me/change-password"),
        ("PUT", f"{P}/admin/me/password"),
        ("GET", f"{P}/users/me"),
    ],
)
def test_a_flagged_account_may_change_its_password_and_read_itself(method, path):
    assert gate(FLAGGED, method, path) is None


@pytest.mark.parametrize(
    "method, path",
    [
        ("PATCH", f"{P}/users/me"),
        ("GET", f"{P}/admin/me/activity"),
        ("GET", f"{P}/admin/teams/{TEAM_ID}/members"),
        ("POST", f"{P}/admin/teams/{TEAM_ID}/members"),
        ("GET", f"{P}/users/me/"),
        ("GET", f"{P}/api-keys"),
        ("POST", f"{P}/api-keys"),
    ],
)
def test_a_flagged_account_is_refused_everything_else(method, path):
    with pytest.raises(HTTPException) as exc:
        gate(FLAGGED, method, path)
    assert exc.value.status_code == 403
    assert exc.value.detail == user_manager.PASSWORD_CHANGE_REQUIRED


@pytest.mark.parametrize("user", [CLEARED, None])
def test_other_requests_pass_the_gate(user):
    assert gate(user, "GET", f"{P}/admin/me/activity") is None


@pytest.fixture
def flagged_session():
    """Every gated router sees a flagged account (no database involved)."""
    from app.main import app

    app.dependency_overrides[user_manager._optional_active_user] = lambda: FLAGGED
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "method, path",
    [
        ("get", "/api/v1/admin/me/activity"),
        ("patch", "/api/v1/users/me"),
        ("get", f"/api/v1/admin/teams/{TEAM_ID}/members"),
        ("post", f"/api/v1/admin/teams/{TEAM_ID}/members"),
        ("get", "/api/v1/api-keys"),
        ("get", f"/api/v1/teams/{TEAM_ID}/api-keys"),
        ("get", "/api/v1/analytics/admin/system-stats"),
    ],
)
def test_every_authenticated_router_carries_the_gate(flagged_session, method, path):
    response = getattr(flagged_session, method)(path)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["message"] == "PASSWORD_CHANGE_REQUIRED"


@pytest.mark.parametrize(
    "method, path",
    [
        ("post", "/api/v1/admin/me/change-password"),
        ("get", "/api/v1/users/me"),
        ("post", "/api/v1/auth/jwt/logout"),
        ("post", "/api/v1/auth/logout"),
    ],
)
def test_the_exempt_routes_are_not_gated(flagged_session, method, path):
    # No token: the route's own authentication answers, not the gate.
    response = getattr(flagged_session, method)(path)
    assert response.status_code != 403 or (
        "PASSWORD_CHANGE_REQUIRED" not in response.text
    ), response.text


# -- the gateway is told --------------------------------------------------------


class AuthorizeSession:
    def __init__(self, user):
        self.row = (user, SimpleNamespace(id=TEAM_ID), SimpleNamespace(role="member"))

    async def execute(self, _query):
        return SimpleNamespace(first=lambda: self.row)


@pytest.mark.parametrize("flag", [True, False])
def test_authorize_reports_the_flag_to_the_gateway(monkeypatch, flag):
    async def nothing(*_args):
        return False

    monkeypatch.setattr(user_manager, "is_token_blacklisted", nothing)
    from app import token_blacklist

    monkeypatch.setattr(token_blacklist, "is_token_blacklisted", nothing)
    secret = "unit-test-gateway-proof-of-origin"
    monkeypatch.setattr(settings, "gateway_internal_secret", secret)
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email=NEW_EMAIL,
        is_active=True,
        tokens_valid_after=None,
        must_change_password=flag,
    )
    token = run(user_manager.get_jwt_strategy().write_token(user))
    request = internal.TokenAuthRequest(token=token, token_type="bearer")
    answer = run(
        internal.authorize_request(
            request, db=AuthorizeSession(user), x_gateway_secret=secret
        )
    )
    assert answer.is_authenticated
    # The session works in the team of its only membership.
    assert answer.team_id == str(TEAM_ID)
    assert answer.password_change_required is flag


def test_the_new_column_defaults_to_false():
    column = User.__table__.c.must_change_password
    assert column.nullable is False
    assert column.server_default is not None
    assert TeamRole.MEMBER.value == "member"
