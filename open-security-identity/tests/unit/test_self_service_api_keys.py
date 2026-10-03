"""The self-service API-key routes act on the caller's own keys (#664).

DELETE /api/v1/api-keys/{key_prefix} selected the key by team and prefix
only, so any member could revoke a teammate's or the owner's key. The
self-service list, get and revoke now match the caller's user ID as well;
a team's keys as a whole stay with the team routes, where revoking needs
the owner or admin role.

The queries are read back from what the routes send to the database: the
criteria of each WHERE clause, column by column. No database is needed.
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api_v1.endpoints import api_keys, user_api_keys  # noqa: E402
from app.models import TeamRole  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from sqlalchemy.sql.elements import BinaryExpression, BindParameter, True_  # noqa: E402
from sqlalchemy.sql.operators import eq, is_  # noqa: E402


def run(coro):
    return asyncio.run(coro)


def equalities(query):
    """{column: value} for every `column == value` of the WHERE clause."""
    found = {}

    def visit(clause):
        if isinstance(clause, BinaryExpression) and clause.operator in (eq, is_):
            column = getattr(clause.left, "key", None)
            if column and isinstance(clause.right, BindParameter):
                found[column] = clause.right.value
            elif column and isinstance(clause.right, True_):
                # `column == True` compiles to `column IS true`.
                found[column] = True
            return
        for child in clause.get_children():
            visit(child)

    visit(query.whereclause)
    return found


class Rows(list):
    def all(self):
        return list(self)


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return Rows(self.value or [])

    def first(self):
        return self.value


class Recorder:
    """Records each query and answers them in the order given."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.queries = []
        self.commits = 0

    async def execute(self, query):
        self.queries.append(query)
        return Result(self.answers.pop(0) if self.answers else None)

    async def commit(self):
        self.commits += 1


@pytest.fixture
def caller(monkeypatch):
    user = SimpleNamespace(id=uuid.uuid4(), email="member@example.com")
    team = SimpleNamespace(id=uuid.uuid4())

    async def primary_team(current_user, db):
        assert current_user is user
        return team

    monkeypatch.setattr(user_api_keys, "get_user_primary_team", primary_team)
    return SimpleNamespace(user=user, team=team)


@pytest.fixture
def gateway(monkeypatch):
    revoked = []

    async def revoke(ids, what):
        revoked.extend(ids)

    for module in (user_api_keys, api_keys):
        monkeypatch.setattr(module, "revoke_api_keys_or_503", revoke)
    return revoked


# -- self-service routes --------------------------------------------------------


def test_revoking_matches_the_caller_s_own_key(caller, gateway):
    key = SimpleNamespace(id=uuid.uuid4(), prefix="wsk_abcd", is_active=True)
    db = Recorder(key)
    run(user_api_keys.revoke_user_api_key("wsk_abcd", caller.user, db))

    (query,) = db.queries
    assert equalities(query) == {
        "team_id": caller.team.id,
        "user_id": caller.user.id,
        "prefix": "wsk_abcd",
        "is_active": True,
    }
    assert gateway == [key.id] and key.is_active is False


def test_a_teammate_s_key_answers_404_and_stays_active(caller, gateway):
    """The query matches the caller's keys only, so a teammate's prefix
    finds nothing: 404, nothing sent to the gateway, nothing committed."""
    db = Recorder(None)
    with pytest.raises(HTTPException) as exc:
        run(user_api_keys.revoke_user_api_key("wsk_mate", caller.user, db))
    assert exc.value.status_code == 404
    assert gateway == [] and db.commits == 0


def test_reading_a_key_matches_the_caller_s_own_key(caller):
    key = SimpleNamespace(id=uuid.uuid4(), prefix="wsk_abcd")
    db = Recorder(key)
    assert run(user_api_keys.get_user_api_key("wsk_abcd", caller.user, db)) is key
    (query,) = db.queries
    assert equalities(query) == {
        "team_id": caller.team.id,
        "user_id": caller.user.id,
        "prefix": "wsk_abcd",
    }


def test_another_user_s_key_cannot_be_read(caller):
    with pytest.raises(HTTPException) as exc:
        run(user_api_keys.get_user_api_key("wsk_mate", caller.user, Recorder(None)))
    assert exc.value.status_code == 404


def test_the_list_holds_the_caller_s_own_active_keys(caller):
    db = Recorder([])
    run(user_api_keys.list_user_api_keys(caller.user, db))
    (query,) = db.queries
    assert equalities(query) == {
        "team_id": caller.team.id,
        "user_id": caller.user.id,
        "is_active": True,
    }


# -- the team routes --------------------------------------------------------------


def membership(role):
    return (SimpleNamespace(id=uuid.uuid4()), SimpleNamespace(role=role))


@pytest.mark.parametrize("role", [TeamRole.OWNER, TeamRole.ADMIN])
def test_an_owner_or_admin_revokes_any_key_of_the_team(role, gateway):
    """Through the team route, by team and prefix: whoever created the key."""
    team, member = membership(role)
    key = SimpleNamespace(id=uuid.uuid4(), prefix="wsk_mate", is_active=True)
    db = Recorder((team, member), key)
    caller = SimpleNamespace(id=uuid.uuid4())

    run(api_keys.revoke_api_key(str(team.id), "wsk_mate", caller, db))

    assert equalities(db.queries[1]) == {
        "team_id": team.id,
        "prefix": "wsk_mate",
        "is_active": True,
    }
    assert gateway == [key.id] and key.is_active is False


def test_a_member_cannot_revoke_through_the_team_route(gateway):
    team, member = membership(TeamRole.MEMBER)
    key = SimpleNamespace(id=uuid.uuid4(), prefix="wsk_boss", is_active=True)
    db = Recorder((team, member), key)
    with pytest.raises(HTTPException) as exc:
        run(
            api_keys.revoke_api_key(
                str(team.id), "wsk_boss", SimpleNamespace(id=uuid.uuid4()), db
            )
        )
    assert exc.value.status_code == 403
    assert gateway == [] and key.is_active is True and db.commits == 0


def test_the_team_route_checks_the_caller_s_membership_of_that_team(gateway):
    caller = SimpleNamespace(id=uuid.uuid4())
    team_id = uuid.uuid4()
    db = Recorder(None)
    with pytest.raises(HTTPException) as exc:
        run(api_keys.revoke_api_key(str(team_id), "wsk_any", caller, db))
    assert exc.value.status_code == 404
    assert equalities(db.queries[0]) == {"id": str(team_id), "user_id": caller.id}
    assert gateway == []
