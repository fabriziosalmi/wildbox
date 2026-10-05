"""Every change that disables an API key revokes it at the gateway first (#593).

The gateway caches the decision for a key for AUTH_CACHE_TTL. Revoking a key
only marked it inactive, so a leaked key kept working for up to five minutes;
deactivating, deleting or removing the account behind it did the same, or
flushed the gateway's cache after the commit, best effort. These tests pin
the contract that replaced it, for every such path: the gateway is told
first, by key id, and must confirm; only then is the change committed; if it
does not confirm, nothing is committed and the answer is 503.

The gateway is patched at the HTTP transport and the database by a stub that
records what is written and when: no service is needed.
"""

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import user_manager  # noqa: E402
from app import access_revocation, gateway_cache, internal, logout  # noqa: E402
from app.api_v1.endpoints import api_keys, user_api_keys, users  # noqa: E402
from app.auth import api_key_expired  # noqa: E402
from app.config import settings  # noqa: E402
from app.models import TeamRole  # noqa: E402
from app.schemas import AccountDeletionRequest, UserUpdate  # noqa: E402
from fastapi import HTTPException  # noqa: E402

SECRET = "unit-test-gateway-proof-of-origin"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def log():
    """What happened, in order: gateway calls and database writes."""
    return []


@pytest.fixture
def gateway(monkeypatch, log):
    """A gateway at the HTTP transport that confirms what it is sent, unless
    a test scripts another answer."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(gateway_cache, "_RETRY_DELAYS", (0, 0))
    state = {"script": [], "bodies": [], "guardian": []}

    def handler(request):
        body = json.loads(request.content)
        if "open-security-guardian" in str(request.url):
            # identity tells guardian after the commit (#676). Not a gateway
            # call: it has its own log entry and consumes no scripted answer.
            (scope,) = body
            log.append(f"guardian:{scope}")
            state["guardian"].append(body)
            return httpx.Response(200, json={"revoked": len(body[scope]), "scope": scope})
        state["bodies"].append(body)
        scope = next(
            name
            for name in ("api_keys", "users", "memberships", "jtis")
            if name in body
        )
        log.append(f"gateway:{scope}")
        if state["script"]:
            outcome = state["script"].pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return httpx.Response(
            200, json={"purged": True, "scope": scope, "revoked": len(body[scope])}
        )

    real_client = httpx.AsyncClient

    def client(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(gateway_cache.httpx, "AsyncClient", client)
    return state


def unconfirmed():
    """An older gateway: it flushes its cache and counts nothing."""
    return [
        httpx.Response(200, json={"purged": True, "scope": "all", "revoked": 0})
    ] * 3


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


class FakeDB:
    """Answers queries in the order given and records writes in ``log``."""

    def __init__(self, log, *results):
        self.log = log
        self.results = list(results)

    async def execute(self, _query):
        return Result(self.results.pop(0))

    async def commit(self):
        self.log.append("commit")

    async def delete(self, obj):
        self.log.append(f"delete:{type(obj).__name__}")

    async def rollback(self):
        self.log.append("rollback")


def make_key(**fields):
    key = SimpleNamespace(
        id=uuid.uuid4(), prefix="wsk_abcd", is_active=True, team_id=uuid.uuid4()
    )
    for name, value in fields.items():
        setattr(key, name, value)
    return key


def make_user(**fields):
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="alice@example.com",
        is_active=True,
        is_superuser=False,
        tokens_valid_after=None,
        owned_teams=[],
        team_memberships=[],
        api_keys=[],
    )
    for name, value in fields.items():
        setattr(user, name, value)
    return user


@pytest.fixture
def key_ids(monkeypatch):
    """The active keys the database holds, by owner: patched where it is read."""
    found = {"ids": ["k-1", "k-2"], "calls": []}

    async def active_api_key_ids(db, *, user_id=None, team_ids=None):
        found["calls"].append({"user_id": user_id, "team_ids": team_ids})
        if team_ids is not None and user_id is None:
            return list(found.get("team_ids_result", []))
        return list(found["ids"])

    for module in (users, user_manager, access_revocation):
        monkeypatch.setattr(module, "active_api_key_ids", active_api_key_ids)
    return found


# -- the gateway client --------------------------------------------------------


def test_the_gateway_is_sent_the_key_ids_and_must_count_them(gateway):
    run(gateway_cache.revoke_api_keys_at_gateway(["a", "b"], ttl_seconds=3600))
    assert gateway["bodies"] == [{"api_keys": ["a", "b"], "ttl": 3600}]


def test_a_gateway_that_does_not_count_the_keys_is_not_trusted(gateway):
    gateway["script"] = unconfirmed()
    with pytest.raises(gateway_cache.GatewayRevocationError):
        run(gateway_cache.revoke_api_keys_at_gateway(["a"], ttl_seconds=60))
    assert len(gateway["bodies"]) == 3


def test_a_gateway_that_stored_fewer_markers_is_not_trusted(gateway):
    """Its marker dict full, the gateway stores what it can and says so."""
    gateway["script"] = [
        httpx.Response(200, json={"purged": True, "scope": "api_keys", "revoked": 1})
    ] * 3
    with pytest.raises(gateway_cache.GatewayRevocationError):
        run(gateway_cache.revoke_api_keys_at_gateway(["a", "b"], ttl_seconds=60))


def test_a_gateway_that_answers_for_another_scope_is_not_trusted(gateway):
    gateway["script"] = [
        httpx.Response(200, json={"purged": True, "scope": "jtis", "revoked": 1})
    ] * 3
    with pytest.raises(gateway_cache.GatewayRevocationError):
        run(gateway_cache.revoke_api_keys_at_gateway(["a"], ttl_seconds=60))


def test_many_keys_are_sent_in_bodies_the_gateway_accepts(gateway):
    ids = [f"k-{n}" for n in range(2500)]
    run(gateway_cache.revoke_api_keys_at_gateway(ids, ttl_seconds=60))
    assert [len(body["api_keys"]) for body in gateway["bodies"]] == [1000, 1000, 500]
    assert sum((body["api_keys"] for body in gateway["bodies"]), []) == ids


def test_revoking_no_key_asks_the_gateway_nothing(gateway):
    run(logout.revoke_api_keys([]))
    assert gateway["bodies"] == []


def test_the_marker_outlives_any_cached_decision(gateway):
    run(logout.revoke_api_keys([uuid.UUID(int=1)]))
    (body,) = gateway["bodies"]
    assert body["api_keys"] == [str(uuid.UUID(int=1))]
    assert body["ttl"] == logout.API_KEY_MARKER_TTL_SECONDS >= 300


def test_no_gateway_secret_fails_the_revocation(gateway, monkeypatch):
    monkeypatch.delenv("GATEWAY_INTERNAL_SECRET")
    with pytest.raises(logout.RevocationError):
        run(logout.revoke_api_keys(["a"]))
    assert gateway["bodies"] == []


# -- revoking a key ------------------------------------------------------------


def revoke_own(key, db, monkeypatch):
    async def primary_team(user, db):
        return SimpleNamespace(id=key.team_id)

    monkeypatch.setattr(user_api_keys, "get_user_primary_team", primary_team)
    return run(user_api_keys.revoke_user_api_key(key.prefix, make_user(), db))


def revoke_by_team(key, db, monkeypatch):
    async def team_and_permission(team_id, user, db, role):
        assert role == TeamRole.ADMIN
        return SimpleNamespace(id=key.team_id)

    monkeypatch.setattr(api_keys, "get_team_and_check_permission", team_and_permission)
    return run(api_keys.revoke_api_key(str(key.team_id), key.prefix, make_user(), db))


@pytest.mark.parametrize("revoke", [revoke_own, revoke_by_team])
def test_a_key_is_revoked_at_the_gateway_before_it_is_marked_inactive(
    revoke, gateway, log, monkeypatch
):
    key = make_key()
    revoke(key, FakeDB(log, key), monkeypatch)

    assert log == ["gateway:api_keys", "commit"]
    assert gateway["bodies"][0]["api_keys"] == [str(key.id)]
    assert key.is_active is False


@pytest.mark.parametrize("revoke", [revoke_own, revoke_by_team])
def test_a_key_stays_active_when_the_gateway_does_not_confirm(
    revoke, gateway, log, monkeypatch
):
    key = make_key()
    gateway["script"] = unconfirmed()
    with pytest.raises(HTTPException) as exc:
        revoke(key, FakeDB(log, key), monkeypatch)

    assert exc.value.status_code == 503
    assert "commit" not in log
    assert key.is_active is True


# -- deactivating an account ---------------------------------------------------


def test_deactivation_ends_keys_and_sessions_at_the_gateway_before_the_commit(
    gateway, log, key_ids
):
    admin = make_user(is_superuser=True)
    target = make_user(email="bob@example.com")

    run(users.update_user_status(str(target.id), False, admin, FakeDB(log, target)))

    assert log == ["gateway:api_keys", "gateway:users", "commit"]
    keys_body, users_body = gateway["bodies"]
    assert keys_body["api_keys"] == ["k-1", "k-2"]
    (entry,) = users_body["users"]
    assert entry["user_id"] == str(target.id)
    assert key_ids["calls"] == [{"user_id": target.id, "team_ids": None}]
    assert target.is_active is False
    # Identity refuses those sessions too, should the account come back.
    assert target.tokens_valid_after.timestamp() == pytest.approx(entry["not_before"])


def test_deactivation_is_not_made_when_the_gateway_does_not_confirm(
    gateway, log, key_ids
):
    target = make_user(email="bob@example.com")
    gateway["script"] = unconfirmed()
    with pytest.raises(HTTPException) as exc:
        run(
            users.update_user_status(
                str(target.id), False, make_user(is_superuser=True), FakeDB(log, target)
            )
        )
    assert exc.value.status_code == 503
    assert "commit" not in log
    assert target.is_active is True and target.tokens_valid_after is None


def test_a_session_cutoff_the_gateway_refuses_also_stops_the_deactivation(
    gateway, log, key_ids
):
    target = make_user(email="bob@example.com")
    gateway["script"] = [
        httpx.Response(200, json={"purged": True, "scope": "api_keys", "revoked": 2})
    ] + unconfirmed()
    with pytest.raises(HTTPException) as exc:
        run(
            users.update_user_status(
                str(target.id), False, make_user(is_superuser=True), FakeDB(log, target)
            )
        )
    assert exc.value.status_code == 503
    assert "commit" not in log and target.is_active is True


def test_activation_asks_the_gateway_nothing(gateway, log, key_ids):
    target = make_user(is_active=False)
    run(
        users.update_user_status(
            str(target.id), True, make_user(is_superuser=True), FakeDB(log, target)
        )
    )
    assert log == ["commit"] and target.is_active is True


class UserStore:
    """The parts of SQLAlchemyUserDatabase the manager uses, in memory."""

    def __init__(self, log, user):
        self.log = log
        self.user = user
        self.session = object()

    async def update(self, user, update_dict):
        self.log.append("database")
        for name, value in update_dict.items():
            setattr(user, name, value)
        return user

    async def delete(self, user):
        self.log.append("database:delete")


def test_deactivation_through_the_users_api_ends_keys_and_sessions_first(
    gateway, log, key_ids
):
    target = make_user(email="bob@example.com")
    manager = user_manager.UserManager(UserStore(log, target))

    run(manager.update(UserUpdate(is_active=False), target, safe=False))

    assert log == ["gateway:api_keys", "gateway:users", "database"]
    assert target.is_active is False and target.tokens_valid_after is not None


def test_deactivation_through_the_users_api_fails_closed(gateway, log, key_ids):
    target = make_user(email="bob@example.com")
    manager = user_manager.UserManager(UserStore(log, target))
    gateway["script"] = unconfirmed()

    with pytest.raises(HTTPException) as exc:
        run(manager.update(UserUpdate(is_active=False), target, safe=False))
    assert exc.value.status_code == 503
    assert "database" not in log and target.is_active is True


def test_an_update_that_does_not_deactivate_asks_the_gateway_nothing(
    gateway, log, key_ids
):
    target = make_user(email="bob@example.com")
    manager = user_manager.UserManager(UserStore(log, target))
    run(manager.update(UserUpdate(is_verified=False), target, safe=False))
    assert log == ["database"]


# -- deleting an account -------------------------------------------------------


def test_deletion_through_the_users_api_ends_keys_and_sessions_first(
    gateway, log, key_ids
):
    target = make_user(email="bob@example.com")
    manager = user_manager.UserManager(UserStore(log, target))
    run(manager.delete(target))
    assert log == [
        "gateway:api_keys",
        "gateway:users",
        "database:delete",
        # guardian is told the account is gone, once it is (#676).
        "guardian:users",
    ]
    assert gateway["guardian"] == [{"users": [str(target.id)]}]


def test_deletion_through_the_users_api_fails_closed(gateway, log, key_ids):
    target = make_user(email="bob@example.com")
    manager = user_manager.UserManager(UserStore(log, target))
    gateway["script"] = unconfirmed()
    with pytest.raises(HTTPException) as exc:
        run(manager.delete(target))
    assert exc.value.status_code == 503
    assert "database:delete" not in log
    assert gateway["guardian"] == []


def test_an_administrator_s_deletion_revokes_before_anything_is_deleted(
    gateway, log, key_ids
):
    target = make_user(email="bob@example.com")
    lone_team = SimpleNamespace(
        id=uuid.uuid4(),
        name="solo",
        memberships=[SimpleNamespace(user_id=target.id)],
    )
    target.owned_teams = [lone_team]
    target.team_memberships = [SimpleNamespace()]
    key_ids["team_ids_result"] = ["k-team"]

    run(
        users.delete_user(
            str(target.id), True, make_user(is_superuser=True), FakeDB(log, target)
        )
    )

    assert log[:2] == ["gateway:api_keys", "gateway:users"]
    # The commit, then the notice to guardian that the account is gone (#676).
    assert log[-2:] == ["commit", "guardian:users"]
    assert gateway["guardian"] == [{"users": [str(target.id)]}]
    # The account's keys and those of the team deleted with it.
    assert sorted(gateway["bodies"][0]["api_keys"]) == ["k-1", "k-2", "k-team"]
    assert {"user_id": None, "team_ids": [lone_team.id]} in key_ids["calls"]


def test_an_administrator_s_deletion_fails_closed(gateway, log, key_ids):
    target = make_user(email="bob@example.com")
    gateway["script"] = unconfirmed()
    with pytest.raises(HTTPException) as exc:
        run(
            users.delete_user(
                str(target.id), False, make_user(is_superuser=True), FakeDB(log, target)
            )
        )
    assert exc.value.status_code == 503
    assert not any(entry.startswith("delete") or entry == "commit" for entry in log)
    assert gateway["guardian"] == []


@pytest.fixture
def password_ok(monkeypatch):
    async def verify(user, password, wrong_detail=None):
        return None

    monkeypatch.setattr(users, "verify_current_password", verify)


def test_deleting_one_s_own_account_ends_keys_and_sessions_first(
    gateway, log, key_ids, password_ok
):
    me = make_user()
    run(
        users.delete_my_account(
            AccountDeletionRequest(password="x", confirm_deletion=True),
            me,
            FakeDB(log, []),
        )
    )
    assert log == ["gateway:api_keys", "gateway:users", "commit", "guardian:users"]
    assert gateway["guardian"] == [{"users": [str(me.id)]}]
    assert me.is_active is False and me.tokens_valid_after is not None


def test_deleting_one_s_own_account_fails_closed(gateway, log, key_ids, password_ok):
    me = make_user()
    gateway["script"] = unconfirmed()
    with pytest.raises(HTTPException) as exc:
        run(
            users.delete_my_account(
                AccountDeletionRequest(password="x", confirm_deletion=True),
                me,
                FakeDB(log, []),
            )
        )
    assert exc.value.status_code == 503
    assert "commit" not in log and me.is_active is True
    assert gateway["guardian"] == []


# -- removing a member from a team ----------------------------------------------


def remove_member(log):
    team_id = uuid.uuid4()
    member = SimpleNamespace(
        user_id=uuid.uuid4(), team_id=team_id, role=TeamRole.MEMBER
    )
    caller = SimpleNamespace(user_id=uuid.uuid4(), role=TeamRole.OWNER)
    db = FakeDB(log, caller, member)
    run(users.remove_team_member(str(team_id), str(member.user_id), make_user(), db))
    return member


def test_removing_a_member_revokes_their_keys_in_that_team_first(gateway, log, key_ids):
    member = remove_member(log)
    # And their sessions in that team (#613): see test_team_removal_sessions.
    assert log == [
        "gateway:api_keys",
        "gateway:memberships",
        "delete:SimpleNamespace",
        "commit",
        # guardian is told last, once the member is gone (#676).
        "guardian:memberships",
    ]
    assert key_ids["calls"] == [
        {"user_id": member.user_id, "team_ids": [member.team_id]}
    ]


def test_removing_a_member_fails_closed(gateway, log, key_ids):
    gateway["script"] = unconfirmed()
    with pytest.raises(HTTPException) as exc:
        remove_member(log)
    assert exc.value.status_code == 503
    assert log == ["gateway:api_keys"] * 3
    assert gateway["guardian"] == []


def test_a_member_without_keys_still_has_their_team_sessions_ended(
    gateway, log, key_ids
):
    key_ids["ids"] = []
    remove_member(log)
    assert log == [
        "gateway:memberships",
        "delete:SimpleNamespace",
        "commit",
        "guardian:memberships",
    ]


# -- the key query --------------------------------------------------------------


def test_the_key_query_reads_only_active_keys_of_whom_it_is_asked():
    class Capture:
        query = None

        async def execute(self, query):
            Capture.query = query
            return Result(["id-1"])

    user_id, team_id = uuid.uuid4(), uuid.uuid4()
    assert run(
        access_revocation.active_api_key_ids(
            Capture(), user_id=user_id, team_ids=[team_id]
        )
    ) == ["id-1"]
    sql = str(Capture.query)
    assert "api_keys.is_active IS true" in sql
    assert "api_keys.user_id" in sql and "api_keys.team_id IN" in sql
    # No team: nothing to look for.
    assert run(access_revocation.active_api_key_ids(Capture(), team_ids=[])) == []


# -- what /internal/authorize tells the gateway ---------------------------------


class AuthorizeSession:
    def __init__(self, row):
        self.row = row

    async def execute(self, _query):
        return Result(self.row)

    async def commit(self):
        pass


def authorize_key(api_key_obj, monkeypatch):
    monkeypatch.setattr(settings, "gateway_internal_secret", SECRET)
    user = make_user()
    row = (
        api_key_obj,
        user,
        SimpleNamespace(id=uuid.uuid4()),
        SimpleNamespace(role="owner"),
    )
    request = internal.TokenAuthRequest(token="wsk_abcd.secret", token_type="api_key")
    return run(
        internal.authorize_request(
            request, db=AuthorizeSession(row), x_gateway_secret=SECRET
        )
    )


def test_the_gateway_is_told_the_key_id_and_its_expiry(monkeypatch):
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    key = make_key(expires_at=expires, scopes=["read"], last_used_at=None)
    answer = authorize_key(key, monkeypatch)
    assert answer.api_key_id == str(key.id)
    assert answer.credential_expires_at == pytest.approx(expires.timestamp())


def test_a_key_without_expiry_reports_none(monkeypatch):
    key = make_key(expires_at=None, scopes=["*"], last_used_at=None)
    answer = authorize_key(key, monkeypatch)
    assert answer.api_key_id == str(key.id)
    assert answer.credential_expires_at is None


def test_an_expired_key_is_refused_rather_than_failing(monkeypatch):
    """expires_at is read back timezone-aware; comparing it with a naive
    utcnow() raised TypeError and every key with an expiry answered 500."""
    key = make_key(
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        scopes=["*"],
        last_used_at=None,
    )
    with pytest.raises(HTTPException) as exc:
        authorize_key(key, monkeypatch)
    assert exc.value.status_code == 401


def test_api_key_expired_reads_aware_and_naive_values():
    now = datetime.now(timezone.utc)
    assert api_key_expired(now - timedelta(seconds=1))
    assert not api_key_expired(now + timedelta(minutes=1))
    assert api_key_expired((now - timedelta(seconds=1)).replace(tzinfo=None))
    assert not api_key_expired(None)


def test_a_session_decision_carries_the_token_s_expiry(monkeypatch):
    monkeypatch.setattr(settings, "gateway_internal_secret", SECRET)

    async def not_blacklisted(_jti):
        return False

    from app import token_blacklist

    monkeypatch.setattr(token_blacklist, "is_token_blacklisted", not_blacklisted)
    user = make_user()
    token = run(user_manager.get_jwt_strategy().write_token(user))
    row = (user, SimpleNamespace(id=uuid.uuid4()), SimpleNamespace(role="owner"))
    answer = run(
        internal.authorize_request(
            internal.TokenAuthRequest(token=token, token_type="bearer"),
            db=AuthorizeSession(row),
            x_gateway_secret=SECRET,
        )
    )
    claims = user_manager.verify_access_token(token)
    assert answer.credential_expires_at == pytest.approx(claims["exp"])
    assert answer.api_key_id is None
