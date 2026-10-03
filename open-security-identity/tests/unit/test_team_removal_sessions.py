"""Removing a member from a team ends their sessions in that team (#613).

A session is not bound to a team: /internal/authorize resolves one on every
request (the oldest membership), and the gateway caches the answer for
AUTH_CACHE_TTL. Since #593 the removal revoked the member's API keys for the
team, but their sessions kept the cached "allowed in this team" decision for
up to five minutes. These tests pin the contract that closes it: the gateway
is told first -- the keys, then a marker for the (user, team) pair -- and
must confirm both; only then is the membership deleted; if it does not
confirm, nothing is deleted and the answer is 503.

The gateway is patched at the HTTP transport and the database by a stub that
records what is written and when: no service is needed.
"""

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import access_revocation, gateway_cache, internal, logout  # noqa: E402
from app.api_v1.endpoints import users  # noqa: E402
from app.config import settings  # noqa: E402
from app.models import TeamRole  # noqa: E402
from fastapi import HTTPException  # noqa: E402

SECRET = "unit-test-gateway-proof-of-origin"
SCOPES = ("api_keys", "users", "memberships", "jtis")


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def log():
    """What happened, in order: gateway calls and database writes."""
    return []


@pytest.fixture
def gateway(monkeypatch, log):
    """A gateway at the HTTP transport that confirms what it is sent, unless
    a test scripts another answer for a scope."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(gateway_cache, "_RETRY_DELAYS", (0, 0))
    state = {"script": {}, "bodies": []}

    def handler(request):
        body = json.loads(request.content)
        state["bodies"].append(body)
        scope = next(name for name in SCOPES if name in body)
        log.append(f"gateway:{scope}")
        script = state["script"].get(scope)
        if script:
            outcome = script.pop(0)
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


@pytest.fixture
def key_ids(monkeypatch):
    """The member's active keys in the team, patched where they are read."""
    found = {"ids": ["k-1"], "calls": []}

    async def active_api_key_ids(db, *, user_id=None, team_ids=None):
        found["calls"].append({"user_id": user_id, "team_ids": team_ids})
        return list(found["ids"])

    monkeypatch.setattr(access_revocation, "active_api_key_ids", active_api_key_ids)
    return found


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return SimpleNamespace(first=lambda: self.value)

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
        self.log.append(f"delete:{getattr(obj.role, 'value', obj.role)}")


def caller(**fields):
    user = SimpleNamespace(id=uuid.uuid4(), is_superuser=False)
    for name, value in fields.items():
        setattr(user, name, value)
    return user


def membership(team_id, role=TeamRole.MEMBER, user_id=None):
    return SimpleNamespace(user_id=user_id or uuid.uuid4(), team_id=team_id, role=role)


def remove(log, *, by_role=TeamRole.OWNER, superuser=False, role=TeamRole.MEMBER):
    """Remove a member of ``role`` from a team, as a caller of ``by_role``
    (or a platform superuser who is not in the team)."""
    team_id = uuid.uuid4()
    target = membership(team_id, role)
    caller_membership = None if superuser else membership(team_id, by_role)
    results = [caller_membership, target]
    if role == TeamRole.OWNER:
        results.append(membership(team_id, TeamRole.OWNER))  # another owner
    db = FakeDB(log, *results)
    run(
        users.remove_team_member(
            str(team_id), str(target.user_id), caller(is_superuser=superuser), db
        )
    )
    return target


# -- the gateway client --------------------------------------------------------


def test_the_gateway_is_sent_the_pairs_and_must_count_them(gateway):
    run(
        gateway_cache.revoke_team_sessions_at_gateway(
            [("u-1", "t-1"), ("u-2", "t-1")], 1800000000.5, ttl_seconds=1800
        )
    )
    assert gateway["bodies"] == [
        {
            "memberships": [
                {"user_id": "u-1", "team_id": "t-1", "not_before": 1800000000.5},
                {"user_id": "u-2", "team_id": "t-1", "not_before": 1800000000.5},
            ],
            "ttl": 1800,
        }
    ]


def test_a_gateway_that_does_not_count_the_memberships_is_not_trusted(gateway):
    gateway["script"]["memberships"] = unconfirmed()
    with pytest.raises(gateway_cache.GatewayRevocationError):
        run(gateway_cache.revoke_team_sessions_at_gateway([("u", "t")], 1.0, 60))
    assert len(gateway["bodies"]) == 3


def test_a_gateway_that_answers_for_another_scope_is_not_trusted(gateway):
    gateway["script"]["memberships"] = [
        httpx.Response(200, json={"purged": True, "scope": "users", "revoked": 1})
    ] * 3
    with pytest.raises(gateway_cache.GatewayRevocationError):
        run(gateway_cache.revoke_team_sessions_at_gateway([("u", "t")], 1.0, 60))


def test_many_memberships_are_sent_in_bodies_the_gateway_accepts(gateway):
    pairs = [(f"u-{n}", "t") for n in range(1500)]
    run(gateway_cache.revoke_team_sessions_at_gateway(pairs, 1.0, 60))
    assert [len(body["memberships"]) for body in gateway["bodies"]] == [1000, 500]


def test_the_marker_outlives_every_session_issued_before_the_removal(gateway):
    not_before = datetime(2027, 1, 15, 12, 0, 0)  # naive: read as UTC
    run(logout.revoke_team_sessions([(uuid.UUID(int=1), uuid.UUID(int=2))], not_before))
    ((entry,),) = [body["memberships"] for body in gateway["bodies"]]
    assert entry == {
        "user_id": str(uuid.UUID(int=1)),
        "team_id": str(uuid.UUID(int=2)),
        "not_before": not_before.replace(tzinfo=timezone.utc).timestamp(),
    }
    ttl = gateway["bodies"][0]["ttl"]
    assert ttl == settings.jwt_access_token_expire_minutes * 60 >= 300


def test_no_membership_asks_the_gateway_nothing(gateway):
    run(logout.revoke_team_sessions([], datetime.now(timezone.utc)))
    assert gateway["bodies"] == []


def test_no_gateway_secret_fails_the_revocation(gateway, monkeypatch):
    monkeypatch.delenv("GATEWAY_INTERNAL_SECRET")
    with pytest.raises(logout.RevocationError):
        run(logout.revoke_team_sessions([("u", "t")], datetime.now(timezone.utc)))
    assert gateway["bodies"] == []


# -- removing a member -----------------------------------------------------------


@pytest.mark.parametrize(
    "who",
    [
        {"by_role": TeamRole.OWNER},
        {"by_role": TeamRole.ADMIN},
        {"superuser": True},
    ],
    ids=["owner", "admin", "superuser"],
)
def test_the_member_s_team_sessions_end_at_the_gateway_before_the_removal(
    who, gateway, log, key_ids
):
    before = datetime.now(timezone.utc).timestamp()
    target = remove(log, **who)
    after = datetime.now(timezone.utc).timestamp()

    assert log == [
        "gateway:api_keys",
        "gateway:memberships",
        "delete:member",
        "commit",
    ]
    keys_body, sessions_body = gateway["bodies"]
    assert keys_body["api_keys"] == ["k-1"]
    (entry,) = sessions_body["memberships"]
    assert entry["user_id"] == str(target.user_id)
    assert entry["team_id"] == str(target.team_id)
    assert before <= entry["not_before"] <= after
    assert key_ids["calls"] == [
        {"user_id": target.user_id, "team_ids": [target.team_id]}
    ]


def test_removing_a_co_owner_ends_their_team_sessions_first(gateway, log, key_ids):
    remove(log, role=TeamRole.OWNER)
    assert log == ["gateway:api_keys", "gateway:memberships", "delete:owner", "commit"]


def test_the_member_stays_when_the_gateway_does_not_confirm_the_sessions(
    gateway, log, key_ids
):
    gateway["script"]["memberships"] = unconfirmed()
    with pytest.raises(HTTPException) as exc:
        remove(log)
    assert exc.value.status_code == 503
    assert log == ["gateway:api_keys"] + ["gateway:memberships"] * 3


def test_the_member_stays_when_the_gateway_is_unreachable(gateway, log, key_ids):
    key_ids["ids"] = []
    gateway["script"]["memberships"] = [httpx.ConnectError("refused")] * 3
    with pytest.raises(HTTPException) as exc:
        remove(log)
    assert exc.value.status_code == 503
    assert not any(entry.startswith("delete") or entry == "commit" for entry in log)


def test_the_sessions_are_not_touched_when_the_keys_are_not_confirmed(
    gateway, log, key_ids
):
    gateway["script"]["api_keys"] = unconfirmed()
    with pytest.raises(HTTPException) as exc:
        remove(log)
    assert exc.value.status_code == 503
    assert log == ["gateway:api_keys"] * 3


def test_a_refused_removal_asks_the_gateway_nothing(gateway, log, key_ids):
    """Removing oneself is refused before anything is revoked."""
    team_id = uuid.uuid4()
    me = caller()
    own = membership(team_id, TeamRole.OWNER, user_id=me.id)
    with pytest.raises(HTTPException) as exc:
        run(
            users.remove_team_member(
                str(team_id), str(me.id), me, FakeDB(log, own, own)
            )
        )
    assert exc.value.status_code == 400
    assert log == [] and gateway["bodies"] == []


def test_a_member_cannot_remove_another(gateway, log, key_ids):
    team_id = uuid.uuid4()
    with pytest.raises(HTTPException) as exc:
        run(
            users.remove_team_member(
                str(team_id), str(uuid.uuid4()), caller(), FakeDB(log, None)
            )
        )
    assert exc.value.status_code == 403
    assert gateway["bodies"] == []


# -- which team a session resolves -------------------------------------------------


def test_a_session_resolves_its_oldest_membership(monkeypatch):
    """What the removed member's next request gets: identity picks the
    oldest membership left, deterministically; the gateway does not choose."""
    monkeypatch.setattr(settings, "gateway_internal_secret", SECRET)

    async def not_blacklisted(_jti):
        return False

    from app import token_blacklist, user_manager

    monkeypatch.setattr(token_blacklist, "is_token_blacklisted", not_blacklisted)

    queries = []
    remaining = SimpleNamespace(id=uuid.uuid4())
    user = SimpleNamespace(
        id=uuid.uuid4(),
        email="m@example.com",
        is_active=True,
        tokens_valid_after=None,
        must_change_password=False,
    )

    class Session:
        async def execute(self, query):
            queries.append(query)
            return Result((user, remaining, SimpleNamespace(role="member")))

    token = run(user_manager.get_jwt_strategy().write_token(user))
    answer = run(
        internal.authorize_request(
            internal.TokenAuthRequest(token=token, token_type="bearer"),
            db=Session(),
            x_gateway_secret=SECRET,
        )
    )

    assert answer.team_id == str(remaining.id)
    sql = " ".join(str(queries[0]).split())
    assert "ORDER BY team_memberships.joined_at ASC, teams.id ASC" in sql
    assert "users.is_active IS true" in sql or "users.is_active = true" in sql
