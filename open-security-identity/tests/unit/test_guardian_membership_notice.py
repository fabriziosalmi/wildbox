"""identity tells guardian when a membership ends (#676).

guardian keeps its own record of the users a team can name -- assignees,
owners, the people a dashboard is shared with -- and nothing told it when
identity removed a member from a team: the removed member stayed one of the
team's users there for good.

These tests pin the notice and its contract, which is deliberately not the
gateway's (test_team_removal_sessions.py, test_api_key_revocation.py):

* guardian is told after the change is committed, never before;
* a notice guardian does not confirm is a failure that is logged, and it
  does not undo the removal or fail the request. Removing a member must not
  depend on guardian being up; guardian's own window on memberships is what
  holds when a notice is lost;
* when the change is refused (the gateway did not confirm), guardian is told
  nothing;
* the notice carries the internal secret in a header and nowhere else.

guardian and the gateway are patched at the HTTP transport and the database
by a stub that records what is written and when: no service is needed.
"""

import asyncio
import json
import logging
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import user_manager  # noqa: E402
from app import access_revocation, gateway_cache, guardian_memberships  # noqa: E402
from app.api_v1.endpoints import users  # noqa: E402
from app.guardian_memberships import CONFIRMED, DISABLED, FAILED  # noqa: E402
from app.models import TeamRole  # noqa: E402
from app.schemas import AccountDeletionRequest  # noqa: E402
from fastapi import HTTPException  # noqa: E402

SECRET = "unit-test-gateway-proof-of-origin"
GUARDIAN = "http://open-security-guardian:8013/internal/team-memberships/revoke/"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def log():
    """What happened, in order: gateway calls, database writes, the notice."""
    return []


@pytest.fixture
def network(monkeypatch, log):
    """The gateway and guardian at the HTTP transport.

    The gateway confirms what it is sent. guardian confirms too, unless a
    test scripts its answers (``state["guardian_script"]``) or the
    gateway's (``state["gateway_script"]``).
    """
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.delenv("GUARDIAN_INTERNAL_URL", raising=False)
    monkeypatch.setattr(gateway_cache, "_RETRY_DELAYS", (0, 0))
    monkeypatch.setattr(guardian_memberships, "_RETRY_DELAYS", (0, 0))
    state = {
        "guardian": [],
        "gateway": [],
        "guardian_script": [],
        "gateway_script": [],
        "requests": [],
    }

    def scripted(script):
        outcome = script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def handler(request):
        body = json.loads(request.content)
        (scope,) = [
            name
            for name in ("api_keys", "users", "memberships", "jtis")
            if name in body
        ]
        if (
            request.url.host == "open-security-guardian"
            or state.get("guardian_host") == request.url.host
        ):
            state["requests"].append(request)
            state["guardian"].append(body)
            log.append(f"guardian:{scope}")
            if state["guardian_script"]:
                return scripted(state["guardian_script"])
            return httpx.Response(
                200, json={"revoked": len(body[scope]), "scope": scope}
            )
        state["gateway"].append(body)
        log.append(f"gateway:{scope}")
        if state["gateway_script"]:
            return scripted(state["gateway_script"])
        return httpx.Response(
            200, json={"purged": True, "scope": scope, "revoked": len(body[scope])}
        )

    real_client = httpx.AsyncClient

    def client(**kwargs):
        state["client_kwargs"] = kwargs
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    return state


def down(times=3):
    return [httpx.ConnectError("refused")] * times


class Rows(list):
    def all(self):
        return list(self)


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        if isinstance(self.value, list):
            return Rows(self.value)
        return SimpleNamespace(first=lambda: self.value, all=lambda: [])

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
        self.log.append("delete")

    async def rollback(self):
        self.log.append("rollback")


class UserStore:
    """The parts of SQLAlchemyUserDatabase the manager uses, in memory."""

    def __init__(self, log):
        self.log = log
        self.session = object()

    async def update(self, user, update_dict):
        self.log.append("database:update")
        for name, value in update_dict.items():
            setattr(user, name, value)
        return user

    async def delete(self, user):
        self.log.append("database:delete")


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
def no_keys(monkeypatch):
    async def active_api_key_ids(db, *, user_id=None, team_ids=None):
        return []

    for module in (users, user_manager, access_revocation):
        monkeypatch.setattr(module, "active_api_key_ids", active_api_key_ids)


def remove_member(log):
    team_id = uuid.uuid4()
    member = SimpleNamespace(
        user_id=uuid.uuid4(), team_id=team_id, role=TeamRole.MEMBER
    )
    caller = SimpleNamespace(user_id=uuid.uuid4(), role=TeamRole.OWNER)
    answer = run(
        users.remove_team_member(
            str(team_id), str(member.user_id), make_user(), FakeDB(log, caller, member)
        )
    )
    return member, answer


# -- the notice --------------------------------------------------------------------


def test_guardian_is_told_which_member_left_which_team(network):
    outcome = run(
        guardian_memberships.notify_memberships_ended(
            [(uuid.UUID(int=1), uuid.UUID(int=2)), ("u-2", "t-2")]
        )
    )

    assert outcome == CONFIRMED
    assert network["guardian"] == [
        {
            "memberships": [
                {"user_id": str(uuid.UUID(int=1)), "team_id": str(uuid.UUID(int=2))},
                {"user_id": "u-2", "team_id": "t-2"},
            ]
        }
    ]
    (request,) = network["requests"]
    assert request.method == "POST"
    # The exact path, slash included: a redirect would drop the body.
    assert str(request.url) == GUARDIAN
    assert guardian_memberships.DEFAULT_URL == GUARDIAN


def test_guardian_is_told_which_accounts_are_gone(network):
    outcome = run(guardian_memberships.notify_accounts_ended([uuid.UUID(int=7), "u-8"]))

    assert outcome == CONFIRMED
    assert network["guardian"] == [{"users": [str(uuid.UUID(int=7)), "u-8"]}]


def test_the_secret_travels_in_a_header_and_nowhere_else(network):
    run(guardian_memberships.notify_memberships_ended([("u", "t")]))

    (request,) = network["requests"]
    assert request.headers["X-Gateway-Secret"] == SECRET
    assert SECRET not in str(request.url)
    assert SECRET not in request.content.decode()
    # A redirect is not followed: it is not guardian's confirmation, and the
    # secret would follow it.
    assert network["client_kwargs"]["follow_redirects"] is False


def test_nothing_ended_tells_guardian_nothing(network):
    assert run(guardian_memberships.notify_memberships_ended([])) == CONFIRMED
    assert run(guardian_memberships.notify_accounts_ended([])) == CONFIRMED
    assert network["guardian"] == []


def test_many_memberships_go_in_notices_guardian_accepts(network):
    pairs = [(f"u-{n}", "t") for n in range(2500)]

    assert run(guardian_memberships.notify_memberships_ended(pairs)) == CONFIRMED

    assert [len(body["memberships"]) for body in network["guardian"]] == [
        1000,
        1000,
        500,
    ]


def _not_confirmations():
    wrong_count = httpx.Response(200, json={"revoked": 0, "scope": "memberships"})
    wrong_scope = httpx.Response(200, json={"revoked": 1, "scope": "users"})
    return [
        pytest.param([wrong_count] * 3, id="counted-nothing"),
        pytest.param([wrong_scope] * 3, id="another-scope"),
        pytest.param(
            [httpx.Response(200, json={"status": "ok"})] * 3, id="200-without-a-count"
        ),
        pytest.param([httpx.Response(200, text="OK")] * 3, id="200-not-json"),
        pytest.param(
            [httpx.Response(403, json={"code": "GATEWAY_SECRET_REQUIRED"})] * 3,
            id="403",
        ),
        pytest.param([httpx.Response(503, json={"code": "x"})] * 3, id="503"),
        pytest.param([httpx.Response(500, text="boom")] * 3, id="500"),
        pytest.param(
            [httpx.Response(400, json={"error": "invalid_request"})] * 3, id="400"
        ),
        pytest.param(
            [
                httpx.Response(
                    301, headers={"Location": "https://open-security-guardian:8013/x"}
                )
            ]
            * 3,
            id="redirected",
        ),
        pytest.param(down(), id="unreachable"),
        pytest.param([httpx.ReadTimeout("slow")] * 3, id="timeout"),
    ]


@pytest.mark.parametrize("answers", _not_confirmations())
def test_a_notice_guardian_does_not_confirm_fails_without_raising(
    network, answers, caplog
):
    network["guardian_script"] = list(answers)

    with caplog.at_level(logging.WARNING, logger="app.guardian_memberships"):
        outcome = run(guardian_memberships.notify_memberships_ended([("u", "t")]))

    assert outcome == FAILED
    # Tried three times, like every call identity makes to the gateway.
    assert len(network["guardian"]) == 3
    errors = [record for record in caplog.records if record.levelno == logging.ERROR]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert "guardian was not told of 1 ended memberships" in message
    # What stays true, for whoever reads the log.
    assert "GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS" in message
    assert SECRET not in caplog.text


def test_a_notice_is_retried_until_guardian_confirms(network):
    network["guardian_script"] = [
        httpx.ConnectError("refused"),
        httpx.Response(503, text="starting"),
    ]

    assert run(guardian_memberships.notify_accounts_ended(["u"])) == CONFIRMED
    assert len(network["guardian"]) == 3


def test_a_failed_notice_stops_at_the_chunk_that_failed(network):
    network["guardian_script"] = down()
    pairs = [(f"u-{n}", "t") for n in range(1500)]

    assert run(guardian_memberships.notify_memberships_ended(pairs)) == FAILED
    assert len(network["guardian"]) == 3


def test_without_the_internal_secret_guardian_cannot_be_told(
    network, monkeypatch, caplog
):
    monkeypatch.delenv("GATEWAY_INTERNAL_SECRET")

    with caplog.at_level(logging.ERROR, logger="app.guardian_memberships"):
        outcome = run(guardian_memberships.notify_memberships_ended([("u", "t")]))

    assert outcome == FAILED
    assert network["guardian"] == []
    assert "GATEWAY_INTERNAL_SECRET is not set" in caplog.text


def test_a_deployment_without_guardian_switches_the_notice_off(network, monkeypatch):
    monkeypatch.setenv("GUARDIAN_INTERNAL_URL", "  ")

    assert run(guardian_memberships.notify_memberships_ended([("u", "t")])) == DISABLED
    assert run(guardian_memberships.notify_accounts_ended(["u"])) == DISABLED
    assert network["guardian"] == []


def test_guardian_can_be_somewhere_else(network, monkeypatch):
    network["guardian_host"] = "guardian.internal"
    monkeypatch.setenv(
        "GUARDIAN_INTERNAL_URL",
        "http://guardian.internal:9000/internal/team-memberships/revoke/",
    )

    assert run(guardian_memberships.notify_accounts_ended(["u"])) == CONFIRMED
    (request,) = network["requests"]
    assert (
        str(request.url)
        == "http://guardian.internal:9000/internal/team-memberships/revoke/"
    )


def test_an_unset_url_means_the_default_and_an_empty_one_means_off(monkeypatch):
    monkeypatch.delenv("GUARDIAN_INTERNAL_URL", raising=False)
    assert guardian_memberships.guardian_url() == GUARDIAN
    monkeypatch.setenv("GUARDIAN_INTERNAL_URL", "")
    assert guardian_memberships.guardian_url() == ""


# -- removing a member ---------------------------------------------------------------


def test_guardian_is_told_after_the_member_is_removed(network, log, no_keys):
    member, answer = remove_member(log)

    assert log == ["gateway:memberships", "delete", "commit", "guardian:memberships"]
    assert network["guardian"] == [
        {
            "memberships": [
                {"user_id": str(member.user_id), "team_id": str(member.team_id)}
            ]
        }
    ]
    assert answer == {"message": "Member removed successfully"}


def test_a_member_is_removed_even_when_guardian_is_down(network, log, no_keys, caplog):
    """Offboarding does not wait for the vulnerability service."""
    network["guardian_script"] = down()

    with caplog.at_level(logging.ERROR, logger="app.guardian_memberships"):
        _, answer = remove_member(log)

    assert answer == {"message": "Member removed successfully"}
    assert (
        log
        == ["gateway:memberships", "delete", "commit"] + ["guardian:memberships"] * 3
    )
    assert "guardian was not told of 1 ended memberships (ConnectError)" in caplog.text


def test_guardian_is_told_nothing_when_the_member_is_not_removed(network, log, no_keys):
    network["gateway_script"] = [
        httpx.Response(200, json={"purged": True, "scope": "all", "revoked": 0})
    ] * 3

    with pytest.raises(HTTPException) as exc:
        remove_member(log)

    assert exc.value.status_code == 503
    assert "commit" not in log
    assert network["guardian"] == []


def test_guardian_is_told_nothing_when_the_removal_is_refused(network, log, no_keys):
    with pytest.raises(HTTPException) as exc:
        run(
            users.remove_team_member(
                str(uuid.uuid4()), str(uuid.uuid4()), make_user(), FakeDB(log, None)
            )
        )

    assert exc.value.status_code == 403
    assert network["guardian"] == []


# -- deleting an account --------------------------------------------------------------


def test_guardian_is_told_after_an_administrator_deletes_an_account(
    network, log, no_keys
):
    target = make_user(email="bob@example.com", team_memberships=[SimpleNamespace()])

    run(
        users.delete_user(
            str(target.id), False, make_user(is_superuser=True), FakeDB(log, target)
        )
    )

    assert log[-2:] == ["commit", "guardian:users"]
    assert log.index("commit") > log.index("gateway:users")
    assert network["guardian"] == [{"users": [str(target.id)]}]


def test_guardian_is_told_after_the_users_api_deletes_an_account(network, log, no_keys):
    target = make_user(email="bob@example.com")

    run(user_manager.UserManager(UserStore(log)).delete(target))

    assert log == ["gateway:users", "database:delete", "guardian:users"]
    assert network["guardian"] == [{"users": [str(target.id)]}]


def test_guardian_is_told_after_someone_deletes_their_own_account(
    network, log, no_keys, monkeypatch
):
    async def password_ok(user, password, wrong_detail=None):
        return None

    monkeypatch.setattr(users, "verify_current_password", password_ok)
    me = make_user()

    run(
        users.delete_my_account(
            AccountDeletionRequest(password="x", confirm_deletion=True),
            me,
            FakeDB(log, []),
        )
    )

    assert log == ["gateway:users", "commit", "guardian:users"]
    assert network["guardian"] == [{"users": [str(me.id)]}]


def test_an_account_is_deleted_even_when_guardian_is_down(network, log, no_keys):
    network["guardian_script"] = down()
    target = make_user(email="bob@example.com")

    run(user_manager.UserManager(UserStore(log)).delete(target))

    assert log == ["gateway:users", "database:delete"] + ["guardian:users"] * 3


def test_guardian_is_told_nothing_when_an_account_is_not_deleted(network, log, no_keys):
    network["gateway_script"] = [
        httpx.Response(200, json={"purged": True, "scope": "all", "revoked": 0})
    ] * 3
    target = make_user(email="bob@example.com")

    with pytest.raises(HTTPException) as exc:
        run(user_manager.UserManager(UserStore(log)).delete(target))

    assert exc.value.status_code == 503
    assert "database:delete" not in log
    assert network["guardian"] == []


# -- what is not a membership ending ---------------------------------------------------


def test_deactivating_an_account_tells_guardian_nothing(network, log, no_keys):
    """A deactivated account keeps its memberships and can come back.

    Telling guardian it left would clear its assignments for good on an
    action that is meant to be undone. It cannot authenticate, so its
    memberships age out in guardian by themselves.
    """
    target = make_user(email="bob@example.com")

    run(
        users.update_user_status(
            str(target.id), False, make_user(is_superuser=True), FakeDB(log, target)
        )
    )

    assert target.is_active is False
    assert log == ["gateway:users", "commit"]
    assert network["guardian"] == []
