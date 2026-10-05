"""Who guardian may e-mail about a team: POST /internal/team-contacts (#705).

guardian mirrors identity's users by id and holds no address, so its e-mails
about a team's vulnerabilities, alerts and compliance findings had nowhere
to go. Its worker asks identity, when it is about to send: the address of a
named member, or the owners and admins of a team. The answer is where a
team's data will be sent, so what is tested here is that it can only ever
name active members of the team asked about, and only to a caller that
holds the secret made for this route.

The database is a stub. The query is checked as SQL, compiled for
PostgreSQL, and the rows are checked again in Python
(``select_contacts``), which the vectors shared with guardian's tests run
against rows of every team, as if the query had returned too much.
"""

import json
import logging
import os
import re
import sys
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import team_contacts  # noqa: E402
from app.config import Settings, settings  # noqa: E402
from app.database import get_db  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from sqlalchemy.dialects import postgresql  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads(
    (REPO_ROOT / "tests" / "shared" / "team_contacts_vectors.json").read_text()
)
ROUTE = "/internal/team-contacts"
SECRET = "c0ntacts-" + "0123456789abcdef" * 3
GATEWAY_SECRET = "gateway-" + "fedcba9876543210" * 3
HEADER = "X-Guardian-Contacts-Secret"

# The names the vectors use, as ids.
_IDS = {}


def _id(name):
    return _IDS.setdefault(name, uuid.uuid5(uuid.NAMESPACE_DNS, f"{name}.vectors"))


def _rows(members=None):
    """Rows as the query returns them: id, email, is_active, team, role."""
    return [
        (
            _id(member["user"]),
            member["email"],
            member["active"],
            _id("team-" + member["team"]),
            member["role"],
        )
        for member in (VECTORS["members"] if members is None else members)
    ]


def _payload(case):
    payload = {"team_id": str(_id("team-" + case["team"]))}
    if "users" in case:
        payload["user_ids"] = [str(_id(user)) for user in case["users"]]
    else:
        payload["roles"] = case["roles"]
    return payload


def _expected(case):
    emails = {
        (member["team"], member["user"]): member["email"]
        for member in VECTORS["members"]
    }
    return [
        {
            "user_id": str(_id(user)),
            "email": emails[(case["team"], user)],
            "role": role,
        }
        for user, role in case["expect"]
    ]


class Db:
    """A session whose query returns the given rows, whatever it asked."""

    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    async def execute(self, query):
        self.queries.append(query)
        rows = self.rows
        return type("Result", (), {"all": lambda self: rows})()


@pytest.fixture
def db():
    return Db(_rows())


@pytest.fixture
def client(monkeypatch, db):
    monkeypatch.setattr(settings, "guardian_contacts_secret", SECRET)
    monkeypatch.setattr(settings, "gateway_internal_secret", GATEWAY_SECRET)

    async def the_db():
        yield db

    app.dependency_overrides[get_db] = the_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _ask(client, payload, secret=SECRET):
    headers = {HEADER: secret} if secret is not None else {}
    return client.post(ROUTE, json=payload, headers=headers)


ADMINS_OF_A = {"team_id": str(_id("team-A")), "roles": ["owner", "admin"]}


# --- the vectors guardian's stand-in also answers ----------------------------------


def test_there_are_vectors():
    assert len(VECTORS["cases"]) >= 12
    assert {member["team"] for member in VECTORS["members"]} == {"A", "B"}


@pytest.mark.parametrize(
    "case", VECTORS["cases"], ids=[case["name"] for case in VECTORS["cases"]]
)
def test_only_the_selected_active_members_of_the_team_are_answered(client, case):
    """The rows are every team's: what the query should never return."""
    response = _ask(client, _payload(case))

    assert response.status_code == 200, response.text
    assert response.json() == {
        "team_id": str(_id("team-" + case["team"])),
        "contacts": _expected(case),
    }


def test_a_user_is_answered_once(client, db):
    db.rows = _rows() + _rows()

    contacts = _ask(client, ADMINS_OF_A).json()["contacts"]

    assert [contact["email"] for contact in contacts] == [
        "ann@a.example",
        "bob@a.example",
    ]


def test_a_role_identity_does_not_have_is_not_answered(client, db):
    db.rows = [(_id("zed"), "zed@a.example", True, _id("team-A"), "superuser")]
    by_user = {"team_id": str(_id("team-A")), "user_ids": [str(_id("zed"))]}

    assert _ask(client, ADMINS_OF_A).json()["contacts"] == []
    assert _ask(client, by_user).json()["contacts"] == []


@pytest.mark.parametrize("active", [None, 1, "true", False])
def test_only_an_account_that_is_active_is_answered(client, db, active):
    db.rows = [(_id("zed"), "zed@a.example", active, _id("team-A"), "owner")]

    assert _ask(client, ADMINS_OF_A).json()["contacts"] == []


# --- the query ------------------------------------------------------------------------


def _sql(payload):
    query = team_contacts.contacts_query(team_contacts.TeamContactsRequest(**payload))
    return " ".join(
        str(
            query.compile(
                dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
            )
        ).split()
    )


def test_the_query_is_about_one_team_and_active_accounts():
    team = _id("team-A")
    sql = _sql({"team_id": str(team), "roles": ["owner", "admin"]})

    assert "JOIN team_memberships ON team_memberships.user_id = users.id" in sql
    where = sql.split(" WHERE ", 1)[1].split(" ORDER BY ")[0]
    conditions = where.split(" AND ")
    assert f"team_memberships.team_id = '{team}'" in conditions
    assert "users.is_active IS true" in conditions
    assert "team_memberships.role IN ('owner', 'admin')" in conditions
    assert len(conditions) == 3
    # No OR anywhere: nothing widens it.
    assert not re.search(r"\bOR\b", sql)


def test_the_query_by_user_stays_in_the_team():
    team, ann, fay = _id("team-A"), _id("ann"), _id("fay")
    sql = _sql({"team_id": str(team), "user_ids": [str(ann), str(fay)]})

    conditions = sql.split(" WHERE ", 1)[1].split(" ORDER BY ")[0].split(" AND ")
    assert f"team_memberships.team_id = '{team}'" in conditions
    assert "users.is_active IS true" in conditions
    assert f"users.id IN ('{ann}', '{fay}')" in conditions
    assert len(conditions) == 3
    assert not re.search(r"\bOR\b", sql)


def test_the_route_runs_that_query(client, db):
    _ask(client, ADMINS_OF_A)

    (query,) = db.queries
    compiled = str(
        query.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert " ".join(compiled.split()) == _sql(ADMINS_OF_A)


# --- the caller -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [None, "", "wrong", SECRET[:-1], SECRET + "0", SECRET.upper(), GATEWAY_SECRET],
    ids=["none", "empty", "wrong", "prefix", "longer", "other-case", "the-gateway's"],
)
def test_a_caller_without_the_secret_is_refused(client, db, secret):
    response = _ask(client, ADMINS_OF_A, secret=secret)

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "Invalid contacts secret"
    assert db.queries == []


def test_the_gateway_secret_header_is_not_a_way_in(client, db):
    """X-Gateway-Secret opens /internal/authorize; it opens nothing here."""
    for headers in (
        {"X-Gateway-Secret": GATEWAY_SECRET},
        {"X-Gateway-Secret": SECRET},
        {"Authorization": f"Bearer {SECRET}"},
    ):
        response = client.post(ROUTE, json=ADMINS_OF_A, headers=headers)
        assert response.status_code == 403, headers
    assert db.queries == []


@pytest.mark.parametrize("unset", [None, ""])
def test_without_a_secret_configured_nobody_is_the_caller(
    client, db, monkeypatch, unset
):
    monkeypatch.setattr(settings, "guardian_contacts_secret", unset)

    for secret in (None, "", SECRET):
        response = _ask(client, ADMINS_OF_A, secret=secret)
        assert response.status_code == 503
        assert "GUARDIAN_CONTACTS_SECRET" in response.json()["error"]["message"]
    assert db.queries == []


def test_the_secret_is_decided_before_the_body_is_read(client, db):
    """A caller without it learns nothing from how a body is refused."""
    nonsense = {"team_id": "not-a-uuid", "everything": True}

    assert _ask(client, nonsense, secret="wrong").status_code == 403
    assert _ask(client, nonsense, secret=None).status_code == 403
    assert _ask(client, nonsense).status_code == 422
    assert db.queries == []


@pytest.mark.parametrize("method", ["get", "put", "delete", "patch"])
def test_only_post_is_served(client, method):
    response = getattr(client, method)(ROUTE, headers={HEADER: SECRET})

    assert response.status_code == 405


# --- the question ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"team_id": str(_id("team-A"))},
        {"roles": ["owner"]},
        {"team_id": "", "roles": ["owner"]},
        {"team_id": "not-a-uuid", "roles": ["owner"]},
        {"team_id": str(_id("team-A")), "roles": []},
        {"team_id": str(_id("team-A")), "roles": ["superuser"]},
        {"team_id": str(_id("team-A")), "roles": ["owner", "*"]},
        {"team_id": str(_id("team-A")), "roles": "owner"},
        {"team_id": str(_id("team-A")), "user_ids": []},
        {"team_id": str(_id("team-A")), "user_ids": ["not-a-uuid"]},
        {
            "team_id": str(_id("team-A")),
            "user_ids": [str(_id("ann"))],
            "roles": ["owner"],
        },
        {"team_id": str(_id("team-A")), "roles": ["owner"], "all": True},
        {"team_id": str(_id("team-A")), "roles": ["owner"], "include_inactive": True},
        {"team_id": [str(_id("team-A")), str(_id("team-B"))], "roles": ["owner"]},
        {
            "team_id": str(_id("team-A")),
            "user_ids": [
                str(uuid.uuid4()) for _ in range(team_contacts.MAX_USER_IDS + 1)
            ],
        },
    ],
    ids=[
        "empty",
        "no-selection",
        "no-team",
        "empty-team",
        "bad-team",
        "no-roles",
        "unknown-role",
        "wildcard-role",
        "roles-not-a-list",
        "no-users",
        "bad-user",
        "both-selections",
        "unknown-field",
        "inactive-asked-for",
        "two-teams",
        "too-many-users",
    ],
)
def test_a_question_it_does_not_fully_understand_is_refused(client, db, payload):
    """There is no way to ask for a whole team, another team, or the inactive."""
    response = _ask(client, payload)

    assert response.status_code == 422, response.text
    assert db.queries == []


def test_the_most_users_one_question_may_name_is_accepted(client):
    payload = {
        "team_id": str(_id("team-A")),
        "user_ids": [str(uuid.uuid4()) for _ in range(team_contacts.MAX_USER_IDS)],
    }

    assert _ask(client, payload).status_code == 200


# --- what is written down --------------------------------------------------------------


def test_no_address_is_logged(client, caplog):
    with caplog.at_level(logging.DEBUG):
        response = _ask(client, ADMINS_OF_A)

    assert len(response.json()["contacts"]) == 2
    assert "Team contacts answered" in caplog.text
    assert "2 contact(s) by role" in caplog.text
    assert "@a.example" not in caplog.text
    assert SECRET not in caplog.text


def test_a_refusal_does_not_log_what_was_presented(client, caplog):
    with caplog.at_level(logging.DEBUG):
        _ask(client, ADMINS_OF_A, secret="presented-by-somebody-else")

    assert "missing or wrong secret" in caplog.text
    assert "presented-by-somebody-else" not in caplog.text
    assert SECRET not in caplog.text


# --- where the route is ----------------------------------------------------------------


def test_the_route_is_under_internal_only():
    served = app.openapi()["paths"]

    assert [path for path in served if "team-contacts" in path] == [ROUTE]
    assert list(served[ROUTE]) == ["post"]


def test_the_gateway_proxies_nothing_of_identity_s_internal_routes():
    conf = (
        REPO_ROOT / "open-security-gateway/nginx/conf.d/wildbox_gateway.conf"
    ).read_text()
    targets = set(re.findall(r"proxy_pass http://identity_service(\S*);", conf))

    assert targets, "the gateway reaches identity somewhere"
    assert all(
        target.startswith("/api/v1/") or target == "/health" for target in targets
    ), targets
    assert "team-contacts" not in conf


# --- the secret itself -----------------------------------------------------------------

_BASE = {
    "database_url": "postgresql://test:test@localhost:5432/test",
    "jwt_secret_key": "j" * 16 + "0123456789abcdef",
    "gateway_internal_secret": GATEWAY_SECRET,
}


def _settings(**values):
    return Settings(_env_file=None, **{**_BASE, **values})


def test_a_secret_of_its_own_is_accepted():
    assert _settings(guardian_contacts_secret=SECRET).guardian_contacts_secret == SECRET


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_an_empty_secret_is_no_secret(blank):
    assert _settings(guardian_contacts_secret=blank).guardian_contacts_secret is None


@pytest.mark.parametrize(
    "other", ["gateway_internal_secret", "jwt_secret_key", "api_key_hash_secret"]
)
def test_identity_does_not_start_with_another_secret_s_value(other):
    """The worker would hold the gateway's secret under another name."""
    shared = "5hared-" + "0123456789abcdef" * 3
    with pytest.raises(ValidationError) as refused:
        _settings(**{other: shared, "guardian_contacts_secret": shared})

    message = str(refused.value)
    assert f"must not be the value of {other.upper()}" in message
    assert shared not in message


@pytest.mark.parametrize(
    "weak,why",
    [
        ("short", "at least 32 characters"),
        ("a" * 31, "at least 32 characters"),
        ("change-me-" + "0123456789abcdef" * 2, "placeholder"),
        ("ab" * 20, "too little entropy"),
    ],
)
def test_identity_does_not_start_with_a_weak_secret(weak, why):
    with pytest.raises(ValidationError) as refused:
        _settings(guardian_contacts_secret=weak)

    message = str(refused.value)
    assert "GUARDIAN_CONTACTS_SECRET" in message and why in message
    assert weak not in message
