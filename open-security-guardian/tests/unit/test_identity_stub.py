"""The stand-in for identity answers as identity's route does (#705).

guardian's tests ask ``tests/unit/identity_stub.py`` who may be e-mailed
about a team, in identity's place. A stand-in more generous than the real
route would make those tests pass on a guardian that e-mails people identity
would never name. The cases in ``tests/shared/team_contacts_vectors.json``
are run here against the stand-in and, in identity's own unit tests,
against the route (open-security-identity/tests/unit/test_team_contacts.py):
the same questions, the same answers.

The names both sides must agree on (the route, the header) are compared
with identity's source.
"""

import json
import pathlib
import re
import uuid

import pytest
from apps.core import notifications
from guardian.mailconf import TEAM_CONTACTS_URL_DEFAULT

from tests.unit import identity_stub

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS = json.loads(
    (REPO_ROOT / "tests" / "shared" / "team_contacts_vectors.json").read_text()
)
IDENTITY = REPO_ROOT / "open-security-identity" / "app"


def _id(name):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{name}.vectors"))


@pytest.fixture
def identity():
    stub = identity_stub.Identity()
    for member in VECTORS["members"]:
        stub.add(
            _id("team-" + member["team"]),
            _id(member["user"]),
            member["email"],
            role=member["role"],
            active=member["active"],
        )
    return stub


def _payload(case):
    payload = {"team_id": _id("team-" + case["team"])}
    if "users" in case:
        payload["user_ids"] = [_id(user) for user in case["users"]]
    else:
        payload["roles"] = case["roles"]
    return payload


def test_there_are_vectors():
    assert len(VECTORS["cases"]) >= 12


@pytest.mark.parametrize(
    "case", VECTORS["cases"], ids=[case["name"] for case in VECTORS["cases"]]
)
def test_the_stand_in_answers_as_identity_does(identity, case):
    emails = {
        (member["team"], member["user"]): member["email"]
        for member in VECTORS["members"]
    }

    response = identity.post(
        identity_stub.URL,
        json=_payload(case),
        headers={notifications.CONTACTS_SECRET_HEADER: identity_stub.SECRET},
    )

    assert response.status_code == 200
    assert response.json() == {
        "team_id": _id("team-" + case["team"]),
        "contacts": [
            {"user_id": _id(user), "email": emails[(case["team"], user)], "role": role}
            for user, role in case["expect"]
        ],
    }


@pytest.mark.parametrize("secret", [None, "", "wrong", identity_stub.SECRET[:-1]])
def test_the_stand_in_refuses_without_the_secret(identity, secret):
    headers = {} if secret is None else {notifications.CONTACTS_SECRET_HEADER: secret}

    response = identity.post(
        identity_stub.URL, json=_payload(VECTORS["cases"][0]), headers=headers
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "payload",
    [
        {"team_id": _id("team-A")},
        {"team_id": _id("team-A"), "roles": []},
        {"team_id": _id("team-A"), "roles": ["superuser"]},
        {"team_id": _id("team-A"), "user_ids": []},
        {"team_id": _id("team-A"), "user_ids": [_id("ann")], "roles": ["owner"]},
        {"team_id": _id("team-A"), "roles": ["owner"], "all": True},
    ],
)
def test_the_stand_in_refuses_what_identity_refuses(identity, payload):
    response = identity.post(
        identity_stub.URL,
        json=payload,
        headers={notifications.CONTACTS_SECRET_HEADER: identity_stub.SECRET},
    )

    assert response.status_code == 422


# --- the names both services use --------------------------------------------------------


def _constant(source, name):
    match = re.search(rf'^{name} = "?([^"\n]*)"?$', source, flags=re.MULTILINE)
    assert match, name
    return match.group(1)


def test_guardian_and_identity_name_the_same_header_and_route():
    route = (IDENTITY / "team_contacts.py").read_text()
    config = (IDENTITY / "config.py").read_text()

    assert _constant(route, "SECRET_HEADER") == notifications.CONTACTS_SECRET_HEADER
    assert '"/team-contacts"' in route
    prefix = re.search(r'internal_api_prefix: str = "([^"]+)"', config).group(1)
    assert TEAM_CONTACTS_URL_DEFAULT.endswith(f"{prefix}/team-contacts")
    assert int(_constant(route, "MAX_USER_IDS")) == notifications.CONTACTS_MAX_USER_IDS


def test_guardian_asks_for_roles_identity_has():
    models = (IDENTITY / "models.py").read_text()
    roles = set(re.findall(r'^    [A-Z]+ = "([a-z]+)"$', models, flags=re.MULTILINE))

    assert roles == set(notifications.ROLES) == set(identity_stub.ROLES)
    assert set(notifications.DEFAULT_RECIPIENT_ROLES) == {"owner", "admin"}
