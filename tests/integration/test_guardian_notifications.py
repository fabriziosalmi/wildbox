"""Guardian's notifications are addressed to their own team's people (#705).

Guardian mirrors identity's users by id and holds no e-mail address, so its
e-mails had nowhere to go. Its worker now asks identity, when it is about to
send, who may be told about the team: here, the owners and admins of the
team an alert rule belongs to, since the rule names no recipients.

Two accounts are registered, each the owner of its own team, and each
creates an alert rule through the gateway. What is asserted is the record
guardian keeps of every notification
(``GET /api/v1/guardian/reports/alerts/{id}/notifications/``): who it was
addressed to, whether it was delivered and, if not, why.

* Each team's notification is addressed to that team's owner, by the
  address identity holds, and not to the other team's.
* An admin the owner creates is addressed from the next notification on,
  without ever having called guardian; removed from the team, they are not
  addressed any more.
* The stack under test has no mail server, so nothing is delivered and the
  record says so. A stack that has one delivers, and the record says that.

This needs ``GUARDIAN_CONTACTS_SECRET`` on identity and guardian-worker
(``scripts/generate_secrets.py`` writes it), and guardian-worker running.
The route the worker asks is not one a client can reach: the last tests ask
it through the gateway, and directly without the secret.

The secret is optional: a deployment has it once its operator opts in to
guardian's e-mail, and a stack upgraded from an earlier release does not
until then. identity says so itself (503, naming the variable), and on such
a stack the tests that need it are skipped with that reason, as the suite
skips its other optional parts. They used to fail there (#779). Under
``REQUIRE_ALL_SERVICES``, which the CI jobs set for a stack made by
``generate_secrets.py``, a missing secret is a failure, not a skip.
"""

import os
import secrets
import time
import uuid

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
TIMEOUT = 15
# The worker evaluates a queued check within seconds; allow for a busy one.
WAIT_SECONDS = 90

GUARDIAN_API = f"{GATEWAY_URL}/api/v1/guardian"
IDENTITY_API = f"{GATEWAY_URL}/api/v1/identity"
ALERTS = f"{GUARDIAN_API}/reports/alerts/"
ASSETS = f"{GUARDIAN_API}/assets/assets/"

NO_MAIL_SERVER = "no mail server is configured"


def _new_owner():
    """(address, bearer headers) of a new account: the owner of its team."""
    address = f"guardian-notify-{secrets.token_hex(6)}@example.com"
    password = f"Guardian-Notify-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": address, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": address, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    return address, {"Authorization": f"Bearer {login.json()['access_token']}"}


def _team_of(headers):
    response = requests.get(ASSETS, headers=headers, timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:200]
    return response.headers["X-Wildbox-Team-ID"]


def _rule(headers, threshold=0):
    """An alert rule that names no recipients, firing as soon as it is checked."""
    created = requests.post(
        ALERTS,
        json={
            "name": f"it-notify-{secrets.token_hex(6)}",
            "data_source": "vulnerabilities.unresolved",
            "condition_type": "threshold",
            "operator": "gte",
            "threshold_value": threshold,
        },
        headers=headers,
        timeout=TIMEOUT,
    )
    assert created.status_code == 201, created.text[:300]
    return created.json()["id"]


def _notifications(headers, rule_id):
    response = requests.get(
        f"{ALERTS}{rule_id}/notifications/", headers=headers, timeout=TIMEOUT
    )
    assert response.status_code == 200, response.text[:300]
    body = response.json()
    rows = body["results"] if isinstance(body, dict) else body
    # Newest first; the tests read them in the order they happened.
    return rows[::-1]


def _check(headers, rule_id, expected):
    """Queue a check of the team's rules; the rule's notifications once there are ``expected``."""
    queued = requests.post(f"{ALERTS}check_all/", headers=headers, timeout=TIMEOUT)
    assert queued.status_code in (200, 202), queued.text[:300]
    deadline = time.monotonic() + WAIT_SECONDS
    rows = []
    while time.monotonic() < deadline:
        rows = _notifications(headers, rule_id)
        # Recorded first, addressed and delivered right after: wait for both.
        if len(rows) >= expected and (
            rows[-1]["delivered"] or rows[-1]["failure_reason"]
        ):
            return rows
        time.sleep(2)
    pytest.fail(
        f"guardian-worker recorded {len(rows)} of {expected} notifications "
        f"within {WAIT_SECONDS}s: {rows}"
    )


def _set_threshold(headers, rule_id, threshold):
    changed = requests.patch(
        f"{ALERTS}{rule_id}/",
        json={"threshold_value": threshold},
        headers=headers,
        timeout=TIMEOUT,
    )
    assert changed.status_code == 200, changed.text[:300]


def _outcome(row):
    """Delivered, or not and why: the two answers a healthy stack can give."""
    outcome = (row["delivered"], row["failure_reason"])
    assert outcome in ((False, NO_MAIL_SERVER), (True, "")), row
    return outcome


def _contacts_not_configured():
    """Why identity cannot name a team's contacts, or None when it can.

    Asked without a secret: an identity that has ``GUARDIAN_CONTACTS_SECRET``
    refuses (403), one that has not says that it is not configured (503).
    """
    answer = requests.post(
        f"{IDENTITY_URL}/internal/team-contacts",
        json={"team_id": str(uuid.uuid4()), "roles": ["owner"]},
        timeout=TIMEOUT,
    )
    if answer.status_code == 503 and "GUARDIAN_CONTACTS_SECRET" in answer.text:
        return (
            "identity has no GUARDIAN_CONTACTS_SECRET, so guardian's worker "
            "cannot ask it who to e-mail: set it in the stack's .env "
            "(see .env.example) and recreate identity and guardian-worker"
        )
    return None


@pytest.fixture(scope="module")
def contacts_configured():
    """Skip, or fail where the stack must have everything, without the secret."""
    reason = _contacts_not_configured()
    if reason is None:
        return
    if os.getenv("REQUIRE_ALL_SERVICES", "") in ("1", "true", "yes"):
        pytest.fail(
            f"{reason}. REQUIRE_ALL_SERVICES is set: the stack is expected "
            "to have it, so these tests must not be skipped",
            pytrace=False,
        )
    pytest.skip(reason)


@pytest.fixture
def owners():
    return _new_owner(), _new_owner()


def test_a_notification_is_addressed_to_its_own_teams_owner(
    contacts_configured, owners
):
    (address_a, a), (address_b, b) = owners
    rule_a, rule_b = _rule(a), _rule(b)
    try:
        (first_a,) = _check(a, rule_a, 1)
        (first_b,) = _check(b, rule_b, 1)

        assert first_a["kind"] == first_b["kind"] == "firing"
        # By the address identity holds: guardian has none of its own.
        assert first_a["recipients"] == [address_a]
        assert first_b["recipients"] == [address_b]
        _outcome(first_a)
        _outcome(first_b)
        # A team does not read another's record.
        hidden = requests.get(
            f"{ALERTS}{rule_a}/notifications/", headers=b, timeout=TIMEOUT
        )
        assert hidden.status_code == 404, hidden.text[:200]
    finally:
        requests.delete(f"{ALERTS}{rule_a}/", headers=a, timeout=TIMEOUT)
        requests.delete(f"{ALERTS}{rule_b}/", headers=b, timeout=TIMEOUT)


def test_who_is_addressed_follows_identity(contacts_configured, owners):
    """An admin is addressed once made one, and no more once removed."""
    (address_a, a), _ = owners
    team_id = _team_of(a)
    rule = _rule(a)
    try:
        (firing,) = _check(a, rule, 1)
        assert firing["recipients"] == [address_a]

        # An admin of the team who never calls guardian.
        admin_address = f"guardian-notify-admin-{secrets.token_hex(6)}@example.com"
        created = requests.post(
            f"{IDENTITY_API}/admin/teams/{team_id}/members",
            json={
                "email": admin_address,
                "password": f"Guardian-Notify-{secrets.token_hex(8)}!",
                "role": "admin",
            },
            headers=a,
            timeout=TIMEOUT,
        )
        assert created.status_code == 201, created.text[:200]
        admin_id = created.json()["user_id"]

        _set_threshold(a, rule, 10**6)
        _, resolved = _check(a, rule, 2)
        assert resolved["kind"] == "resolved"
        assert sorted(resolved["recipients"]) == sorted([address_a, admin_address])

        removed = requests.delete(
            f"{IDENTITY_API}/admin/teams/{team_id}/members/{admin_id}",
            headers=a,
            timeout=TIMEOUT,
        )
        assert removed.status_code == 200, removed.text[:200]

        _set_threshold(a, rule, 0)
        _, _, again = _check(a, rule, 3)
        assert again["kind"] == "firing"
        assert again["recipients"] == [address_a]
        _outcome(again)
    finally:
        requests.delete(f"{ALERTS}{rule}/", headers=a, timeout=TIMEOUT)


# --- the route the worker asks is not a client's ---------------------------------------

CONTACTS_PATHS = (
    "/internal/team-contacts",
    "/api/v1/identity/internal/team-contacts",
    "/api/v1/identity/team-contacts",
    "/auth/internal/team-contacts",
)


def _is_an_answer(response):
    """True if the body is what identity's route answers."""
    try:
        body = response.json()
    except ValueError:
        return False
    return isinstance(body, dict) and "contacts" in body


@pytest.mark.parametrize("path", CONTACTS_PATHS)
def test_the_contacts_route_is_not_served_through_the_gateway(owners, path):
    """Whatever the gateway answers there, it is not identity's answer."""
    (address_a, a), _ = owners
    question = {"team_id": _team_of(a), "roles": ["owner", "admin"]}

    for headers in ({}, a):
        response = requests.post(
            f"{GATEWAY_URL}{path}", json=question, headers=headers, timeout=TIMEOUT
        )
        assert not _is_an_answer(response), (path, response.text[:200])
        assert address_a not in response.text


def test_the_contacts_route_refuses_whoever_does_not_hold_its_secret(
    contacts_configured, owners
):
    """Not a session, not the gateway's secret: identity names nobody."""
    (address_a, a), _ = owners
    question = {"team_id": _team_of(a), "roles": ["owner", "admin"]}
    url = f"{IDENTITY_URL}/internal/team-contacts"
    presented = [{}, a, {"X-Guardian-Contacts-Secret": "not-the-secret"}]
    gateway_secret = os.getenv("GATEWAY_INTERNAL_SECRET")
    if gateway_secret:
        presented += [
            {"X-Gateway-Secret": gateway_secret},
            {"X-Guardian-Contacts-Secret": gateway_secret},
        ]

    for headers in presented:
        response = requests.post(url, json=question, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 403, (
            sorted(headers),
            response.status_code,
            response.text[:200],
        )
        assert address_a not in response.text
