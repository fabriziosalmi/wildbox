"""A user who left a team is no longer one of its users in guardian (#676).

guardian recorded a TeamMembership row the first time the gateway
authenticated a user in a team, and nothing removed it. A member identity
removed from a team could no longer authenticate in it, but the team could
still assign vulnerabilities to them and share dashboards with them, and its
data went on naming them as assignee, owner and approver.

Two things end a membership here now, and both are tested:

* identity's notice (POST /internal/team-memberships/revoke/): the row is
  deleted and the roles the user held in that team are cleared, at once;
* time: a row counts for settings.TEAM_MEMBERSHIP_MAX_AGE from the last
  request the user made in the team. A notice that never arrived, or a
  member who left before there were notices, does not leave a member behind.

test_team_isolation.py checks, for every field of every API view that takes
a user, that a former member is refused there as an unknown id is.
"""

import json
import uuid
from datetime import timedelta
from unittest import mock

import pytest
from apps.core import memberships
from apps.core.models import TeamMembership
from apps.core.tenancy import (
    current_memberships,
    has_global_rows,
    is_current_member,
    scope_to_team,
    team_lookup,
)
from django.apps import apps
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.test import Client
from django.utils import timezone
from guardian.schedule import team_membership_max_age

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
REVOKE = "/internal/team-memberships/revoke/"
WINDOW = timedelta(days=30)


@pytest.fixture(autouse=True)
def window(settings):
    settings.TEAM_MEMBERSHIP_MAX_AGE = WINDOW
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }


@pytest.fixture
def teams():
    return uuid.uuid4(), uuid.uuid4()


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)

    def call(method, url, team, data=None, role="admin", user_id=None):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": user_id or str(uuid.uuid4()),
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": role,
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        }
        if data is not None:
            kwargs.update(data=data, content_type="application/json")
        return getattr(client, method)(url, **kwargs)

    return call


@pytest.fixture
def identity(monkeypatch):
    """identity's notice to guardian, as it arrives on the internal network."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)

    def notify(body, secret=_GW_SECRET, method="post", **extra):
        headers = dict(extra)
        if secret is not None:
            headers["HTTP_X_GATEWAY_SECRET"] = secret
        if method == "get":
            # The test client reads a GET's data as query parameters.
            return client.get(REVOKE, **headers)
        payload = body if isinstance(body, (str, bytes)) else json.dumps(body)
        return getattr(client, method)(
            REVOKE, data=payload, content_type="application/json", **headers
        )

    return notify


def _left(team_id, member):
    return {"memberships": [{"user_id": member.username, "team_id": str(team_id)}]}


def _age(team_id, member, age):
    """Make guardian have last seen ``member`` in the team ``age`` ago."""
    changed = TeamMembership.objects.filter(team_id=team_id, user=member).update(
        last_seen=timezone.now() - age
    )
    assert changed == 1


def _hold(model, field, team_id, member):
    """A row of ``model`` in the team, on which ``member`` holds ``field``."""
    row = tf.make(model, team_id)
    if field.many_to_many:
        getattr(row, field.name).add(member)
    else:
        model._default_manager.filter(pk=row.pk).update(**{field.name: member})
    return row


def _holds(row, field, member):
    row = type(row)._default_manager.get(pk=row.pk)
    if field.many_to_many:
        return getattr(row, field.name).filter(pk=member.pk).exists()
    return getattr(row, f"{field.name}_id") == member.pk


ROLES = [
    pytest.param(model, field, id=f"{model.__name__}.{field.name}")
    for model, field in memberships._role_fields()
]


# --- a membership row counts for a while, not for good ---------------------------


@pytest.mark.django_db
def test_a_member_seen_recently_is_one_of_the_teams_users(teams):
    team_a, team_b = teams
    member = tf.user(team_a)

    assert is_current_member(member, team_a)
    assert not is_current_member(member, team_b)
    assert list(scope_to_team(User.objects.all(), team_a)) == [member]
    assert list(scope_to_team(User.objects.all(), team_b)) == []


@pytest.mark.django_db
@pytest.mark.parametrize(
    "age,counts",
    [
        (timedelta(0), True),
        (WINDOW - timedelta(minutes=1), True),
        (WINDOW + timedelta(minutes=1), False),
        (timedelta(days=400), False),
    ],
)
def test_a_membership_counts_for_the_window_and_no_longer(teams, age, counts):
    team_a, _ = teams
    member = tf.user(team_a)
    _age(team_a, member, age)

    assert is_current_member(member, team_a) is counts
    assert scope_to_team(User.objects.all(), team_a).exists() is counts
    assert current_memberships(team_a).exists() is counts
    # The row is still there: it is what guardian trusts that changed.
    assert TeamMembership.objects.filter(team_id=team_a, user=member).exists()


@pytest.mark.django_db
def test_a_fresh_membership_elsewhere_does_not_revive_a_stale_one(teams):
    """Stale here, fresh in another team: not a member here.

    A join on "a row of this team" and "a row that still counts" can match
    two different rows; the user must hold one row that is both.
    """
    team_a, team_b = teams
    member = tf.user(team_a)
    TeamMembership.objects.create(team_id=team_b, user=member)
    _age(team_a, member, WINDOW + timedelta(days=1))

    assert not is_current_member(member, team_a)
    assert is_current_member(member, team_b)
    members_of_a = scope_to_team(User.objects.all(), team_a)
    assert not members_of_a.exists()
    # However the caller narrows it further.
    assert not members_of_a.filter(guardian_team_memberships__team_id=team_b).exists()
    assert list(scope_to_team(User.objects.all(), team_b)) == [member]


def test_nobody_is_a_member_of_no_team():
    assert is_current_member(User(pk=1), None) is False
    assert is_current_member(None, uuid.uuid4()) is False


# --- every request refreshes the membership ---------------------------------------


@pytest.mark.django_db
def test_a_request_records_when_the_member_was_seen(api, teams):
    team_a, _ = teams
    user_id = str(uuid.uuid4())
    before = timezone.now()

    assert (
        api("get", "/api/v1/assets/assets/", team_a, user_id=user_id).status_code == 200
    )

    row = TeamMembership.objects.get(team_id=team_a, user__username=user_id)
    assert before <= row.last_seen <= timezone.now()
    assert before <= row.first_seen


@pytest.mark.django_db
def test_a_member_who_comes_back_is_a_member_again_at_once(api, teams):
    team_a, _ = teams
    member = tf.user(team_a)
    _age(team_a, member, WINDOW + timedelta(days=5))
    assert not is_current_member(member, team_a)

    response = api("get", "/api/v1/assets/assets/", team_a, user_id=member.username)

    assert response.status_code == 200
    assert is_current_member(member, team_a)
    row = TeamMembership.objects.get(team_id=team_a, user=member)
    assert timezone.now() - row.last_seen < timedelta(minutes=1)
    assert row.first_seen < timezone.now()
    assert TeamMembership.objects.filter(user=member).count() == 1


@pytest.mark.django_db
def test_a_request_does_not_write_the_membership_every_time(api, teams):
    """Refreshed at most once per MEMBERSHIP_REFRESH_INTERVAL."""
    from apps.core.gateway_middleware import MEMBERSHIP_REFRESH_INTERVAL

    team_a, _ = teams
    member = tf.user(team_a)
    recent = timezone.now() - MEMBERSHIP_REFRESH_INTERVAL + timedelta(seconds=30)
    TeamMembership.objects.filter(user=member).update(last_seen=recent)

    api("get", "/api/v1/assets/assets/", team_a, user_id=member.username)
    assert TeamMembership.objects.get(user=member).last_seen == recent

    older = timezone.now() - MEMBERSHIP_REFRESH_INTERVAL - timedelta(seconds=30)
    TeamMembership.objects.filter(user=member).update(last_seen=older)
    api("get", "/api/v1/assets/assets/", team_a, user_id=member.username)
    assert TeamMembership.objects.get(user=member).last_seen > recent
    # Far below the window: an active member never looks stale.
    assert MEMBERSHIP_REFRESH_INTERVAL * 100 < timedelta(days=1)


# --- the window setting -------------------------------------------------------------


def test_the_membership_window_defaults_to_thirty_days(settings):
    variable = "GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS"
    assert team_membership_max_age({}) == timedelta(days=30)
    assert team_membership_max_age({variable: ""}) == timedelta(days=30)
    assert team_membership_max_age({variable: "1"}) == timedelta(days=1)
    assert team_membership_max_age({variable: " 7 "}) == timedelta(days=7)
    assert team_membership_max_age({variable: "365"}) == timedelta(days=365)


@pytest.mark.parametrize(
    "value", ["0", "-1", "366", "100000", "off", "never", "30d", "1.5"]
)
def test_a_window_that_is_not_a_window_stops_start_up(value):
    # No "off", and no value that amounts to forever: that was the bug.
    with pytest.raises(ImproperlyConfigured) as raised:
        team_membership_max_age({"GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS": value})
    assert "GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS" in str(raised.value)


def test_guardian_has_a_membership_window():
    from guardian import settings as guardian_settings

    assert (
        timedelta(days=1)
        <= guardian_settings.TEAM_MEMBERSHIP_MAX_AGE
        <= timedelta(days=365)
    )


# --- roles and records ----------------------------------------------------------------


def test_every_relation_to_a_user_is_a_role_or_a_record():
    """A new field has to be put in one list: nothing is cleared, or kept, by accident."""
    found = {
        (model._meta.label, field.name) for model, field in memberships.user_relations()
    }
    roles = {(m, f) for m, names in memberships.ROLE_FIELDS.items() for f in names}
    records = {(m, f) for m, names in memberships.RECORD_FIELDS.items() for f in names}

    assert len(found) > 35
    assert roles & records == set()
    assert (
        found - roles - records == set()
    ), "classify these in apps/core/memberships.py"
    assert (roles | records) - found == set(), "these are not relations to a user"


def test_a_role_can_be_cleared_without_deleting_the_row():
    assert len(ROLES) == 9
    for model, field in memberships._role_fields():
        assert team_lookup(model), model
        assert field.many_to_many or field.null, (model, field.name)
        # No shared reference row carries a role: clearing an account's
        # roles everywhere cannot change what every team reads.
        assert not has_global_rows(model), model


@pytest.mark.django_db
@pytest.mark.parametrize("model,field", ROLES)
def test_leaving_a_team_clears_the_role_held_in_it_and_only_in_it(teams, model, field):
    team_a, team_b = teams
    member = tf.user(team_a)
    TeamMembership.objects.create(team_id=team_b, user=member)
    colleague = tf.user(team_a)
    in_a = _hold(model, field, team_a, member)
    in_b = _hold(model, field, team_b, member)
    colleagues = _hold(model, field, team_a, colleague)

    cleared = memberships.revoke_membership(team_a, member.username)

    assert cleared == {f"{model._meta.label}.{field.name}": 1}
    assert not _holds(in_a, field, member)
    # Still a member of the other team, with the role there; and a colleague
    # who stays keeps theirs.
    assert _holds(in_b, field, member)
    assert _holds(colleagues, field, colleague)
    assert model._default_manager.filter(pk=in_a.pk).exists()
    assert not TeamMembership.objects.filter(team_id=team_a, user=member).exists()
    assert TeamMembership.objects.filter(team_id=team_b, user=member).exists()


@pytest.mark.django_db
def test_what_a_member_did_stays_on_record_after_they_leave(teams):
    from apps.compliance.models import ComplianceException
    from apps.vulnerabilities.models import Vulnerability, VulnerabilityNote

    team_a, _ = teams
    member = tf.user(team_a)
    vulnerability = tf.make(Vulnerability, team_a)
    Vulnerability.objects.filter(pk=vulnerability.pk).update(created_by=member)
    note = VulnerabilityNote.objects.create(
        vulnerability=vulnerability, author=member, content="triaged"
    )
    exception = tf.make(ComplianceException, team_a)
    ComplianceException.objects.filter(pk=exception.pk).update(approved_by=member)

    assert memberships.revoke_membership(team_a, member.username) == {}

    vulnerability.refresh_from_db()
    exception.refresh_from_db()
    assert vulnerability.created_by_id == member.pk
    assert exception.approved_by_id == member.pk
    assert VulnerabilityNote.objects.filter(pk=note.pk, author=member).exists()
    assert User.objects.filter(pk=member.pk).exists()


@pytest.mark.django_db
def test_an_unassigned_vulnerability_says_why_in_its_history(teams):
    from apps.vulnerabilities.models import Vulnerability, VulnerabilityHistory

    team_a, _ = teams
    member = tf.user(team_a)
    field = Vulnerability._meta.get_field("assigned_to")
    vulnerability = _hold(Vulnerability, field, team_a, member)

    with mock.patch(
        "apps.vulnerabilities.signals.notify_vulnerability_assignment"
    ) as notify:
        memberships.revoke_membership(team_a, member.username)

    entry = VulnerabilityHistory.objects.get(
        vulnerability=vulnerability, field_name="assigned_to"
    )
    assert entry.change_reason == (
        "Unassigned: the assignee is no longer a member of the team"
    )
    assert (entry.old_value, entry.new_value) == ("assigned", "")
    # Not an edit by anybody: no assignment e-mail is queued for it.
    notify.delay.assert_not_called()


@pytest.mark.django_db
def test_a_user_guardian_never_saw_has_nothing_to_revoke(teams):
    team_a, _ = teams
    assert memberships.revoke_membership(team_a, uuid.uuid4()) == {}
    assert memberships.revoke_user(uuid.uuid4()) == {}
    with pytest.raises(ValueError):
        memberships.revoke_membership(None, uuid.uuid4())


@pytest.mark.django_db
@pytest.mark.parametrize("model,field", ROLES)
def test_an_account_that_is_gone_holds_no_role_in_any_team(teams, model, field):
    team_a, team_b = teams
    member = tf.user(team_a)
    in_a = _hold(model, field, team_a, member)
    # A role in a team whose membership row is already gone.
    in_b = _hold(model, field, team_b, member)

    cleared = memberships.revoke_user(member.username)

    assert cleared == {f"{model._meta.label}.{field.name}": 2}
    assert not _holds(in_a, field, member)
    assert not _holds(in_b, field, member)
    assert not TeamMembership.objects.filter(user=member).exists()


# --- identity's notice ------------------------------------------------------------------


@pytest.mark.django_db
def test_identity_says_a_member_left_and_guardian_acts(identity, teams):
    from apps.vulnerabilities.models import Vulnerability

    team_a, team_b = teams
    member = tf.user(team_a)
    TeamMembership.objects.create(team_id=team_b, user=member)
    field = Vulnerability._meta.get_field("assigned_to")
    vulnerability = _hold(Vulnerability, field, team_a, member)

    response = identity(_left(team_a, member))

    assert response.status_code == 200, response.content[:300]
    assert response.json() == {"revoked": 1, "scope": "memberships"}
    assert not is_current_member(member, team_a)
    assert is_current_member(member, team_b)
    assert not _holds(vulnerability, field, member)


@pytest.mark.django_db
def test_identity_says_an_account_is_gone(identity, teams):
    team_a, team_b = teams
    member = tf.user(team_a)
    TeamMembership.objects.create(team_id=team_b, user=member)
    stays = tf.user(team_a)

    response = identity({"users": [member.username, str(uuid.uuid4())]})

    assert response.status_code == 200, response.content[:300]
    # The account guardian never saw is handled too: nothing is left of it.
    assert response.json() == {"revoked": 2, "scope": "users"}
    assert not TeamMembership.objects.filter(user=member).exists()
    assert is_current_member(stays, team_a)


@pytest.mark.django_db
def test_several_members_leave_in_one_notice(identity, teams):
    team_a, team_b = teams
    one, two = tf.user(team_a), tf.user(team_b)

    response = identity(
        {
            "memberships": [
                {"user_id": one.username, "team_id": str(team_a)},
                {"user_id": two.username, "team_id": str(team_b)},
            ]
        }
    )

    assert response.json() == {"revoked": 2, "scope": "memberships"}
    assert not TeamMembership.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "secret,headers",
    [
        (None, {}),
        ("", {}),
        ("wrong-secret", {}),
        (_GW_SECRET + "x", {}),
        (_GW_SECRET[:-1], {}),
        # The gateway's identity headers are not the proof: the secret is.
        (
            None,
            {
                "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
                "HTTP_X_WILDBOX_TEAM_ID": str(uuid.uuid4()),
                "HTTP_X_WILDBOX_ROLE": "owner",
            },
        ),
    ],
)
def test_the_notice_is_refused_without_the_internal_secret(
    identity, teams, secret, headers
):
    team_a, _ = teams
    member = tf.user(team_a)

    response = identity(_left(team_a, member), secret=secret, **headers)

    assert response.status_code == 403, response.content[:300]
    assert response.json()["code"] == "GATEWAY_SECRET_REQUIRED"
    assert is_current_member(member, team_a)


@pytest.mark.django_db
@pytest.mark.parametrize("configured", [None, ""])
def test_the_notice_is_refused_when_guardian_has_no_secret(
    identity, teams, monkeypatch, configured
):
    """Fail closed: no secret configured is not "anyone may call"."""
    team_a, _ = teams
    member = tf.user(team_a)
    if configured is None:
        monkeypatch.delenv("GATEWAY_INTERNAL_SECRET")
    else:
        monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", configured)

    for secret in (None, "", _GW_SECRET):
        response = identity(_left(team_a, member), secret=secret)
        assert response.status_code == 503, response.content[:300]
        assert response.json()["code"] == "GATEWAY_SECRET_NOT_CONFIGURED"
    assert is_current_member(member, team_a)


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["get", "put", "patch", "delete"])
def test_the_notice_is_a_post(identity, teams, method):
    team_a, _ = teams
    member = tf.user(team_a)

    response = identity(_left(team_a, member), method=method)

    assert response.status_code == 405
    assert is_current_member(member, team_a)


def _bad_bodies():
    user, team = str(uuid.uuid4()), str(uuid.uuid4())
    pair = {"user_id": user, "team_id": team}
    return [
        pytest.param("", id="empty"),
        pytest.param("not json", id="not-json"),
        pytest.param([], id="a-list"),
        pytest.param({}, id="no-key"),
        pytest.param({"memberships": [pair], "users": [user]}, id="both-scopes"),
        pytest.param({"memberships": [pair], "ttl": 300}, id="unknown-key"),
        pytest.param({"teams": [team]}, id="unknown-scope"),
        pytest.param({"memberships": []}, id="no-memberships"),
        pytest.param({"users": []}, id="no-users"),
        pytest.param({"memberships": pair}, id="not-a-list"),
        pytest.param({"memberships": [{"user_id": user}]}, id="no-team"),
        pytest.param({"memberships": [{"team_id": team}]}, id="no-user"),
        pytest.param({"memberships": [{**pair, "role": "owner"}]}, id="extra-field"),
        pytest.param(
            {"memberships": [{"user_id": "x", "team_id": team}]}, id="bad-user"
        ),
        pytest.param(
            {"memberships": [{"user_id": user, "team_id": None}]}, id="null-team"
        ),
        pytest.param({"memberships": [[user, team]]}, id="pair-as-list"),
        pytest.param({"users": ["not-a-uuid"]}, id="bad-uuid"),
        pytest.param({"users": [1]}, id="a-number"),
        pytest.param({"users": [user] * 1001}, id="too-many"),
    ]


@pytest.mark.django_db
@pytest.mark.parametrize("body", _bad_bodies())
def test_a_notice_guardian_does_not_understand_is_refused(identity, teams, body):
    """400, never a 200 that did nothing: identity must not read it as done."""
    team_a, _ = teams
    member = tf.user(team_a)

    response = identity(body)

    assert response.status_code == 400, response.content[:300]
    assert "revoked" not in response.json()
    assert is_current_member(member, team_a)


@pytest.mark.django_db
def test_one_bad_item_and_nothing_in_the_notice_is_applied(identity, teams):
    team_a, _ = teams
    member = tf.user(team_a)
    body = _left(team_a, member)
    body["memberships"].append({"user_id": "not-a-uuid", "team_id": str(team_a)})

    assert identity(body).status_code == 400
    assert is_current_member(member, team_a)


@pytest.mark.django_db
def test_the_notice_arrives_over_plain_http(identity, teams, settings):
    """identity calls it on the internal network: a 301 to https loses it."""
    settings.SECURE_SSL_REDIRECT = True
    settings.SECURE_REDIRECT_EXEMPT = __import__(
        "guardian.settings", fromlist=["x"]
    ).SECURE_REDIRECT_EXEMPT
    team_a, _ = teams
    member = tf.user(team_a)

    response = identity(_left(team_a, member))

    assert response.status_code == 200, (response.status_code, response.content[:200])
    assert not is_current_member(member, team_a)
    # The exemption is that one route: the API still redirects.
    redirected = Client().get("/api/v1/assets/assets/")
    assert redirected.status_code == 301


def test_the_notice_is_outside_the_api_the_gateway_proxies():
    # The gateway proxies /api/v1/guardian/ to /api/v1/ and nothing else, so a
    # route outside /api/ is not reachable through it.
    from django.urls import reverse

    assert reverse("revoke-team-memberships") == REVOKE
    assert not REVOKE.startswith("/api/")


# --- through the API: a former member is refused, and not named ------------------------


def _assign(api, team, vulnerability, user):
    with mock.patch("apps.vulnerabilities.views.notify_vulnerability_assignment"):
        return api(
            "post",
            f"/api/v1/vulnerabilities/{vulnerability.pk}/assign/",
            team,
            data={"assigned_to": user.pk},
        )


def _former_member_cases():
    def notice(identity, team, member):
        assert identity(_left(team, member)).status_code == 200

    def account_gone(identity, team, member):
        assert identity({"users": [member.username]}).status_code == 200

    def not_seen(identity, team, member):
        _age(team, member, WINDOW + timedelta(days=1))

    return [
        pytest.param(notice, True, id="identity-said-they-left"),
        pytest.param(account_gone, True, id="identity-said-the-account-is-gone"),
        pytest.param(not_seen, False, id="not-seen-for-longer-than-the-window"),
    ]


@pytest.mark.django_db
@pytest.mark.parametrize("leave,roles_cleared", _former_member_cases())
def test_a_former_member_is_not_accepted_as_assignee_or_share_target(
    api, identity, teams, leave, roles_cleared
):
    from apps.reporting.models import Dashboard
    from apps.vulnerabilities.models import Vulnerability

    team_a, _ = teams
    member, colleague = tf.user(team_a), tf.user(team_a)
    vulnerability = tf.make(Vulnerability, team_a)
    other = tf.make(Vulnerability, team_a)
    board = tf.make(Dashboard, team_a)
    share = f"/api/v1/reports/dashboards/{board.pk}/share/"

    # While a member: accepted, and named.
    assert _assign(api, team_a, vulnerability, member).status_code == 200
    assert api("post", share, team_a, data={"user_ids": [member.pk]}).status_code == 200
    assert list(board.shared_with.values_list("pk", flat=True)) == [member.pk]

    leave(identity, team_a, member)

    refused = _assign(api, team_a, other, member)
    assert refused.status_code == 400, refused.content[:300]
    # Answered as an id nobody has.
    unknown = _assign(api, team_a, other, User(pk=10**9))
    assert refused.json() == unknown.json()
    with mock.patch("apps.vulnerabilities.views.notify_vulnerability_assignment"):
        bulk = api(
            "post",
            "/api/v1/vulnerabilities/bulk_action/",
            team_a,
            data={
                "vulnerability_ids": [str(other.pk)],
                "action": "assign",
                "assigned_to": member.pk,
            },
        )
    assert bulk.status_code == 400, bulk.content[:300]
    patched = api(
        "patch",
        f"/api/v1/vulnerabilities/{other.pk}/",
        team_a,
        data={"assigned_to": member.pk},
    )
    assert patched.status_code == 400, patched.content[:300]
    assert "does not exist" in str(patched.json()["assigned_to"])
    other.refresh_from_db()
    assert other.assigned_to_id is None

    board.shared_with.clear()
    shared = api("post", share, team_a, data={"user_ids": [member.pk, colleague.pk]})
    assert shared.status_code == 200, shared.content[:300]
    assert list(board.shared_with.values_list("pk", flat=True)) == [colleague.pk]

    # A colleague who stays is still accepted: the refusal is about the one.
    assert _assign(api, team_a, other, colleague).status_code == 200

    if roles_cleared:
        vulnerability.refresh_from_db()
        assert vulnerability.assigned_to_id is None


@pytest.mark.django_db
def test_a_member_identity_removed_is_no_longer_named_to_the_team(api, identity, teams):
    from apps.assets.models import Asset
    from apps.reporting.models import Dashboard
    from apps.vulnerabilities.models import Vulnerability

    team_a, _ = teams
    member = tf.user(team_a)
    vulnerability = tf.make(Vulnerability, team_a)
    Vulnerability.objects.filter(pk=vulnerability.pk).update(assigned_to=member)
    Asset.objects.filter(pk=vulnerability.asset_id).update(
        owner=member, technical_contact=member
    )
    board = tf.make(Dashboard, team_a)
    board.shared_with.add(member)
    urls = {
        "vulnerability": f"/api/v1/vulnerabilities/{vulnerability.pk}/",
        "asset": f"/api/v1/assets/assets/{vulnerability.asset_id}/",
        "dashboard": f"/api/v1/reports/dashboards/{board.pk}/",
    }

    def named():
        bodies = {name: api("get", url, team_a) for name, url in urls.items()}
        for name, response in bodies.items():
            assert response.status_code == 200, (name, response.content[:300])
        bodies = {name: response.json() for name, response in bodies.items()}
        return {
            "assigned_to": bodies["vulnerability"]["assigned_to"],
            "owner": bodies["asset"]["owner"],
            "owner_username": bodies["asset"].get("owner_username"),
            "technical_contact": bodies["asset"]["technical_contact"],
            "shared_with": bodies["dashboard"]["shared_with"],
        }, json.dumps(bodies)

    before, _ = named()
    assert before == {
        "assigned_to": member.pk,
        "owner": member.pk,
        "owner_username": member.username,
        "technical_contact": member.pk,
        "shared_with": [member.pk],
    }

    assert identity(_left(team_a, member)).status_code == 200

    after, raw = named()
    assert after == {
        "assigned_to": None,
        "owner": None,
        "owner_username": None,
        "technical_contact": None,
        "shared_with": [],
    }
    # Their identity id is in none of the three responses any more.
    assert member.username not in raw


# --- e-mail about a team's data does not follow a member out of it ---------------------


def _overdue(team_id, assignee):
    from apps.vulnerabilities.models import Vulnerability

    vulnerability = tf.make(Vulnerability, team_id)
    Vulnerability.objects.filter(pk=vulnerability.pk).update(
        assigned_to=assignee, due_date=timezone.now() - timedelta(hours=5)
    )
    return vulnerability


def _with_address(team_id, address):
    member = tf.user(team_id)
    member.email = address
    member.save(update_fields=["email"])
    return member


@pytest.mark.django_db
@pytest.mark.parametrize(
    "state,told",
    [("member", True), ("not-seen", False), ("row-deleted", False)],
)
def test_an_sla_violation_is_not_e_mailed_to_a_former_member(
    teams, mailoutbox, state, told
):
    """The notice was lost, so the assignment is still there: no e-mail all the same."""
    from apps.vulnerabilities.tasks import check_sla_violations

    team_a, team_b = teams
    member = _with_address(team_a, "left@example.com")
    # Still a member of another team: that does not make them one here.
    TeamMembership.objects.create(team_id=team_b, user=member)
    vulnerability = _overdue(team_a, member)
    if state == "not-seen":
        _age(team_a, member, WINDOW + timedelta(days=1))
    elif state == "row-deleted":
        TeamMembership.objects.filter(team_id=team_a, user=member).delete()

    outcome = check_sla_violations.apply().get()

    assert [message.to for message in mailoutbox] == (
        [["left@example.com"]] if told else []
    )
    assert outcome == {
        "notifications_sent": 1 if told else 0,
        "notifications_not_sent": 0 if told else 1,
    }
    if not told:
        assert vulnerability.title not in "".join(
            m.subject + m.body for m in mailoutbox
        )


@pytest.mark.django_db
def test_an_assignment_is_not_e_mailed_to_a_former_member(teams, mailoutbox, caplog):
    from apps.vulnerabilities.tasks import notify_vulnerability_assignment

    team_a, _ = teams
    member = _with_address(team_a, "left@example.com")
    colleague = _with_address(team_a, "stays@example.com")
    assigner = tf.user(team_a)
    gone = _overdue(team_a, member)
    kept = _overdue(team_a, colleague)
    _age(team_a, member, WINDOW + timedelta(days=1))

    with caplog.at_level("WARNING", logger="apps.vulnerabilities.tasks"):
        result = notify_vulnerability_assignment.apply(
            args=(str(gone.pk), assigner.pk)
        ).get()
    assert result == {"notification_sent": False}
    assert mailoutbox == []
    assert "the assignee is not a member of its team" in caplog.text

    # A member is still told.
    notify_vulnerability_assignment.apply(args=(str(kept.pk), assigner.pk)).get()
    assert [message.to for message in mailoutbox] == [["stays@example.com"]]


# --- the notice, by hand ----------------------------------------------------------------


def _command(*args):
    from io import StringIO

    from django.core.management import call_command

    out = StringIO()
    call_command("revoke_team_membership", *args, stdout=out)
    return out.getvalue()


@pytest.mark.django_db
def test_an_operator_applies_a_lost_notice_by_hand(teams):
    """identity logged "guardian was not told of": no waiting for the window."""
    from apps.vulnerabilities.models import Vulnerability

    team_a, team_b = teams
    member = tf.user(team_a)
    TeamMembership.objects.create(team_id=team_b, user=member)
    field = Vulnerability._meta.get_field("assigned_to")
    in_a = _hold(Vulnerability, field, team_a, member)
    in_b = _hold(Vulnerability, field, team_b, member)

    would = _command("--team", str(team_a), "--user", member.username, "--dry-run")
    assert "Would revoke" in would
    assert "vulnerabilities.Vulnerability.assigned_to: 1 cleared" in would
    # A dry run changes nothing.
    assert is_current_member(member, team_a)
    assert _holds(in_a, field, member)

    done = _command("--team", str(team_a), "--user", member.username)
    assert f"Revoked user {member.username} in team {team_a}." in done
    assert "vulnerabilities.Vulnerability.assigned_to: 1 cleared" in done
    assert not is_current_member(member, team_a)
    assert not _holds(in_a, field, member)
    # The other team is not this notice's business.
    assert is_current_member(member, team_b)
    assert _holds(in_b, field, member)

    gone = _command("--user", member.username, "--all-teams")
    assert "in every team" in gone
    assert not TeamMembership.objects.filter(user=member).exists()
    assert not _holds(in_b, field, member)


@pytest.mark.django_db
def test_the_command_does_not_guess_between_one_team_and_all(teams):
    from django.core.management.base import CommandError

    team_a, _ = teams
    member = tf.user(team_a)

    for args in (
        ("--user", member.username),
        ("--user", member.username, "--team", str(team_a), "--all-teams"),
    ):
        with pytest.raises(CommandError):
            _command(*args)
    with pytest.raises(CommandError):
        _command("--team", str(team_a))
    assert is_current_member(member, team_a)


@pytest.mark.django_db
def test_the_command_says_so_for_a_user_guardian_never_saw(teams):
    team_a, _ = teams
    unknown = str(uuid.uuid4())

    assert "nothing to revoke" in _command("--team", str(team_a), "--user", unknown)
    held_none = _command("--team", str(team_a), "--user", tf.user(team_a).username)
    assert "They held no role there." in held_none


# --- the migration ------------------------------------------------------------------------


@pytest.mark.django_db
def test_rows_from_before_the_upgrade_were_last_seen_when_first_seen(teams):
    """Not at the time of the migration: that would trust every stale row anew."""
    import importlib

    migration = importlib.import_module(
        "apps.core.migrations.0004_team_membership_last_seen"
    )
    team_a, team_b = teams
    old, recent = tf.user(team_a), tf.user(team_b)
    long_ago = timezone.now() - timedelta(days=200)
    TeamMembership.objects.filter(user=old).update(first_seen=long_ago)
    yesterday = timezone.now() - timedelta(days=1)
    TeamMembership.objects.filter(user=recent).update(first_seen=yesterday)

    migration.last_seen_is_first_seen(apps, None)

    assert TeamMembership.objects.get(user=old).last_seen == long_ago
    assert TeamMembership.objects.get(user=recent).last_seen == yesterday
    assert not is_current_member(old, team_a)
    assert is_current_member(recent, team_b)
