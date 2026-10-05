"""A request that overtakes a membership notice does not undo it (#724).

identity tells the gateway that a member left a team, and then guardian
(#676). From the first moment no new request of theirs is authenticated;
but one the gateway let through just before can reach guardian just after
the notice. The middleware records a membership for every request it lets
in, so that request put back the row the notice had deleted, and the former
member was one of the team's users again, assignable and named, for
GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS.

guardian now remembers a notice for a while (REVOCATION_GRACE), and in that
time no request records the membership it ended. The two can also cross
inside guardian, the request between its check and its row: the notice is
written down before the rows are deleted, so whichever comes second sees
the other. Every order is tried below.
"""

import json
import uuid
from datetime import timedelta
from unittest import mock

import pytest
from apps.core import gateway_middleware, memberships
from apps.core.memberships import REVOCATION_GRACE
from apps.core.models import TeamMembership, TeamMembershipRevocation
from apps.core.tenancy import is_current_member, scope_to_team
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
_ASSETS = "/api/v1/assets/assets/"
REVOKE = "/internal/team-memberships/revoke/"


@pytest.fixture(autouse=True)
def stack(settings, monkeypatch):
    settings.TEAM_MEMBERSHIP_MAX_AGE = timedelta(days=30)
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)


@pytest.fixture
def request_as():
    """A request the gateway authenticated for ``user_id`` in ``team``."""
    client = Client(raise_request_exception=False)

    def call(user_id, team, method="get", url=_ASSETS, data=None):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": str(user_id),
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": "admin",
            "HTTP_X_WILDBOX_AUTH_TYPE": "session",
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        }
        if data is not None:
            kwargs.update(data=json.dumps(data), content_type="application/json")
        return getattr(client, method)(url, **kwargs)

    return call


def _notice(body):
    return Client(raise_request_exception=False).post(
        REVOKE,
        data=json.dumps(body),
        content_type="application/json",
        HTTP_X_GATEWAY_SECRET=_GW_SECRET,
    )


def _left(team, user_id):
    response = _notice(
        {"memberships": [{"user_id": str(user_id), "team_id": str(team)}]}
    )
    assert response.status_code == 200, response.content


def _rows(team, user_id):
    return TeamMembership.objects.filter(team_id=team, user__username=str(user_id))


def _member(team):
    member = tf.user(team)
    return member, member.username


# --- the request arrives after the notice ----------------------------------------


@pytest.mark.django_db
def test_a_request_that_arrives_after_the_notice_records_nothing(request_as):
    team = uuid.uuid4()
    member, user_id = _member(team)
    _left(team, user_id)
    assert not _rows(team, user_id).exists()

    # Authenticated before the removal, delivered after the notice.
    response = request_as(user_id, team)

    # Served: the gateway authenticated it. Not recorded.
    assert response.status_code == 200
    assert not _rows(team, user_id).exists()
    assert not is_current_member(member, team)
    assert not scope_to_team(User.objects.all(), team).filter(pk=member.pk).exists()


@pytest.mark.django_db
def test_the_former_member_cannot_be_named_by_the_request_that_overtook(request_as):
    """What recreating the row allowed: assigning to the one who left."""
    from apps.vulnerabilities.models import Vulnerability

    team = uuid.uuid4()
    member, user_id = _member(team)
    vulnerability = tf.make(Vulnerability, team)
    _left(team, user_id)

    with mock.patch("apps.vulnerabilities.views.notify_vulnerability_assignment"):
        response = request_as(
            user_id,
            team,
            "post",
            f"/api/v1/vulnerabilities/{vulnerability.pk}/assign/",
            {"assigned_to": member.pk},
        )

    assert response.status_code == 400, response.content[:300]
    vulnerability.refresh_from_db()
    assert vulnerability.assigned_to_id is None


@pytest.mark.django_db
def test_every_request_in_the_grace_is_held_back_not_only_the_first(request_as):
    team = uuid.uuid4()
    _, user_id = _member(team)
    _left(team, user_id)

    for _ in range(3):
        assert request_as(user_id, team).status_code == 200

    assert not _rows(team, user_id).exists()


@pytest.mark.django_db
def test_a_user_guardian_never_saw_is_held_back_too(request_as):
    """The request in flight may be their first."""
    team, user_id = uuid.uuid4(), uuid.uuid4()
    _left(team, user_id)

    assert request_as(user_id, team).status_code == 200

    assert not _rows(team, user_id).exists()


@pytest.mark.django_db
def test_an_account_that_is_gone_is_recorded_in_no_team(request_as):
    seen_in, never_seen_in = uuid.uuid4(), uuid.uuid4()
    _, user_id = _member(seen_in)
    assert _notice({"users": [user_id]}).status_code == 200

    for team in (seen_in, never_seen_in):
        assert request_as(user_id, team).status_code == 200
        assert not _rows(team, user_id).exists()


# --- only that membership, and only for a while -----------------------------------


@pytest.mark.django_db
def test_the_notice_holds_back_that_membership_only(request_as):
    team, other_team = uuid.uuid4(), uuid.uuid4()
    _, user_id = _member(team)
    colleague = uuid.uuid4()
    _left(team, user_id)

    request_as(user_id, other_team)
    request_as(colleague, team)

    # Still a member elsewhere, and others are members here.
    assert _rows(other_team, user_id).exists()
    assert _rows(team, colleague).exists()
    assert not _rows(team, user_id).exists()


@pytest.mark.django_db
def test_a_member_added_back_is_recorded_once_the_grace_has_passed(request_as):
    team = uuid.uuid4()
    member, user_id = _member(team)
    _left(team, user_id)
    request_as(user_id, team)
    assert not _rows(team, user_id).exists()

    # The gateway authenticates them again long after: identity added them back.
    TeamMembershipRevocation.objects.update(
        revoked_at=timezone.now() - REVOCATION_GRACE - timedelta(seconds=1)
    )
    assert request_as(user_id, team).status_code == 200

    assert _rows(team, user_id).exists()
    assert is_current_member(member, team)


@pytest.mark.django_db
def test_just_inside_the_grace_still_holds():
    team = uuid.uuid4()
    _, user_id = _member(team)
    memberships.revoke_membership(team, user_id)
    edge = timezone.now() - REVOCATION_GRACE + timedelta(seconds=5)
    TeamMembershipRevocation.objects.update(revoked_at=edge)

    assert memberships.revoked_recently(user_id, team)
    assert not memberships.revoked_recently(user_id, uuid.uuid4())
    assert not memberships.revoked_recently(uuid.uuid4(), team)


def test_the_grace_outlasts_a_request_and_is_short_for_a_person():
    # The gateway gives a request a minute to be answered.
    assert timedelta(minutes=5) <= REVOCATION_GRACE <= timedelta(minutes=30)


# --- the two cross inside guardian -------------------------------------------------


@pytest.mark.django_db
def test_a_notice_between_the_check_and_the_row_still_wins():
    """The request found no note, then the notice came, then it wrote its row."""
    team = uuid.uuid4()
    member, user_id = _member(team)
    real = memberships.revoked_recently
    calls = []

    def notice_arrives_after_the_first_check(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            answer = real(*args, **kwargs)
            # The whole notice, between the check and the insert.
            memberships.revoke_membership(team, user_id)
            return answer
        return real(*args, **kwargs)

    TeamMembership.objects.filter(team_id=team, user=member).delete()
    with mock.patch.object(
        memberships, "revoked_recently", notice_arrives_after_the_first_check
    ):
        gateway_middleware._record_membership(member, team)

    assert len(calls) == 2
    assert not _rows(team, user_id).exists()


@pytest.mark.django_db
def test_a_row_written_just_before_the_notice_is_deleted_by_it():
    team = uuid.uuid4()
    member, user_id = _member(team)
    TeamMembership.objects.filter(team_id=team, user=member).delete()

    gateway_middleware._record_membership(member, team)
    assert _rows(team, user_id).exists()
    memberships.revoke_membership(team, user_id)

    assert not _rows(team, user_id).exists()


@pytest.mark.django_db
def test_the_notice_is_written_down_before_and_apart_from_the_deletion():
    """If clearing the roles fails, the note is there all the same."""
    team = uuid.uuid4()
    _, user_id = _member(team)

    with mock.patch.object(memberships, "_clear_roles", side_effect=RuntimeError):
        with pytest.raises(RuntimeError):
            memberships.revoke_membership(team, user_id)

    # The deletion was rolled back with the failure; the note was not.
    assert _rows(team, user_id).exists()
    assert memberships.revoked_recently(user_id, team)


# --- what it costs --------------------------------------------------------------------


@pytest.mark.django_db
def test_a_current_member_costs_one_query_as_before(django_assert_num_queries):
    team = uuid.uuid4()
    member, _ = _member(team)

    with django_assert_num_queries(1):
        gateway_middleware._record_membership(member, team)


@pytest.mark.django_db
def test_notes_that_hold_nothing_back_are_not_kept():
    team = uuid.uuid4()
    for _ in range(3):
        memberships.revoke_membership(team, uuid.uuid4())
    TeamMembershipRevocation.objects.update(
        revoked_at=timezone.now() - REVOCATION_GRACE - timedelta(minutes=1)
    )

    memberships.revoke_membership(team, uuid.uuid4())

    assert TeamMembershipRevocation.objects.count() == 1
