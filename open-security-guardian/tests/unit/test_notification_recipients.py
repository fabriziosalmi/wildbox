"""A notification goes to the recipients its own team named, or to nobody (#678).

guardian read two notification fallbacks that nothing defined:
``DEFAULT_NOTIFICATION_RECIPIENTS`` (alert rules, scheduled reports and
compliance notifications without recipients) and ``SECURITY_TEAM_EMAIL``
(a copy of every SLA violation). Both were one value for the whole
platform: an operator who defined them would have sent every team's asset
names, vulnerability titles and findings to one mailbox, across the team
boundary of #642.

They are gone. Here they are defined, as that operator would, and must
receive nothing; a notification nobody can be told of is not sent, and that
is logged and, where the notification belongs to a row, recorded on it.

Since #705 a notification without recipients of its own goes to the owners
and admins of its team, and the address of an assignee is the one identity
gives (tests/unit/test_notification_delivery.py). The tests below that set
an address on guardian's own copy of a user, which no user that came through
the gateway has, now give it to identity instead; the ones that asserted
"nobody is told" assert it for a team identity lists nobody for.
"""

import pathlib
import re
import uuid
from datetime import timedelta
from unittest import mock

import pytest
from django.utils import timezone

from tests.unit import team_fixtures as tf

PLATFORM = "platform-wide@example.com"
SECURITY_TEAM = "security-team@example.com"
REMOVED_SETTINGS = ("DEFAULT_NOTIFICATION_RECIPIENTS", "SECURITY_TEAM_EMAIL")


@pytest.fixture(autouse=True)
def platform_wide_recipients(settings):
    settings.DEFAULT_NOTIFICATION_RECIPIENTS = [PLATFORM]
    settings.SECURITY_TEAM_EMAIL = SECURITY_TEAM
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": f"recipients-{uuid.uuid4().hex}",
        }
    }


@pytest.fixture
def teams():
    return uuid.uuid4(), uuid.uuid4()


def _addresses(mailoutbox):
    return sorted(address for message in mailoutbox for address in message.to)


def _overdue(team_id, assignee=None, hours=5):
    from apps.vulnerabilities.models import Vulnerability

    patches = tf._quiet()
    try:
        return tf.vulnerability(
            team_id,
            assigned_to=assignee,
            due_date=timezone.now() - timedelta(hours=hours),
        )
    finally:
        tf._stop(patches)
        assert Vulnerability.objects.filter(due_date__isnull=False).exists()


@pytest.fixture(autouse=True)
def nobody_platform_wide(mailoutbox):
    """Whatever a test sends, the platform-wide addresses receive none of it."""
    yield
    assert not {PLATFORM, SECURITY_TEAM} & set(_addresses(mailoutbox))


def _sla_history(vulnerability):
    from apps.vulnerabilities.models import VulnerabilityHistory

    return list(
        VulnerabilityHistory.objects.filter(
            vulnerability=vulnerability, field_name="sla_status"
        )
        .order_by("timestamp")
        .values_list("change_reason", flat=True)
    )


# --- nothing reads the platform-wide settings ----------------------------------


def test_no_code_reads_the_platform_wide_settings():
    """The names survive in comments only: nothing reads them from settings."""
    root = pathlib.Path(__file__).resolve().parents[2]
    names = "|".join(REMOVED_SETTINGS)
    reads = re.compile(
        rf"settings\.({names})\b|getattr\(\s*settings\s*,\s*['\"]({names})['\"]"
    )
    files = [*root.glob("apps/**/*.py"), *root.glob("guardian/**/*.py")]
    assert len(files) > 100
    found = [
        f"{path.relative_to(root)}:{number}"
        for path in files
        for number, line in enumerate(path.read_text().splitlines(), 1)
        if reads.search(line)
    ]
    assert found == []


@pytest.mark.parametrize("name", REMOVED_SETTINGS)
def test_guardian_defines_no_platform_wide_recipient(name):
    from guardian import settings as guardian_settings

    assert not hasattr(guardian_settings, name)


# --- the notification utility ---------------------------------------------------


@pytest.mark.parametrize("recipients", [None, [], ()])
@pytest.mark.parametrize("team", [None, "a-team"])
def test_a_notification_nobody_can_be_told_of_is_not_sent_and_logged(
    recipients, team, mailoutbox, caplog, identity_contacts, db
):
    """No address of its own, no owner or admin: nobody, not everybody."""
    from apps.core import notifications

    team_id = uuid.uuid4() if team else None
    with caplog.at_level("WARNING", logger="apps.core.notifications"):
        delivery = notifications.notify_team_from_template(
            team_id,
            "Compliance Assessment Started",
            "compliance/assessment_started.html",
            {"assessment": "Q3", "framework": "ISO 27001"},
            named=recipients,
            kind="compliance",
        )

    assert delivery.sent is False and delivery.recipients == ()
    assert delivery.reason == (
        notifications.NO_DEFAULT_RECIPIENTS if team else notifications.NO_TEAM
    )
    assert mailoutbox == []
    assert (
        f"Notification not sent (compliance), {delivery.reason}: "
        "Compliance Assessment Started"
    ) in caplog.text


def test_a_notification_goes_to_the_recipients_it_names_only(mailoutbox):
    from apps.core.notifications import notify_team_from_template

    delivery = notify_team_from_template(
        None,
        "s",
        "compliance/assessment_started.html",
        {"assessment": "Q3", "framework": "ISO 27001"},
        named=["grc@team-a.example"],
    )
    assert delivery.sent and delivery.recipients == ("grc@team-a.example",)
    assert _addresses(mailoutbox) == ["grc@team-a.example"]


# --- alert rules ----------------------------------------------------------------


@pytest.mark.django_db
def test_an_alert_goes_to_its_own_rules_recipients_only(teams, mailoutbox):
    from apps.reporting import tasks
    from apps.reporting.models import AlertNotification

    team_a, team_b = teams
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        named = tf.alert_rule(
            team_a,
            operator="eq",
            notification_config={"recipients": ["soc@team-a.example"]},
        )
        silent = tf.alert_rule(team_b, operator="eq")

    for rule in (named, silent):
        assert tasks.check_alert_rule(rule.pk)["notification"] == "firing"

    assert _addresses(mailoutbox) == ["soc@team-a.example"]
    # The notification without recipients is recorded, undelivered: its
    # team reads that on GET .../alerts/{id}/notifications/.
    recorded = AlertNotification.objects.get(rule=silent)
    assert (recorded.recipients, recorded.delivered) == ([], False)
    assert AlertNotification.objects.get(rule=named).delivered is True


@pytest.mark.django_db
def test_an_undelivered_alert_is_visible_to_its_team(teams, monkeypatch):
    from apps.reporting import tasks
    from django.test import Client

    team_a, _ = teams
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        rule = tf.alert_rule(team_a, operator="eq")
    tasks.check_alert_rule(rule.pk)

    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", "test-gateway-secret")
    response = Client().get(
        f"/api/v1/reports/alerts/{rule.pk}/notifications/",
        secure=True,
        HTTP_X_WILDBOX_USER_ID=str(uuid.uuid4()),
        HTTP_X_WILDBOX_TEAM_ID=str(team_a),
        HTTP_X_WILDBOX_ROLE="member",
        HTTP_X_GATEWAY_SECRET="test-gateway-secret",
        HTTP_X_WILDBOX_AUTH_TYPE="session",
    )

    assert response.status_code == 200, response.content[:300]
    body = response.json()
    rows = body["results"] if isinstance(body, dict) else body
    assert [(row["kind"], row["recipients"], row["delivered"]) for row in rows] == [
        ("firing", [], False)
    ]


# --- scheduled reports ----------------------------------------------------------


def _scheduled_report(team_id, recipients):
    from apps.reporting.models import Report

    schedule = tf.report_schedule(team_id)
    schedule.recipients = recipients
    schedule.save(update_fields=["recipients"])
    return Report.objects.create(
        template=schedule.template, schedule=schedule, name="weekly", format="json"
    )


@pytest.mark.django_db
def test_a_scheduled_report_is_announced_to_its_schedules_recipients_only(
    teams, mailoutbox, caplog, identity_contacts
):
    from apps.reporting.tasks import notify_scheduled_report

    team_a, team_b = teams
    named = _scheduled_report(team_a, ["ciso@team-a.example"])
    silent = _scheduled_report(team_b, [])

    assert notify_scheduled_report(named) is True
    with caplog.at_level("WARNING", logger="apps.reporting.tasks"):
        assert notify_scheduled_report(silent) is False

    assert _addresses(mailoutbox) == ["ciso@team-a.example"]
    assert f"Report schedule {silent.schedule_id}" in caplog.text
    assert (
        "no e-mail sent (the team has no owner or admin with an active "
        "account and an address)"
    ) in caplog.text


# --- SLA violations --------------------------------------------------------------


@pytest.mark.django_db
def test_an_sla_violation_is_told_to_the_assignee_and_nobody_else(
    teams, mailoutbox, identity_contacts
):
    from apps.vulnerabilities.tasks import check_sla_violations

    team_a, team_b = teams
    assigned = _overdue(
        team_a, identity_contacts.member(team_a, "dev@team-a.example")
    )
    unassigned = _overdue(team_b)
    # A member identity holds no address for: nobody to write to.
    no_address = _overdue(team_b, identity_contacts.member(team_b, ""))

    outcome = check_sla_violations.apply().get()

    assert outcome == {"notifications_sent": 1, "notifications_not_sent": 2}
    assert _addresses(mailoutbox) == ["dev@team-a.example"]
    assert assigned.title in mailoutbox[0].subject
    for message in mailoutbox:
        assert unassigned.title not in message.subject + message.body
        assert no_address.title not in message.subject + message.body


@pytest.mark.django_db
def test_an_sla_violation_nobody_is_told_of_is_recorded_and_logged(
    teams, mailoutbox, caplog, identity_contacts
):
    from apps.vulnerabilities.tasks import check_sla_violations

    team_a, _ = teams
    unassigned = _overdue(team_a)

    with caplog.at_level("WARNING", logger="apps.vulnerabilities.tasks"):
        first = check_sla_violations.apply().get()

    assert first == {"notifications_sent": 0, "notifications_not_sent": 1}
    assert mailoutbox == []
    (reason,) = _sla_history(unassigned)
    # No assignee, and identity lists no owner or admin for the team.
    assert reason.startswith(
        "SLA violation notification not sent (the team has no owner or admin "
        "with an active account and an address)"
    )
    assert f"SLA violation of vulnerability {unassigned.id}" in caplog.text
    assert "not sent (the team has no owner or admin" in caplog.text


@pytest.mark.django_db
def test_an_unassigned_violation_is_recorded_once_then_notified_when_assigned(
    teams, mailoutbox, identity_contacts
):
    """Not a history line a day for every vulnerability nobody is assigned."""
    from apps.vulnerabilities.models import Vulnerability, VulnerabilityHistory
    from apps.vulnerabilities.tasks import check_sla_violations

    team_a, _ = teams
    vulnerability = _overdue(team_a)
    check_sla_violations.apply().get()
    # Two days later, still nobody to tell: nothing new is recorded.
    VulnerabilityHistory.objects.filter(vulnerability=vulnerability).update(
        timestamp=timezone.now() - timedelta(days=2)
    )
    again = check_sla_violations.apply().get()
    assert again == {"notifications_sent": 0, "notifications_not_sent": 0}
    assert len(_sla_history(vulnerability)) == 1

    # Once it has an assignee with an address, they are told.
    Vulnerability.objects.filter(pk=vulnerability.pk).update(
        assigned_to=identity_contacts.member(team_a, "dev@team-a.example")
    )
    assigned = check_sla_violations.apply().get()
    assert assigned == {"notifications_sent": 1, "notifications_not_sent": 0}
    assert _addresses(mailoutbox) == ["dev@team-a.example"]
    assert _sla_history(vulnerability)[-1].startswith("SLA violation notification sent")


@pytest.mark.django_db
@pytest.mark.parametrize("failure", [0, OSError("connection refused")])
def test_a_failed_delivery_is_not_recorded_as_sent(teams, identity_contacts, failure):
    """A server that takes nothing, or cannot be reached; the history said "sent"."""
    from apps.vulnerabilities.tasks import check_sla_violations
    from django.core.mail import EmailMultiAlternatives

    team_a, _ = teams
    vulnerability = _overdue(
        team_a, identity_contacts.member(team_a, "dev@team-a.example")
    )

    with mock.patch.object(
        EmailMultiAlternatives,
        "send",
        autospec=True,
        **(
            {"side_effect": failure}
            if isinstance(failure, Exception)
            else {"return_value": failure}
        ),
    ) as send:
        outcome = check_sla_violations.apply().get()

    assert send.call_args.args[0].to == ["dev@team-a.example"]
    assert outcome == {"notifications_sent": 0, "notifications_not_sent": 1}
    (reason,) = _sla_history(vulnerability)
    assert reason.startswith("SLA violation notification not sent (delivery failed)")


@pytest.mark.django_db
def test_the_sla_history_is_what_the_team_reads(teams, monkeypatch):
    from apps.vulnerabilities.tasks import check_sla_violations
    from django.test import Client

    team_a, _ = teams
    vulnerability = _overdue(team_a)
    check_sla_violations.apply().get()

    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", "test-gateway-secret")
    response = Client().get(
        f"/api/v1/vulnerabilities/{vulnerability.pk}/history/",
        secure=True,
        HTTP_X_WILDBOX_USER_ID=str(uuid.uuid4()),
        HTTP_X_WILDBOX_TEAM_ID=str(team_a),
        HTTP_X_WILDBOX_ROLE="admin",
        HTTP_X_GATEWAY_SECRET="test-gateway-secret",
        HTTP_X_WILDBOX_AUTH_TYPE="session",
    )

    assert response.status_code == 200, response.content[:300]
    assert "SLA violation notification not sent" in response.content.decode()
