"""guardian's e-mails have an address to go to, and only their own team's (#705).

guardian mirrors identity's users by id, with no address, so the SLA and
assignment e-mails reached nobody; compliance notifications named no
recipient at all; and with no mail server configured, Django's console
backend printed each message to the worker's log while guardian recorded it
as sent.

Every e-mail about a team's data now goes through
``apps.core.notifications.notify_team``. The notification paths are listed
below (``PATHS``): SLA violations, assignments, alert rules, scheduled
reports and the five compliance notifications. The list is checked against
the code, not trusted: a call site of ``notify_team`` that no path covers,
or an e-mail template no path renders, fails here, so a notification added
later is covered, or these tests say it is not.

For each path, with two teams that each have an owner, an admin and a
member in identity (stood in at the HTTP layer, tests/unit/identity_stub.py):

* the e-mail goes to its own team's people and to nobody else's, never to
  a platform-wide address (#678), a former member (#676), a deactivated
  account or an address guardian remembers;
* it carries nothing of the other team: every template is rendered for
  both teams, and no e-mail to one names a row, an address or the id of the
  other;
* without a mail server nothing is printed and nothing is "sent": the
  notification is recorded as not sent, with the reason.
"""

import ast
import pathlib
import uuid
from datetime import timedelta
from unittest import mock

import pytest
import requests
from apps.core import notifications
from apps.core.models import TeamMembership
from django.core import mail
from django.db.models import F
from django.test import Client
from django.test.signals import template_rendered
from django.utils import timezone

from tests.unit import identity_stub
from tests.unit import team_fixtures as tf

GUARDIAN = pathlib.Path(__file__).resolve().parents[2]
PLATFORM = "platform-wide@example.com"
SECURITY_TEAM = "security-team@example.com"
_GW_SECRET = "test-gateway-secret"

# A team with nobody to tell, in the words its record uses.
NOBODY = "the team has no owner or admin with an active account and an address"


@pytest.fixture(autouse=True)
def environment(settings):
    """A locmem cache (the sweeps' locks), and the old platform-wide settings.

    Defined as an operator who found their names might: nothing reads them,
    and every test ends by checking they received nothing.
    """
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": f"delivery-{uuid.uuid4().hex}",
        }
    }
    settings.DEFAULT_NOTIFICATION_RECIPIENTS = [PLATFORM]
    settings.SECURITY_TEAM_EMAIL = SECURITY_TEAM
    yield
    told = {address for message in mail.outbox for address in message.recipients()}
    assert not {PLATFORM, SECURITY_TEAM} & told


class Team:
    """A team as identity knows it: an owner, an admin and a member.

    The owner never opened guardian (no membership row here): identity is
    who says they own the team. The admin and the member did.
    """

    def __init__(self, identity, label):
        self.id = uuid.uuid4()
        self.label = label
        self.tag = str(self.id)[:8]
        self.owner = identity.member(
            self.id, f"owner@{label}.example", role="owner", seen=False
        )
        self.admin = identity.member(self.id, f"admin@{label}.example", role="admin")
        self.member = identity.member(self.id, f"member@{label}.example")
        self.admins = [f"owner@{label}.example", f"admin@{label}.example"]
        self.addresses = self.admins + [f"member@{label}.example"]


@pytest.fixture
def teams(identity_contacts, db):
    return Team(identity_contacts, "team-a"), Team(identity_contacts, "team-b")


def _quiet(make, *args, **kwargs):
    patches = tf._quiet()
    try:
        return make(*args, **kwargs)
    finally:
        tf._stop(patches)


def _overdue(team_id, assignee=None, hours=5):
    return _quiet(
        tf.vulnerability,
        team_id,
        assigned_to=assignee,
        due_date=timezone.now() - timedelta(hours=hours),
    )


def _history(vulnerability, field_name):
    from apps.vulnerabilities.models import VulnerabilityHistory

    return list(
        VulnerabilityHistory.objects.filter(
            vulnerability=vulnerability, field_name=field_name
        )
        .order_by("timestamp", "pk")
        .values_list("change_reason", flat=True)
    )


def _age_history(vulnerability, days=2):
    from apps.vulnerabilities.models import VulnerabilityHistory

    # Each entry that much older, so that they keep their order.
    VulnerabilityHistory.objects.filter(vulnerability=vulnerability).update(
        timestamp=F("timestamp") - timedelta(days=days)
    )


def _sweep():
    from apps.vulnerabilities.tasks import check_sla_violations

    return check_sla_violations.apply().get()


def _assign(vulnerability):
    from apps.vulnerabilities.tasks import notify_vulnerability_assignment

    return notify_vulnerability_assignment.apply(args=[str(vulnerability.pk), None])


def _whole(message):
    """Everything an e-mail carries: its headers and both its parts."""
    parts = [message.subject, message.body, message.from_email]
    parts += [content for content, _type in getattr(message, "alternatives", [])]
    parts += message.to + message.cc + message.bcc + message.reply_to
    return "\n".join(parts)


def _to(messages):
    return [sorted(message.to) for message in messages]


# --- the notification paths ------------------------------------------------------------
#
# Each makes the rows of one notification for a team and runs what sends
# it. ``site`` is the function that calls notify_team for it; ``audience``
# is who it is for; ``templates`` what it renders.


def _run_sla_unassigned(team):
    vulnerability = _overdue(team.id)
    _sweep()
    return vulnerability


def _run_sla_assigned(team):
    vulnerability = _overdue(team.id, team.member)
    _sweep()
    return vulnerability


def _run_assignment(team):
    vulnerability = _quiet(tf.vulnerability, team.id, assigned_to=team.member)
    _assign(vulnerability).get()
    return vulnerability


def _alert_rule(team, **fields):
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        return tf.alert_rule(team.id, operator="gte", **fields)


def _run_alert(team, **fields):
    from apps.reporting import tasks

    rule = _alert_rule(team, **fields)
    assert tasks.check_alert_rule(rule.pk)["notification"] == "firing"
    return rule


def _run_alert_resolved(team):
    from apps.reporting import tasks
    from apps.reporting.models import AlertRule

    already = len(mail.outbox)
    rule = _run_alert(team)
    # The "resolved" e-mail is the one this path is about.
    del mail.outbox[already:]
    AlertRule.objects.filter(pk=rule.pk).update(threshold_value=10**6)
    assert tasks.check_alert_rule(rule.pk)["notification"] == "resolved"
    return rule


def _scheduled_report(team, recipients=()):
    from apps.reporting.models import Report

    schedule = tf.report_schedule(team.id)
    schedule.recipients = list(recipients)
    schedule.save(update_fields=["recipients"])
    return Report.objects.create(
        template=schedule.template,
        schedule=schedule,
        name=tf._tag(team.id),
        format="json",
    )


def _run_report(team):
    from apps.reporting.tasks import notify_scheduled_report

    report = _scheduled_report(team)
    notify_scheduled_report(report)
    return report


def _compliance(kind, make):
    def run(team):
        from apps.compliance.tasks import send_compliance_notification

        row = _quiet(make, team.id)
        # What the callers pass: the task reads the row instead, except
        # for the moment of the event.
        data = {
            "started_at": "2026-10-05T10:00:00",
            "completed_at": "2026-10-05T11:00:00",
        }
        send_compliance_notification(kind, str(row.pk), data)
        return row

    return run


def _overdue_assessment(team_id):
    assessment = tf.assessment(team_id)
    assessment.due_date = timezone.now() - timedelta(days=3, hours=1)
    assessment.save(update_fields=["due_date"])
    return assessment


class Path:
    def __init__(self, name, run, site, audience, template):
        self.name, self.run, self.site = name, run, site
        self.audience, self.template = audience, template

    def recipients(self, team):
        if self.audience == "assignee":
            return [f"member@{team.label}.example"]
        return team.admins

    def __repr__(self):
        return self.name


_VULNERABILITIES = "apps/vulnerabilities/notifications.py"
_REPORTING = "apps/reporting/tasks.py"
_COMPLIANCE = ("apps/compliance/tasks.py", "send_compliance_notification")

PATHS = [
    Path(
        "sla-unassigned",
        _run_sla_unassigned,
        (_VULNERABILITIES, "notify_sla_violation"),
        "admins",
        "vulnerabilities/sla_violation.html",
    ),
    Path(
        "sla-assigned",
        _run_sla_assigned,
        (_VULNERABILITIES, "notify_sla_violation"),
        "assignee",
        "vulnerabilities/sla_violation.html",
    ),
    Path(
        "assignment",
        _run_assignment,
        (_VULNERABILITIES, "notify_assignment"),
        "assignee",
        "vulnerabilities/assignment.html",
    ),
    Path(
        "alert-firing",
        _run_alert,
        (_REPORTING, "deliver_alert_notification"),
        "admins",
        "reporting/alert_notification.html",
    ),
    Path(
        "alert-resolved",
        _run_alert_resolved,
        (_REPORTING, "deliver_alert_notification"),
        "admins",
        "reporting/alert_notification.html",
    ),
    Path(
        "scheduled-report",
        _run_report,
        (_REPORTING, "notify_scheduled_report"),
        "admins",
        "reporting/report_generated.html",
    ),
    Path(
        "compliance-high-risk",
        _compliance("high_risk_finding", tf.result),
        _COMPLIANCE,
        "admins",
        "compliance/high_risk_finding.html",
    ),
    Path(
        "compliance-started",
        _compliance("assessment_started", tf.assessment),
        _COMPLIANCE,
        "admins",
        "compliance/assessment_started.html",
    ),
    Path(
        "compliance-completed",
        _compliance("assessment_completed", tf.assessment),
        _COMPLIANCE,
        "admins",
        "compliance/assessment_completed.html",
    ),
    Path(
        "compliance-overdue",
        _compliance("assessment_overdue", _overdue_assessment),
        _COMPLIANCE,
        "admins",
        "compliance/assessment_overdue.html",
    ),
    Path(
        "compliance-expiring",
        _compliance("exception_expiring", tf.exception),
        _COMPLIANCE,
        "admins",
        "compliance/exception_expiring.html",
    ),
]
BY_NAME = {path.name: path for path in PATHS}
FALLBACK_PATHS = [path for path in PATHS if path.audience == "admins"]
ASSIGNEE_PATHS = [path for path in PATHS if path.audience == "assignee"]

# Templates under apps/*/templates that are not an e-mail: the document a
# report is.
NOT_AN_EMAIL = {"reporting/report.html"}


def _call_sites():
    """(file, function) of every call of notify_team* outside its module."""
    found = set()
    files = [*GUARDIAN.glob("apps/**/*.py"), *GUARDIAN.glob("guardian/**/*.py")]
    assert len(files) > 100
    for path in files:
        relative = str(path.relative_to(GUARDIAN))
        if relative == "apps/core/notifications.py":
            continue
        tree = ast.parse(path.read_text())
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(function):
                if isinstance(node, ast.Call):
                    name = getattr(node.func, "id", getattr(node.func, "attr", ""))
                    if name in ("notify_team", "notify_team_from_template"):
                        found.add((relative, function.name))
    return found


def _mail_templates():
    return {
        str(path.relative_to(root))
        for root in GUARDIAN.glob("apps/*/templates")
        for path in root.rglob("*.html")
    } - NOT_AN_EMAIL


# --- the list of paths is the code's ----------------------------------------------------


def test_every_place_that_notifies_a_team_is_a_path_here():
    sites = _call_sites()

    assert len(sites) == 5, sorted(sites)
    assert sites == {path.site for path in PATHS}


def test_every_e_mail_template_is_a_path_here():
    templates = _mail_templates()

    assert len(templates) == 9, sorted(templates)
    assert templates == {path.template for path in PATHS}


def test_nothing_else_sends_e_mail():
    """One door: no send_mail, no message built by hand, no mail to admins."""
    senders = ("send_mail", "send_mass_mail", "mail_admins", "mail_managers")
    builders = ("EmailMessage", "EmailMultiAlternatives")
    found = []
    for path in [*GUARDIAN.glob("apps/**/*.py"), *GUARDIAN.glob("guardian/**/*.py")]:
        relative = str(path.relative_to(GUARDIAN))
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", getattr(node.func, "attr", ""))
                if name in senders or (
                    name in builders and relative != "apps/core/notifications.py"
                ):
                    found.append(f"{relative}:{node.lineno} {name}")
    assert found == []


def test_guardian_sends_by_smtp_whatever_the_environment_says():
    """EMAIL_BACKEND is not read: the console backend "sent" to the log."""
    from guardian.mailconf import mail_settings

    for environ in (
        {},
        {"EMAIL_BACKEND": "django.core.mail.backends.console.EmailBackend"},
        {
            "EMAIL_BACKEND": "django.core.mail.backends.dummy.EmailBackend",
            "EMAIL_HOST": "smtp.example.com",
            "DEFAULT_FROM_EMAIL": "guardian@example.com",
        },
    ):
        assert (
            mail_settings(environ)["EMAIL_BACKEND"]
            == "django.core.mail.backends.smtp.EmailBackend"
        )


# --- who is told -------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("path", PATHS, ids=repr)
def test_a_notification_goes_to_its_own_teams_people_and_nobody_else(
    path, teams, identity_contacts, mailoutbox
):
    team_a, team_b = teams

    path.run(team_a)

    assert _to(mailoutbox) == [sorted(path.recipients(team_a))]
    # Nobody of the other team was even asked about.
    asked = {question["json"]["team_id"] for question in identity_contacts.asked}
    assert asked == {str(team_a.id)}
    assert str(team_b.id) not in _whole(mailoutbox[0])


@pytest.mark.django_db
@pytest.mark.parametrize("path", PATHS, ids=repr)
def test_an_e_mail_carries_nothing_of_another_team(path, teams, mailoutbox):
    """Each template, rendered for both teams: neither names the other."""
    rendered = []

    def record(sender, template, **_kwargs):
        rendered.append(template.name)

    template_rendered.connect(record)
    try:
        for team in teams:
            path.run(team)
    finally:
        template_rendered.disconnect(record)

    assert rendered.count(path.template) >= 2
    assert len(mailoutbox) == 2
    for team, other in (teams, teams[::-1]):
        (message,) = [m for m in mailoutbox if set(m.to) <= set(team.addresses)]
        text = _whole(message)
        # It is about its team (the positive control) ...
        assert team.tag in text, text
        # ... and names no row, no address and no id of the other.
        assert other.tag not in text
        assert str(other.id) not in text
        for address in other.addresses:
            assert address not in text


@pytest.mark.django_db
def test_an_alert_s_value_is_its_own_teams(teams, mailoutbox):
    """What the e-mail reports is measured over the rule's team alone."""
    team_a, team_b = teams
    _quiet(tf.vulnerability, team_a.id)
    for _ in range(3):
        _quiet(tf.vulnerability, team_b.id)

    _run_alert(team_a)
    _run_alert(team_b)

    by_team = {tuple(sorted(m.to)): m.body for m in mailoutbox}
    assert "Value: 1.0" in by_team[tuple(sorted(team_a.admins))]
    assert "Value: 3.0" in by_team[tuple(sorted(team_b.admins))]


@pytest.mark.django_db
@pytest.mark.parametrize(
    "kind,make,theirs",
    [
        ("high_risk_finding", tf.result, {"assessment": "x", "control": "x"}),
        ("assessment_started", tf.assessment, {"assessment": "x", "framework": "x"}),
        ("assessment_completed", tf.assessment, {"assessment": "x", "framework": "x"}),
        (
            "assessment_overdue",
            _overdue_assessment,
            {"assessment": "x", "framework": "x"},
        ),
        ("exception_expiring", tf.exception, {"exception": "x", "control": "x"}),
    ],
)
def test_a_compliance_e_mail_says_what_its_row_says_not_what_it_was_passed(
    kind, make, theirs, teams, mailoutbox
):
    """Names passed for another team's row cannot reach this team's e-mail."""
    from apps.compliance.tasks import send_compliance_notification

    team_a, team_b = teams
    row = _quiet(make, team_a.id)
    leaked = f"{tf.MARKER}-{team_b.tag}-other-teams-row"
    data = {name: leaked for name in theirs}
    data.update(status=leaked, risk_level=leaked, due_date=leaked, expiry_date=leaked)

    assert send_compliance_notification(kind, str(row.pk), data) is True

    (message,) = mailoutbox
    assert message.to == team_a.admins
    assert leaked not in _whole(message) and team_b.tag not in _whole(message)
    assert team_a.tag in _whole(message)


@pytest.mark.django_db
def test_a_compliance_notification_of_a_row_that_is_gone_is_not_sent(
    teams, mailoutbox, caplog
):
    from apps.compliance.tasks import send_compliance_notification

    with caplog.at_level("WARNING", logger="apps.compliance.tasks"):
        sent = send_compliance_notification(
            "assessment_started", str(uuid.uuid4()), {"assessment": "Q3"}
        )

    assert sent is False and mailoutbox == []
    assert "no longer exists" in caplog.text


# --- the per-team default: owners and admins, as identity lists them now --------------


@pytest.mark.django_db
@pytest.mark.parametrize("path", FALLBACK_PATHS, ids=repr)
def test_the_default_recipients_are_the_owners_and_admins_identity_lists(
    path, teams, identity_contacts, mailoutbox
):
    """Not a member, not who left, not a deactivated account, not without an address."""
    team_a, team_b = teams
    left = identity_contacts.member(team_a.id, "left@team-a.example", role="admin")
    identity_contacts.remove(left, team_a.id)
    disabled = identity_contacts.member(
        team_a.id, "disabled@team-a.example", role="admin"
    )
    identity_contacts.deactivate(disabled)
    identity_contacts.member(team_a.id, "", role="admin")
    # An admin of another team, and a member of this one.
    elsewhere = identity_contacts.member(team_b.id, "both@example.com", role="admin")
    identity_contacts.add(team_a.id, elsewhere.username, "both@example.com")
    TeamMembership.objects.create(team_id=team_a.id, user=elsewhere)

    path.run(team_a)

    assert _to(mailoutbox) == [sorted(team_a.admins)]
    assert identity_contacts.asked[-1]["json"] == {
        "team_id": str(team_a.id),
        "roles": ["admin", "owner"],
    }


@pytest.mark.django_db
@pytest.mark.parametrize("path", FALLBACK_PATHS, ids=repr)
def test_who_is_told_is_who_holds_the_role_when_it_is_sent(
    path, teams, identity_contacts, mailoutbox
):
    """Asked each time: a demotion, a promotion and a new address take effect."""
    team_a, _ = teams
    identity_contacts.change_role(team_a.admin, team_a.id, "member")
    identity_contacts.change_role(team_a.member, team_a.id, "admin")
    identity_contacts.change_address(team_a.owner, "new-owner@team-a.example")

    path.run(team_a)

    assert _to(mailoutbox) == [
        sorted(["new-owner@team-a.example", "member@team-a.example"])
    ]
    assert "owner@team-a.example" not in mailoutbox[0].to


@pytest.mark.django_db
@pytest.mark.parametrize("path", FALLBACK_PATHS, ids=repr)
def test_a_team_with_nobody_to_tell_is_sent_nothing(
    path, teams, identity_contacts, mailoutbox, caplog
):
    """Its notification does not go to another team's people instead."""
    team_a, team_b = teams
    for user in (team_a.owner, team_a.admin):
        identity_contacts.deactivate(user)

    with caplog.at_level("WARNING", logger="apps.core.notifications"):
        path.run(team_a)

    assert mailoutbox == []
    assert f"Notification not sent ({_kind(path)}), {NOBODY}" in caplog.text


def _kind(path):
    for prefix, kind in (
        ("sla", "sla"),
        ("assignment", "assignment"),
        ("alert", "alert"),
        ("scheduled", "report"),
        ("compliance", "compliance"),
    ):
        if path.name.startswith(prefix):
            return kind
    raise AssertionError(path)


@pytest.mark.django_db
def test_a_row_without_a_team_has_no_owners_and_admins(identity_contacts, mailoutbox):
    """Rows from before guardian kept a team: nobody to ask identity about."""
    from apps.compliance.tasks import send_compliance_notification
    from apps.reporting import tasks
    from apps.reporting.models import AlertNotification

    with mock.patch("apps.reporting.signals.check_alert_rule"):
        rule = tf.alert_rule(None, operator="gte")
    tasks.check_alert_rule(rule.pk)
    assessment = _quiet(tf.assessment, None)
    sent = send_compliance_notification("assessment_started", str(assessment.pk), {})
    vulnerability = _overdue(None, tf.user())
    outcome = _sweep()
    assignment = _assign(vulnerability).get()

    assert mailoutbox == [] and sent is False
    assert assignment == {"notification_sent": False}
    assert _history(vulnerability, "assignment_notification") == [
        f"Assignment notification not sent ({notifications.NO_TEAM})"
    ]
    assert identity_contacts.asked == []
    recorded = AlertNotification.objects.get(rule=rule)
    assert (recorded.delivered, recorded.failure_reason) == (
        False,
        notifications.NO_TEAM,
    )
    assert outcome == {"notifications_sent": 0, "notifications_not_sent": 1}
    assert notifications.NO_TEAM in _history(vulnerability, "sla_status")[0]


@pytest.mark.django_db
def test_named_recipients_are_used_as_they_are_and_identity_is_not_asked(
    teams, identity_contacts, mailoutbox
):
    """What a team typed into its rule or schedule is its own choice."""
    from apps.reporting.tasks import notify_scheduled_report

    team_a, _ = teams
    _run_alert(team_a, notification_config={"recipients": ["soc@team-a.example"]})
    report = _scheduled_report(team_a, ["ciso@team-a.example", "CISO@team-a.example"])
    assert notify_scheduled_report(report) is True

    assert _to(mailoutbox) == [["soc@team-a.example"], ["ciso@team-a.example"]]
    assert identity_contacts.asked == []


# --- the assignee: a member here, with an active account there ------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("path", ASSIGNEE_PATHS, ids=repr)
def test_the_assignee_s_address_is_identity_s_not_guardian_s_copy(
    path, teams, identity_contacts, mailoutbox
):
    """No user that came through the gateway has an address here; a stale one is not used."""
    team_a, _ = teams
    team_a.member.email = "stale-copy@example.com"
    team_a.member.save(update_fields=["email"])

    path.run(team_a)

    assert _to(mailoutbox) == [["member@team-a.example"]]
    assert identity_contacts.asked[0]["json"] == {
        "team_id": str(team_a.id),
        "user_ids": [team_a.member.username],
    }


@pytest.mark.django_db
def test_a_changed_address_is_used_from_the_next_e_mail(
    teams, identity_contacts, mailoutbox
):
    """The e-mail change of #569: the old address receives nothing more."""
    team_a, _ = teams
    vulnerability = _overdue(team_a.id, team_a.member)
    _sweep()
    identity_contacts.change_address(team_a.member, "moved@elsewhere.example")
    _age_history(vulnerability)
    _sweep()

    assert _to(mailoutbox) == [["member@team-a.example"], ["moved@elsewhere.example"]]


def _deactivated(identity, team):
    identity.deactivate(team.member)


def _removed_in_identity(identity, team):
    identity.remove(team.member, team.id)


def _not_seen_here(identity, team):
    from django.conf import settings

    TeamMembership.objects.filter(team_id=team.id, user=team.member).update(
        last_seen=timezone.now() - settings.TEAM_MEMBERSHIP_MAX_AGE - timedelta(days=1)
    )


def _revoked_here(identity, team):
    from apps.core.memberships import revoke_membership
    from apps.vulnerabilities.models import Vulnerability

    assigned = list(Vulnerability.objects.filter(assigned_to=team.member))
    revoke_membership(team.id, team.member.username)
    # The notice also clears the assignment; put it back, as a stale row.
    for vulnerability in assigned:
        Vulnerability.objects.filter(pk=vulnerability.pk).update(
            assigned_to=team.member
        )


def _no_address(identity, team):
    identity.change_address(team.member, "")


GONE = [_deactivated, _removed_in_identity, _not_seen_here, _revoked_here, _no_address]


@pytest.mark.django_db
@pytest.mark.parametrize("gone", GONE, ids=lambda f: f.__name__.strip("_"))
def test_an_sla_violation_of_an_assignee_who_cannot_be_told_goes_to_the_admins(
    gone, teams, identity_contacts, mailoutbox
):
    """Deactivated, removed (in identity or here), not seen, no address: never them."""
    team_a, _ = teams
    vulnerability = _overdue(team_a.id, team_a.member)
    gone(identity_contacts, team_a)

    assert _sweep() == {"notifications_sent": 1, "notifications_not_sent": 0}

    assert _to(mailoutbox) == [sorted(team_a.admins)]
    assert "member@team-a.example" not in _whole(mailoutbox[0])
    assert "has no assignee who can be told" in mailoutbox[0].body
    assert _history(vulnerability, "sla_status")[0].startswith(
        "SLA violation notification sent to the team's owners and admins "
        "(no assignee to e-mail) - "
    )


@pytest.mark.django_db
@pytest.mark.parametrize("gone", GONE, ids=lambda f: f.__name__.strip("_"))
def test_an_assignment_to_somebody_who_cannot_be_told_is_not_e_mailed(
    gone, teams, identity_contacts, mailoutbox
):
    """And not to the admins instead: it is only meaningful to the assignee."""
    team_a, _ = teams
    vulnerability = _quiet(tf.vulnerability, team_a.id, assigned_to=team_a.member)
    gone(identity_contacts, team_a)

    assert _assign(vulnerability).get() == {"notification_sent": False}

    assert mailoutbox == []


@pytest.mark.django_db
def test_an_assignee_of_another_team_is_not_told(teams, identity_contacts, mailoutbox):
    """A stale assignment across teams: a member there is not one here."""
    team_a, team_b = teams
    vulnerability = _overdue(team_a.id, team_b.member)

    assert _assign(vulnerability).get() == {"notification_sent": False}
    _sweep()

    assert _to(mailoutbox) == [sorted(team_a.admins)]
    assert all(
        q["json"].get("user_ids") != [team_b.member.username]
        for q in identity_contacts.asked
    )


@pytest.mark.django_db
def test_an_owner_who_never_opened_guardian_is_told(teams, mailoutbox):
    """identity says who owns a team, not guardian's record of who called it."""
    team_a, _ = teams
    assert not TeamMembership.objects.filter(user=team_a.owner).exists()

    _run_sla_unassigned(team_a)

    assert "owner@team-a.example" in mailoutbox[0].to


@pytest.mark.django_db
def test_an_assignment_is_recorded_in_the_vulnerability_s_history(
    teams, identity_contacts, mailoutbox
):
    team_a, _ = teams
    told = _run_assignment(team_a)
    untold = _quiet(tf.vulnerability, team_a.id, assigned_to=team_a.member)
    identity_contacts.deactivate(team_a.member)
    _assign(untold).get()

    assert _history(told, "assignment_notification") == ["Assignment notification sent"]
    assert _history(untold, "assignment_notification") == [
        "Assignment notification not sent (the member has no active account "
        "with an address in the team)"
    ]


@pytest.mark.django_db
def test_an_assignment_to_a_group_has_no_address(teams, mailoutbox, caplog):
    team_a, _ = teams
    vulnerability = _quiet(tf.vulnerability, team_a.id, assignee_group="blue team")

    with caplog.at_level("WARNING", logger="apps.vulnerabilities.tasks"):
        result = _assign(vulnerability)

    assert result.get() == {"notification_sent": False}
    assert mailoutbox == []
    assert "it is assigned to a group, which has no address" in caplog.text


@pytest.mark.django_db
def test_the_assignment_task_runs_without_an_assigner(teams, mailoutbox):
    """It looked the assigner up first, and failed for a call without one."""
    team_a, _ = teams
    vulnerability = _quiet(tf.vulnerability, team_a.id, assigned_to=team_a.member)

    result = _assign(vulnerability)

    assert result.state == "SUCCESS", result.traceback
    assert _to(mailoutbox) == [["member@team-a.example"]]
    assert "None" not in mailoutbox[0].body


# --- how often ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_assignee_is_reminded_daily_the_admins_are_told_once(teams, mailoutbox):
    team_a, _ = teams
    assigned = _overdue(team_a.id, team_a.member)
    unassigned = _overdue(team_a.id)

    for _day in range(3):
        _sweep()
        # Within a day, however often the check runs: nothing more.
        assert _sweep() == {"notifications_sent": 0, "notifications_not_sent": 0}
        _age_history(assigned)
        _age_history(unassigned)

    to_member = [m for m in mailoutbox if m.to == ["member@team-a.example"]]
    to_admins = [m for m in mailoutbox if sorted(m.to) == sorted(team_a.admins)]
    assert (len(to_member), len(to_admins)) == (3, 1)
    assert len(_history(unassigned, "sla_status")) == 1
    assert len(_history(assigned, "sla_status")) == 3


@pytest.mark.django_db
def test_once_told_the_admins_are_told_again_only_of_a_new_situation(
    teams, identity_contacts, mailoutbox
):
    """Assigned afterwards, the assignee is reminded; unassigned again, the admins."""
    from apps.vulnerabilities.models import Vulnerability

    team_a, _ = teams
    vulnerability = _overdue(team_a.id)
    _sweep()
    _age_history(vulnerability)
    Vulnerability.objects.filter(pk=vulnerability.pk).update(assigned_to=team_a.member)
    _sweep()
    _age_history(vulnerability)
    identity_contacts.deactivate(team_a.member)
    _sweep()

    assert _to(mailoutbox) == [
        sorted(team_a.admins),
        ["member@team-a.example"],
        sorted(team_a.admins),
    ]


@pytest.mark.django_db
def test_a_reason_only_a_person_can_remove_is_recorded_once(
    teams, identity_contacts, mailoutbox
):
    """Not a line a day for every overdue vulnerability of a team nobody runs."""
    team_a, _ = teams
    for user in (team_a.owner, team_a.admin):
        identity_contacts.deactivate(user)
    vulnerability = _overdue(team_a.id)

    assert _sweep() == {"notifications_sent": 0, "notifications_not_sent": 1}
    _age_history(vulnerability)
    assert _sweep() == {"notifications_sent": 0, "notifications_not_sent": 0}

    (line,) = _history(vulnerability, "sla_status")
    assert line.startswith(f"SLA violation notification not sent ({NOBODY}) - ")
    # Somebody takes the team over: they are told.
    identity_contacts.member(team_a.id, "new-owner@team-a.example", role="owner")
    _age_history(vulnerability)
    assert _sweep() == {"notifications_sent": 1, "notifications_not_sent": 0}
    assert _to(mailoutbox) == [["new-owner@team-a.example"]]


# --- no mail server: recorded as not sent, never printed -------------------------------


@pytest.fixture
def no_mail_server(settings):
    settings.EMAIL_HOST = ""


@pytest.mark.django_db
@pytest.mark.parametrize("path", PATHS, ids=repr)
def test_without_a_mail_server_nothing_is_sent_or_printed(
    path, teams, no_mail_server, mailoutbox, caplog, capsys
):
    """The console backend printed the team's data and reported it sent."""
    team_a, _ = teams
    with caplog.at_level("WARNING", logger="apps.core.notifications"):
        path.run(team_a)

    assert mailoutbox == []
    assert "no mail server is configured" in caplog.text
    # What the console backend wrote for each message: its headers and body.
    printed = capsys.readouterr()
    for trace in ("Subject:", "To:", "@team-a.example", "guardian@test.invalid"):
        assert trace not in printed.out + printed.err
    assert "@team-a.example" not in caplog.text


@pytest.mark.django_db
def test_without_a_mail_server_each_record_says_so(teams, no_mail_server, mailoutbox):
    from apps.compliance.tasks import send_compliance_notification
    from apps.reporting import tasks
    from apps.reporting.models import AlertNotification

    team_a, _ = teams
    rule = _alert_rule(team_a)
    tasks.check_alert_rule(rule.pk)
    named = _alert_rule(
        team_a, notification_config={"recipients": ["soc@team-a.example"]}
    )
    tasks.check_alert_rule(named.pk)
    overdue = _overdue(team_a.id, team_a.member)
    outcome = _sweep()
    assigned = _quiet(tf.vulnerability, team_a.id, assigned_to=team_a.member)
    assignment = _assign(assigned).get()
    assessment = _quiet(tf.assessment, team_a.id)

    assert mailoutbox == []
    # Who it was addressed to, that it did not go, and why.
    recorded = AlertNotification.objects.get(rule=rule)
    assert recorded.recipients == team_a.admins
    assert (recorded.delivered, recorded.failure_reason) == (
        False,
        "no mail server is configured",
    )
    recorded = AlertNotification.objects.get(rule=named)
    assert recorded.recipients == ["soc@team-a.example"]
    assert (recorded.delivered, recorded.failure_reason) == (
        False,
        "no mail server is configured",
    )
    assert outcome == {"notifications_sent": 0, "notifications_not_sent": 1}
    assert _history(overdue, "sla_status")[0].startswith(
        "SLA violation notification not sent (no mail server is configured) - "
    )
    assert assignment == {"notification_sent": False}
    assert _history(assigned, "assignment_notification") == [
        "Assignment notification not sent (no mail server is configured)"
    ]
    assert (
        send_compliance_notification("assessment_started", str(assessment.pk), {})
        is False
    )
    assert tasks.notify_scheduled_report(_scheduled_report(team_a)) is False


@pytest.mark.django_db
def test_without_a_mail_server_the_sla_check_writes_one_line_and_asks_nobody(
    teams, identity_contacts, settings, mailoutbox
):
    """Not a line a day, nor a question to identity per overdue vulnerability."""
    team_a, _ = teams
    settings.EMAIL_HOST = ""
    vulnerability = _overdue(team_a.id, team_a.member)

    _sweep()
    _age_history(vulnerability)
    assert _sweep() == {"notifications_sent": 0, "notifications_not_sent": 0}

    assert len(_history(vulnerability, "sla_status")) == 1
    assert identity_contacts.asked == []
    # A mail server is configured: the next check sends.
    settings.EMAIL_HOST = "smtp.test.invalid"
    _age_history(vulnerability)
    assert _sweep() == {"notifications_sent": 1, "notifications_not_sent": 0}
    assert _to(mailoutbox) == [["member@team-a.example"]]


@pytest.mark.django_db
def test_the_alert_record_is_what_the_team_reads(teams, settings, monkeypatch):
    """GET .../alerts/{id}/notifications/: addressed to whom, delivered or why not."""
    from apps.reporting import tasks

    team_a, team_b = teams
    sent = _run_alert(team_a)
    settings.EMAIL_HOST = ""
    unsent = _alert_rule(team_a)
    tasks.check_alert_rule(unsent.pk)

    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)

    def rows(rule, team):
        response = Client().get(
            f"/api/v1/reports/alerts/{rule.pk}/notifications/",
            secure=True,
            HTTP_X_WILDBOX_USER_ID=team.member.username,
            HTTP_X_WILDBOX_TEAM_ID=str(team.id),
            HTTP_X_WILDBOX_ROLE="member",
            HTTP_X_GATEWAY_SECRET=_GW_SECRET,
            HTTP_X_WILDBOX_AUTH_TYPE="session",
        )
        if response.status_code != 200:
            return response.status_code
        body = response.json()
        return [
            (row["recipients"], row["delivered"], row["failure_reason"])
            for row in (body["results"] if isinstance(body, dict) else body)
        ]

    assert rows(sent, team_a) == [(team_a.admins, True, "")]
    assert rows(unsent, team_a) == [
        (team_a.admins, False, "no mail server is configured")
    ]
    # Another team does not read it: the record names this team's people.
    assert rows(sent, team_b) == 404


# --- identity does not answer, or answers something else --------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "fault,retry",
    [
        (requests.ConnectionError("refused"), True),
        (requests.Timeout("slow"), True),
        (identity_stub.Response(503, {"detail": "not configured"}), True),
        (identity_stub.Response(500), True),
        (identity_stub.Response(403, {"detail": "Invalid contacts secret"}), False),
        (identity_stub.Response(422, {"detail": "invalid"}), False),
        (identity_stub.Response(302), False),
    ],
    ids=["refused", "timeout", "503", "500", "403", "422", "redirect"],
)
def test_identity_not_answering_is_a_notification_not_sent(
    fault, retry, teams, identity_contacts, mailoutbox
):
    team_a, _ = teams
    identity_contacts.fault = fault

    delivery = notifications.notify_team(team_a.id, "s", "t", member=team_a.member)

    assert mailoutbox == []
    assert (delivery.sent, delivery.recipients) == (False, ())
    assert delivery.reason == "identity could not be asked for the addresses"
    assert delivery.retry is retry


def _answer(team, contacts, **extra):
    return identity_stub.Response(
        200, {"team_id": str(team.id), "contacts": contacts, **extra}
    )


def _contact(user, email="x@team-a.example", role="owner"):
    return {"user_id": user.username, "email": email, "role": role}


@pytest.mark.django_db
@pytest.mark.parametrize(
    "wrong",
    [
        "another-team",
        "a-user-not-asked-for",
        "a-role-not-asked-for",
        "an-unknown-role",
        "an-unknown-role-of-the-user-asked-for",
        "extra-fields",
        "extra-contact-fields",
        "not-a-list",
        "not-json",
        "a-list",
        "an-address-that-is-not-text",
        "a-user-id-that-is-not-one",
    ],
)
def test_an_answer_that_is_wrong_somewhere_is_not_used_at_all(
    wrong, teams, identity_contacts, mailoutbox
):
    """Where a team's data is about to be sent is not taken on trust."""
    team_a, team_b = teams
    good = _contact(team_a.owner)
    by_user = False
    if wrong == "another-team":
        fault = _answer(team_b, [good])
    elif wrong == "a-user-not-asked-for":
        by_user = True
        fault = _answer(team_a, [_contact(team_a.member, role="member"), good])
    elif wrong == "a-role-not-asked-for":
        fault = _answer(team_a, [good, _contact(team_a.member, role="member")])
    elif wrong == "an-unknown-role":
        fault = _answer(team_a, [_contact(team_a.owner, role="superuser")])
    elif wrong == "an-unknown-role-of-the-user-asked-for":
        by_user = True
        fault = _answer(team_a, [_contact(team_a.member, role="superuser")])
    elif wrong == "extra-fields":
        fault = _answer(team_a, [good], also=[_contact(team_b.owner)])
    elif wrong == "extra-contact-fields":
        fault = _answer(team_a, [{**good, "cc": "elsewhere@example.com"}])
    elif wrong == "not-a-list":
        fault = _answer(team_a, {"0": good})
    elif wrong == "not-json":
        fault = identity_stub.Response(200)
    elif wrong == "a-list":
        fault = identity_stub.Response(200, [good])
    elif wrong == "an-address-that-is-not-text":
        fault = _answer(team_a, [_contact(team_a.owner, email=["a@b.example"])])
    else:
        fault = _answer(team_a, [{**good, "user_id": "the-owner"}])
    identity_contacts.fault = fault

    delivery = notifications.notify_team(
        team_a.id, "s", "t", member=team_a.member if by_user else None
    )

    assert mailoutbox == []
    assert (delivery.sent, delivery.retry) == (False, False)
    assert delivery.reason == "identity's answer about the addresses was not understood"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "address",
    [
        "",
        "not-an-address",
        "a@b.example, elsewhere@example.com",
        "a@b.example\nBcc: elsewhere@example.com",
        "Somebody <a@b.example>",
        "a@b.example;c@d.example",
        " a@b.example",
        # Valid as an address, with a quoted local part: not one guardian
        # puts in a recipient list.
        '"a,b"@b.example',
        '"a b"@b.example',
    ],
)
def test_an_entry_that_is_not_one_address_is_left_out(
    address, teams, identity_contacts, mailoutbox
):
    """A member guardian cannot write to; the others are told."""
    team_a, _ = teams
    identity_contacts.fault = _answer(
        team_a,
        [
            _contact(team_a.owner, email=address),
            _contact(team_a.admin, email="admin@team-a.example", role="admin"),
        ],
    )

    delivery = notifications.notify_team(team_a.id, "s", "t")

    assert delivery.recipients == ("admin@team-a.example",)
    assert _to(mailoutbox) == [["admin@team-a.example"]]


@pytest.mark.django_db
def test_an_sla_violation_identity_could_not_be_asked_about_is_tried_again(
    teams, identity_contacts, mailoutbox
):
    """Recorded each time, unlike a reason only a person can remove."""
    team_a, _ = teams
    vulnerability = _overdue(team_a.id, team_a.member)
    identity_contacts.fault = requests.ConnectionError("refused")

    assert _sweep() == {"notifications_sent": 0, "notifications_not_sent": 1}
    _age_history(vulnerability)
    assert _sweep() == {"notifications_sent": 0, "notifications_not_sent": 1}
    identity_contacts.fault = None
    _age_history(vulnerability)
    assert _sweep() == {"notifications_sent": 1, "notifications_not_sent": 0}

    lines = _history(vulnerability, "sla_status")
    assert [line.rsplit(" - ", 1)[0] for line in lines] == [
        "SLA violation notification not sent (identity could not be asked for "
        "the addresses)",
        "SLA violation notification not sent (identity could not be asked for "
        "the addresses)",
        "SLA violation notification sent",
    ]
    assert _to(mailoutbox) == [["member@team-a.example"]]


@pytest.mark.django_db
def test_an_assignment_identity_could_not_be_asked_about_is_retried_then_recorded(
    teams, identity_contacts, mailoutbox
):
    """Three more attempts; the last one writes what became of it."""
    team_a, _ = teams
    vulnerability = _quiet(tf.vulnerability, team_a.id, assigned_to=team_a.member)
    identity_contacts.fault = requests.ConnectionError("refused")

    result = _assign(vulnerability)

    assert result.get() == {"notification_sent": False}
    assert len(identity_contacts.asked) == 4
    assert _history(vulnerability, "assignment_notification") == [
        "Assignment notification not sent (identity could not be asked for "
        "the addresses)"
    ]
    assert mailoutbox == []


@pytest.mark.django_db
def test_a_mail_server_that_refuses_is_a_notification_not_sent(
    teams, mailoutbox, caplog
):
    from apps.reporting import tasks
    from apps.reporting.models import AlertNotification
    from django.core.mail import EmailMultiAlternatives

    team_a, _ = teams
    rule = _alert_rule(team_a)
    with mock.patch.object(
        EmailMultiAlternatives, "send", side_effect=OSError("to owner@team-a.example")
    ):
        with caplog.at_level("DEBUG"):
            delivery = notifications.notify_team(team_a.id, "s", "t")
            tasks.check_alert_rule(rule.pk)

    # The kind of error, not its text: a refusal can quote the addresses.
    assert "delivery failed with OSError" in caplog.text
    assert "@team-a.example" not in caplog.text
    assert (delivery.sent, delivery.reason, delivery.retry) == (
        False,
        "delivery failed",
        True,
    )
    assert delivery.recipients == tuple(team_a.admins)
    recorded = AlertNotification.objects.get(rule=rule)
    assert (recorded.delivered, recorded.failure_reason) == (False, "delivery failed")


# --- how identity is asked -----------------------------------------------------------------


@pytest.mark.django_db
def test_identity_is_asked_with_the_contacts_secret_and_nothing_else(
    teams, identity_contacts, monkeypatch
):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    team_a, _ = teams

    notifications.notify_team(team_a.id, "s", "t")

    (question,) = identity_contacts.asked
    assert question["url"] == identity_stub.URL
    assert question["headers"] == {"X-Guardian-Contacts-Secret": identity_stub.SECRET}
    assert question["allow_redirects"] is False
    assert question["timeout"] == (3, 5)
    assert _GW_SECRET not in repr(question)


def test_identity_is_not_asked_through_a_proxy_from_the_environment():
    """The worker may have one for what it fetches outside; this carries a secret."""
    with notifications._session() as session:
        assert isinstance(session, requests.Session)
        assert session.trust_env is False


@pytest.mark.django_db
@pytest.mark.parametrize("secret", [None, ""])
def test_without_a_contacts_secret_identity_is_not_asked(
    secret, teams, identity_contacts, settings, mailoutbox
):
    """A deployment that has not set one: only what a team typed is written to."""
    team_a, _ = teams
    settings.TEAM_CONTACTS_SECRET = secret

    delivery = notifications.notify_team(team_a.id, "s", "t", member=team_a.member)
    named = notifications.notify_team(team_a.id, "s", "t", named=["soc@team-a.example"])

    assert identity_contacts.asked == []
    assert (delivery.sent, delivery.retry) == (False, False)
    assert delivery.reason == (
        "guardian is not set up to ask identity for addresses "
        "(GUARDIAN_CONTACTS_SECRET)"
    )
    assert named.sent and _to(mailoutbox) == [["soc@team-a.example"]]


@pytest.mark.django_db
def test_a_sweep_asks_once_per_team_and_assignee_and_the_next_asks_again(
    teams, identity_contacts
):
    """Remembered for one task, so nothing stale is used by the next."""
    team_a, _ = teams
    for _ in range(4):
        _overdue(team_a.id, team_a.member)
    for _ in range(3):
        _overdue(team_a.id)

    assert _sweep() == {"notifications_sent": 7, "notifications_not_sent": 0}
    assert len(identity_contacts.asked) == 2

    directory = notifications.TeamDirectory()
    directory.default_addresses(team_a.id)
    directory.default_addresses(team_a.id)
    notifications.TeamDirectory().default_addresses(team_a.id)
    assert len(identity_contacts.asked) == 4


@pytest.mark.django_db
def test_no_address_and_no_secret_is_written_to_the_log(
    teams, identity_contacts, mailoutbox, caplog
):
    team_a, _ = teams
    with caplog.at_level("DEBUG"):
        for path in PATHS:
            path.run(team_a)
        identity_contacts.fault = requests.ConnectionError(
            f"{identity_stub.URL} refused {identity_stub.SECRET}"
        )
        notifications.notify_team(team_a.id, "s", "t")

    assert len(mailoutbox) == len(PATHS)
    assert "Notification sent" in caplog.text
    assert "@team-a.example" not in caplog.text
    assert identity_stub.SECRET not in caplog.text


def test_guardian_keeps_no_address_on_its_copy_of_a_user(teams):
    """Nothing here writes one: what is not kept cannot go stale."""
    from django.contrib.auth.models import User

    for path in PATHS:
        path.run(teams[0])

    assert set(User.objects.values_list("email", flat=True)) == {""}


# --- what an e-mail looks like -----------------------------------------------------------


@pytest.mark.django_db
def test_a_subject_is_one_line(teams, mailoutbox):
    """A title with a line break is not a second header."""
    team_a, _ = teams

    delivery = notifications.notify_team(
        team_a.id, "SLA Violation: a\r\nBcc: elsewhere@example.com  b", "t"
    )

    assert delivery.sent
    assert mailoutbox[0].subject == "SLA Violation: a Bcc: elsewhere@example.com b"
    assert mailoutbox[0].bcc == []


@pytest.mark.django_db
def test_an_e_mail_has_a_text_part_without_markup_and_an_html_part(teams, mailoutbox):
    team_a, _ = teams
    vulnerability = _quiet(
        tf.vulnerability,
        team_a.id,
        title="<b>SQL</b> injection & more",
        assigned_to=team_a.member,
    )
    _assign(vulnerability).get()

    (message,) = mailoutbox
    ((html, mimetype),) = message.alternatives
    assert mimetype == "text/html"
    assert "&lt;b&gt;SQL&lt;/b&gt; injection &amp; more" in html
    assert "<b>SQL</b> injection & more" in message.body
    assert "<p>" not in message.body and "<li>" not in message.body
    assert message.from_email == "guardian@test.invalid"
