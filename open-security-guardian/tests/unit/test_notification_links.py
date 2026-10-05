"""A link in an e-mail opens something that exists (#705).

The SLA and assignment e-mails linked
``<GUARDIAN_BASE_URL>/vulnerabilities/<id>/``. The dashboard has no page for
one vulnerability, so the link opened a 404; and with ``GUARDIAN_BASE_URL``
unset, which is how Compose started guardian, it was a relative path, which
in an e-mail opens nothing. The report e-mail named guardian's own API path,
which no client of the gateway can call.

A link is now built for a page the dashboard serves, from the address users
open the dashboard at, or not at all. The dashboard's routes are read from
its source tree, so a page that is renamed or removed fails here.
"""

import pathlib
import re
import uuid
from datetime import timedelta
from unittest import mock

import pytest
from apps.core import notifications
from django.urls import resolve
from django.utils import timezone

from tests.unit import team_fixtures as tf

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
DASHBOARD_APP = REPO_ROOT / "open-security-dashboard" / "src" / "app"
GATEWAY_CONF = (
    REPO_ROOT / "open-security-gateway" / "nginx" / "conf.d" / "wildbox_gateway.conf"
)
PUBLIC = "https://wildbox.example.com"
URL = re.compile(r"https?://[^\s<>\"']+")


@pytest.fixture(autouse=True)
def cache(settings):
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }


@pytest.fixture
def team(identity_contacts, db):
    team_id = uuid.uuid4()
    identity_contacts.member(team_id, "owner@team-a.example", role="owner")
    return team_id


def _quiet(make, *args, **kwargs):
    patches = tf._quiet()
    try:
        return make(*args, **kwargs)
    finally:
        tf._stop(patches)


def _everything(message):
    return "\n".join(
        [message.subject, message.body]
        + [content for content, _type in message.alternatives]
    )


def _vulnerability_mails(team, identity_contacts):
    """The SLA e-mail and the assignment e-mail of one vulnerability."""
    from apps.vulnerabilities.tasks import (
        check_sla_violations,
        notify_vulnerability_assignment,
    )

    member = identity_contacts.member(team, "dev@team-a.example")
    vulnerability = _quiet(
        tf.vulnerability,
        team,
        assigned_to=member,
        due_date=timezone.now() - timedelta(hours=5),
    )
    check_sla_violations.apply().get()
    notify_vulnerability_assignment.apply(args=[str(vulnerability.pk), None]).get()
    return vulnerability


def _report_mail(team):
    from apps.reporting.models import Report
    from apps.reporting.tasks import notify_scheduled_report

    schedule = tf.report_schedule(team)
    report = Report.objects.create(
        template=schedule.template, schedule=schedule, name="weekly", format="json"
    )
    assert notify_scheduled_report(report) is True
    return report


# --- the dashboard's pages ---------------------------------------------------------------


def test_there_are_dashboard_routes_to_check():
    assert notifications.DASHBOARD_ROUTES == {"vulnerabilities": "/vulnerabilities"}
    assert DASHBOARD_APP.is_dir()


@pytest.mark.parametrize("kind,route", sorted(notifications.DASHBOARD_ROUTES.items()))
def test_every_route_an_e_mail_links_to_is_a_page_of_the_dashboard(kind, route):
    page = DASHBOARD_APP / route.strip("/") / "page.tsx"

    assert page.is_file(), f"the dashboard serves no {route} ({kind})"
    # A plain path: a parameter would need a value guardian does not have.
    assert re.fullmatch(r"(/[a-z0-9-]+)+", route)


def test_the_dashboard_has_no_page_for_one_vulnerability():
    """Why the e-mails link the list: if this changes, link the row."""
    pages = sorted(
        str(page.parent.relative_to(DASHBOARD_APP))
        for page in (DASHBOARD_APP / "vulnerabilities").rglob("page.tsx")
    )

    assert pages == ["vulnerabilities"]


@pytest.mark.parametrize("kind", ["alerts", "reports", "compliance", "", None, "../x"])
def test_a_kind_without_a_page_gets_no_link(kind, settings):
    settings.BASE_URL = PUBLIC

    assert notifications.dashboard_link(kind) is None


def test_a_link_starts_with_the_public_address(settings):
    settings.BASE_URL = PUBLIC
    assert (
        notifications.dashboard_link("vulnerabilities") == f"{PUBLIC}/vulnerabilities"
    )

    settings.BASE_URL = ""
    assert notifications.dashboard_link("vulnerabilities") is None


# --- the e-mails ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_vulnerability_e_mails_link_the_page_the_dashboard_has(
    team, identity_contacts, settings, mailoutbox
):
    settings.BASE_URL = PUBLIC

    vulnerability = _vulnerability_mails(team, identity_contacts)

    assert len(mailoutbox) == 2
    for message in mailoutbox:
        assert set(URL.findall(_everything(message))) == {f"{PUBLIC}/vulnerabilities"}
        assert f'<a href="{PUBLIC}/vulnerabilities">' in message.alternatives[0][0]
        # Not the page that does not exist.
        assert f"/vulnerabilities/{vulnerability.id}" not in _everything(message)
        assert str(vulnerability.id) not in _everything(message)


@pytest.mark.django_db
def test_without_a_public_address_the_e_mails_carry_no_link(
    team, identity_contacts, settings, mailoutbox
):
    """Not a relative path, which opens nothing from an e-mail."""
    settings.BASE_URL = ""

    _vulnerability_mails(team, identity_contacts)
    _report_mail(team)

    assert len(mailoutbox) == 3
    for message in mailoutbox:
        text = _everything(message)
        assert URL.findall(text) == []
        assert "href" not in text
        assert "/vulnerabilities" not in text
        assert "dashboard" not in text


@pytest.mark.django_db
@pytest.mark.parametrize("base", ["", PUBLIC])
def test_the_report_e_mail_names_the_route_a_client_of_the_gateway_calls(
    base, team, settings, mailoutbox
):
    settings.BASE_URL = base

    report = _report_mail(team)

    (message,) = mailoutbox
    path = f"/api/v1/guardian/reports/reports/{report.pk}/download/"
    assert f"GET {base}{path}" in message.body
    # guardian's own path, the one it gave, is not in it.
    assert "GET /api/v1/reports/" not in message.body
    assert set(URL.findall(_everything(message))) == (
        {f"{base}{path}"} if base else set()
    )


@pytest.mark.django_db
def test_the_route_the_report_e_mail_names_is_one_guardian_serves(team, mailoutbox):
    report = _report_mail(team)

    named = re.search(r"GET (\S+)", mailoutbox[0].body).group(1)
    assert named.startswith(notifications.GATEWAY_API_PREFIX + "/")
    inside = "/api/v1" + named[len(notifications.GATEWAY_API_PREFIX) :]
    match = resolve(inside)
    assert match.kwargs == {"pk": str(report.pk)}
    assert match.func.actions["get"] == "download"


def test_the_gateway_serves_guardian_under_that_prefix():
    conf = GATEWAY_CONF.read_text()

    assert f"location {notifications.GATEWAY_API_PREFIX}/ " in conf
    assert (
        notifications.gateway_api_path("/api/v1/reports/reports/1/download/")
        == "/api/v1/guardian/reports/reports/1/download/"
    )
    with pytest.raises(ValueError):
        notifications.gateway_api_path("/internal/team-memberships/revoke/")


@pytest.mark.django_db
@pytest.mark.parametrize("configured", [True, False])
def test_no_other_e_mail_carries_a_link(
    configured, team, identity_contacts, settings, mailoutbox
):
    """Alert rules and compliance have no page in the dashboard."""
    from apps.compliance.tasks import send_compliance_notification
    from apps.reporting import tasks

    settings.BASE_URL = PUBLIC if configured else ""
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        rule = tf.alert_rule(team, operator="gte")
    tasks.check_alert_rule(rule.pk)
    rows = {
        "high_risk_finding": _quiet(tf.result, team),
        "assessment_started": _quiet(tf.assessment, team),
        "assessment_completed": _quiet(tf.assessment, team),
        "assessment_overdue": _quiet(tf.assessment, team),
        "exception_expiring": _quiet(tf.exception, team),
    }
    for kind, row in rows.items():
        assert send_compliance_notification(kind, str(row.pk), {}) is True

    assert len(mailoutbox) == 6
    for message in mailoutbox:
        assert URL.findall(_everything(message)) == []
        assert "href" not in _everything(message)
