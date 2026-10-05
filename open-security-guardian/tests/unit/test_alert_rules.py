"""Alert rules evaluate guardian's data and do not repeat themselves (#549).

get_current_value_for_rule returned 0 for every rule, so no rule ever
measured anything, and a firing rule notified on every sweep: 96 e-mails a
day at the default 15 minutes. These tests cover each metric against seeded
data, the rules the API refuses, and the notification state machine: one
notification when a rule starts firing, none while it keeps firing until the
re-notification interval has passed, one when it recovers.
"""

import uuid
from datetime import timedelta
from unittest import mock

import pytest
from apps.reporting import tasks
from apps.reporting.alert_metrics import UnsupportedAlertRule, current_value
from apps.reporting.models import AlertNotification, AlertRule
from django.core.exceptions import ImproperlyConfigured
from django.test import Client
from django.utils import timezone
from guardian.schedule import alert_renotify_interval

_GW_SECRET = "test-gateway-secret"
# Every row these tests seed belongs to this team, and every request is
# made as a member of it: guardian answers 404 for another team's rows (#642).
TEAM_ID = str(uuid.uuid4())
DAY = timedelta(days=1)


@pytest.fixture
def locmem_cache(settings):
    # The lock and the throttles use the default cache, Redis outside tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }


@pytest.fixture
def client(locmem_cache, monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    return Client(raise_request_exception=False)


def _headers(role="admin"):
    return {
        "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_TEAM_ID": TEAM_ID,
        "HTTP_X_WILDBOX_ROLE": role,
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        "HTTP_X_WILDBOX_AUTH_TYPE": "session",
    }


# --- seeded data -----------------------------------------------------------


def _asset(name="host"):
    from apps.assets.models import Asset

    with mock.patch("apps.assets.signals.scan_asset_ports"):
        return Asset.objects.create(name=name, team_id=TEAM_ID)


def _vulnerability(asset, **fields):
    from apps.vulnerabilities.models import Vulnerability

    fields.setdefault("title", f"finding-{uuid.uuid4().hex[:6]}")
    fields.setdefault("description", "d")
    with mock.patch(
        "apps.vulnerabilities.signals.enrich_vulnerability_with_threat_intel"
    ):
        vulnerability = Vulnerability.objects.create(asset=asset, **fields)
    # save() recalculates the risk score; set it as the test means it.
    if "risk_score" in fields:
        Vulnerability.objects.filter(pk=vulnerability.pk).update(
            risk_score=fields["risk_score"]
        )
    if "due_date" in fields:
        Vulnerability.objects.filter(pk=vulnerability.pk).update(
            due_date=fields["due_date"]
        )
    return vulnerability


def _rule(data_source="vulnerabilities.unresolved", **fields):
    fields.setdefault("name", f"rule-{uuid.uuid4().hex[:8]}")
    fields.setdefault("condition_type", "threshold")
    fields.setdefault("operator", "gt")
    fields.setdefault("threshold_value", 0)
    fields.setdefault("team_id", TEAM_ID)
    # Without the test-mode check its creation queues (signals.py).
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        return AlertRule.objects.create(data_source=data_source, **fields)


def _value(data_source, **config):
    return current_value(_rule(data_source, condition_config=config))


# --- each metric is a query over guardian's data ---------------------------


@pytest.mark.django_db
def test_unresolved_vulnerabilities():
    asset, other = _asset("a"), _asset("b")
    _vulnerability(asset, severity="critical", status="open")
    _vulnerability(asset, severity="high", status="in_progress")
    _vulnerability(asset, severity="critical", status="resolved")
    _vulnerability(asset, severity="low", status="false_positive")
    _vulnerability(other, severity="critical", status="open")

    assert _value("vulnerabilities.unresolved") == 3
    assert _value("vulnerabilities.unresolved", severity=["critical"]) == 2
    assert _value("vulnerabilities.unresolved", asset=str(asset.pk)) == 2
    assert (
        _value("vulnerabilities.unresolved", severity=["critical"], asset=str(asset.pk))
        == 1
    )


@pytest.mark.django_db
def test_overdue_vulnerabilities_are_the_sla_checks():
    asset = _asset()
    now = timezone.now()
    _vulnerability(asset, status="open", due_date=now - timedelta(hours=1))
    _vulnerability(asset, status="open", due_date=now + timedelta(hours=1))
    _vulnerability(asset, status="resolved", due_date=now - timedelta(hours=1))
    _vulnerability(
        asset, status="open", severity="low", due_date=now - timedelta(days=3)
    )

    assert _value("vulnerabilities.overdue") == 2
    assert _value("vulnerabilities.overdue", severity=["low"]) == 1


@pytest.mark.django_db
def test_max_risk_score():
    assert _value("vulnerabilities.max_risk_score") == 0.0
    asset = _asset()
    _vulnerability(asset, status="open", risk_score=6.5)
    _vulnerability(asset, status="in_progress", risk_score=8.25)
    _vulnerability(asset, status="resolved", risk_score=9.9)
    assert _value("vulnerabilities.max_risk_score") == 8.25


@pytest.mark.django_db
def test_compliance_metrics():
    from apps.compliance.models import (
        ComplianceAssessment,
        ComplianceControl,
        ComplianceFramework,
        ComplianceResult,
    )

    now = timezone.now()
    with mock.patch("apps.compliance.signals.send_compliance_notification"), mock.patch(
        "apps.compliance.signals.calculate_compliance_metrics"
    ):
        framework = ComplianceFramework.objects.create(name="ISO27001")
        late = ComplianceAssessment.objects.create(
            team_id=TEAM_ID,
            name="late",
            framework=framework,
            assessment_type="self_assessment",
            due_date=now - DAY,
        )
        ComplianceAssessment.objects.create(
            team_id=TEAM_ID,
            name="done",
            framework=framework,
            assessment_type="self_assessment",
            status="completed",
            due_date=now - DAY,
        )
        for number, (status, risk) in enumerate(
            [("non_compliant", "high"), ("non_compliant", "low"), ("compliant", "high")]
        ):
            control = ComplianceControl.objects.create(
                framework=framework,
                control_id=f"A.5.{number}",
                title="c",
                control_type="preventive",
            )
            ComplianceResult.objects.create(
                assessment=late, control=control, status=status, risk_level=risk
            )

    assert _value("compliance.non_compliant_results") == 2
    assert _value("compliance.non_compliant_results", risk_level=["high"]) == 1
    assert _value("compliance.overdue_assessments") == 1


@pytest.mark.django_db
@pytest.mark.parametrize(
    "fields",
    [
        {"data_source": "integration-test"},
        {"data_source": "vulnerabilities"},
        {"condition_type": "trend"},
        {"condition_type": "anomaly"},
        {"operator": ""},
        {"threshold_value": None},
        {"condition_config": {"severity": ["catastrophic"]}},
        {"condition_config": {"asset": "not-an-id"}},
        {"condition_config": {"owner": "me"}},
        {"condition_config": ["severity"]},
    ],
)
def test_a_rule_guardian_cannot_evaluate_is_an_error_not_zero(fields):
    data_source = fields.pop("data_source", "vulnerabilities.unresolved")
    rule = _rule(data_source, **fields)
    with pytest.raises(UnsupportedAlertRule):
        current_value(rule)


# --- the state machine: notify on changes, not on every evaluation ---------


@pytest.fixture
def renotify(settings):
    settings.ALERT_RENOTIFY_INTERVAL = DAY
    return settings


def _notifications(rule):
    return list(
        AlertNotification.objects.filter(rule=rule)
        .order_by("created_at")
        .values_list("kind", flat=True)
    )


@pytest.mark.django_db
def test_a_rule_that_does_not_fire_records_its_value_and_stays_quiet(renotify):
    rule = _rule(operator="gt", threshold_value=0)

    result = tasks.check_alert_rule(rule.pk)

    assert result["triggered"] is False
    assert result["current_value"] == 0
    assert result["notification"] is None
    rule.refresh_from_db()
    assert rule.state == "ok"
    assert rule.last_value == 0
    assert rule.last_evaluated_at is not None
    assert rule.trigger_count == 0
    assert _notifications(rule) == []


@pytest.mark.django_db
def test_a_rule_fires_on_real_data(renotify):
    # With the placeholder every rule saw 0 and "> 0" could never fire.
    asset = _asset()
    rule = _rule(condition_config={"asset": str(asset.pk)})
    _vulnerability(asset, severity="critical")

    result = tasks.check_alert_rule(rule.pk)

    assert result["triggered"] is True
    assert result["current_value"] == 1
    assert result["notification"] == "firing"
    rule.refresh_from_db()
    assert rule.state == "firing"
    assert rule.trigger_count == 1
    assert rule.firing_since == rule.last_triggered == rule.last_notified_at


@pytest.mark.django_db
def test_still_firing_does_not_notify_again_within_the_interval(renotify):
    rule = _rule(operator="eq", threshold_value=0)
    start = timezone.now()

    first = tasks.record_alert_evaluation(rule.pk, 0.0, True, now=start)
    second = tasks.record_alert_evaluation(
        rule.pk, 0.0, True, now=start + timedelta(minutes=15)
    )
    later = tasks.record_alert_evaluation(rule.pk, 0.0, True, now=start + DAY / 2)

    assert first.kind == "firing"
    assert second is None
    assert later is None
    assert _notifications(rule) == ["firing"]
    rule.refresh_from_db()
    assert rule.trigger_count == 1
    assert rule.last_evaluated_at == start + DAY / 2
    assert rule.last_notified_at == start


@pytest.mark.django_db
def test_still_firing_notifies_once_per_interval(renotify):
    rule = _rule()
    start = timezone.now()
    tasks.record_alert_evaluation(rule.pk, 1.0, True, now=start)

    repeat = tasks.record_alert_evaluation(rule.pk, 2.0, True, now=start + DAY)
    soon_after = tasks.record_alert_evaluation(
        rule.pk, 2.0, True, now=start + DAY + timedelta(minutes=15)
    )

    assert repeat.kind == "repeat"
    assert repeat.value == 2.0
    assert soon_after is None
    assert _notifications(rule) == ["firing", "repeat"]
    rule.refresh_from_db()
    # Still the same firing episode.
    assert rule.trigger_count == 1
    assert rule.firing_since == start


@pytest.mark.django_db
def test_with_reminders_off_a_firing_rule_notifies_once(settings):
    settings.ALERT_RENOTIFY_INTERVAL = None
    rule = _rule()
    start = timezone.now()
    for days in range(0, 30):
        tasks.record_alert_evaluation(rule.pk, 1.0, True, now=start + days * DAY)
    assert _notifications(rule) == ["firing"]


@pytest.mark.django_db
def test_recovery_notifies_once_and_a_new_episode_fires_again(renotify):
    rule = _rule()
    start = timezone.now()
    minute = timedelta(minutes=1)

    tasks.record_alert_evaluation(rule.pk, 3.0, True, now=start)
    resolved = tasks.record_alert_evaluation(rule.pk, 0.0, False, now=start + minute)
    quiet = tasks.record_alert_evaluation(rule.pk, 0.0, False, now=start + 2 * minute)
    again = tasks.record_alert_evaluation(rule.pk, 1.0, True, now=start + 3 * minute)

    assert resolved.kind == "resolved"
    assert resolved.value == 0.0
    assert quiet is None
    assert again.kind == "firing"
    assert _notifications(rule) == ["firing", "resolved", "firing"]
    rule.refresh_from_db()
    assert rule.trigger_count == 2
    assert rule.firing_since == start + 3 * minute


@pytest.mark.django_db
def test_test_mode_changes_nothing(renotify):
    rule = _rule(operator="eq", threshold_value=0)
    result = tasks.check_alert_rule(rule.pk, test_mode=True)
    assert result["triggered"] is True
    rule.refresh_from_db()
    assert (rule.state, rule.trigger_count, rule.last_evaluated_at) == ("ok", 0, None)
    assert _notifications(rule) == []


@pytest.mark.django_db
def test_a_rule_that_cannot_be_evaluated_reports_an_error(renotify):
    # Accepted before #549 and evaluated against 0; now an error, and no
    # notification however it compares with 0.
    rule = _rule("integration-test", operator="eq", threshold_value=0)
    result = tasks.check_alert_rule(rule.pk)
    assert result["triggered"] is False
    assert "unknown metric" in str(result["error"])
    rule.refresh_from_db()
    assert rule.last_evaluated_at is None
    assert _notifications(rule) == []


@pytest.mark.django_db
def test_the_sweep_does_not_repeat_a_firing_rule(renotify, locmem_cache):
    from apps.reporting.tasks import check_all_alert_rules

    rule = _rule(operator="eq", threshold_value=0)
    for _ in range(4):
        assert check_all_alert_rules.apply().successful()
    assert _notifications(rule) == ["firing"]
    rule.refresh_from_db()
    assert rule.trigger_count == 1


# --- delivery --------------------------------------------------------------


@pytest.mark.django_db
def test_a_notification_is_e_mailed_to_the_rule_recipients(renotify, mailoutbox):
    asset = _asset()
    rule = _rule(
        condition_config={"asset": str(asset.pk)},
        notification_config={"recipients": ["soc@example.com"]},
    )
    _vulnerability(asset)
    tasks.check_alert_rule(rule.pk)

    assert len(mailoutbox) == 1
    assert mailoutbox[0].to == ["soc@example.com"]
    assert mailoutbox[0].subject == f"Alert: {rule.name}"
    assert "started firing" in mailoutbox[0].body
    notification = AlertNotification.objects.get(rule=rule)
    assert notification.delivered is True
    assert notification.recipients == ["soc@example.com"]

    from apps.vulnerabilities.models import Vulnerability

    Vulnerability.objects.filter(asset=asset).update(status="resolved")
    tasks.check_alert_rule(rule.pk)
    assert len(mailoutbox) == 2
    assert mailoutbox[1].subject == f"Resolved: {rule.name}"
    assert "no longer firing" in mailoutbox[1].body


@pytest.mark.django_db
def test_without_recipients_the_notification_is_recorded_undelivered(
    renotify, mailoutbox, caplog
):
    rule = _rule(operator="eq", threshold_value=0)
    with caplog.at_level("WARNING", logger="apps.reporting.tasks"):
        tasks.check_alert_rule(rule.pk)
    assert mailoutbox == []
    notification = AlertNotification.objects.get(rule=rule)
    assert (notification.kind, notification.delivered) == ("firing", False)
    assert notification.recipients == []
    # The rule names nobody and guardian cannot ask identity for its team's
    # owners and admins here: the record and the log say why (#705).
    assert notification.failure_reason == (
        "guardian is not set up to ask identity for addresses "
        "(GUARDIAN_CONTACTS_SECRET)"
    )
    assert f"notification not sent ({notification.failure_reason})" in caplog.text


@pytest.mark.django_db
def test_a_rule_without_recipients_has_no_platform_wide_fallback(
    renotify, mailoutbox, settings
):
    # This asserted the opposite: that DEFAULT_NOTIFICATION_RECIPIENTS, one
    # list for every team, received the alerts of a rule that names nobody
    # (#678).
    settings.DEFAULT_NOTIFICATION_RECIPIENTS = ["secops@example.com"]
    rule = _rule(operator="eq", threshold_value=0)
    tasks.check_alert_rule(rule.pk)
    assert mailoutbox == []
    notification = AlertNotification.objects.get(rule=rule)
    assert (notification.recipients, notification.delivered) == ([], False)


# --- the re-notification interval setting ----------------------------------


def test_the_renotify_interval_defaults_to_a_day(settings):
    assert alert_renotify_interval({}) == DAY
    assert alert_renotify_interval({"GUARDIAN_ALERT_RENOTIFY_INTERVAL": ""}) == DAY
    assert alert_renotify_interval(
        {"GUARDIAN_ALERT_RENOTIFY_INTERVAL": "3600"}
    ) == timedelta(hours=1)
    assert alert_renotify_interval({"GUARDIAN_ALERT_RENOTIFY_INTERVAL": "off"}) is None


@pytest.mark.parametrize("value", ["0", "-60", "1h", "15 * * * *"])
def test_an_invalid_renotify_interval_stops_start_up(value):
    with pytest.raises(ImproperlyConfigured):
        alert_renotify_interval({"GUARDIAN_ALERT_RENOTIFY_INTERVAL": value})


# --- the API -----------------------------------------------------------------

ALERTS = "/api/v1/reports/alerts/"


def _post(client, payload):
    return client.post(
        ALERTS,
        data=payload,
        content_type="application/json",
        secure=True,
        **_headers(),
    )


def _payload(**fields):
    payload = {
        "name": f"rule-{uuid.uuid4().hex[:8]}",
        "data_source": "vulnerabilities.unresolved",
        "condition_type": "threshold",
        "operator": "gt",
        "threshold_value": 0,
        "condition_config": {"severity": ["critical", "high"]},
        "notification_config": {"recipients": ["soc@example.com"]},
    }
    payload.update(fields)
    return payload


@pytest.mark.django_db
def test_a_supported_rule_is_created(client):
    with mock.patch("apps.reporting.signals.check_alert_rule"):
        response = _post(client, _payload(state="firing", trigger_count=7))
    assert response.status_code == 201, response.content[:500]
    body = response.json()
    # The evaluation state is read-only.
    assert body["state"] == "ok"
    assert body["trigger_count"] == 0
    assert body["last_evaluated_at"] is None


@pytest.mark.django_db
@pytest.mark.parametrize(
    "fields,field",
    [
        ({"data_source": "integration-test"}, "data_source"),
        ({"condition_type": "change"}, "condition_type"),
        ({"operator": ""}, "operator"),
        ({"threshold_value": None}, "threshold_value"),
        ({"condition_config": {"severity": ["catastrophic"]}}, "condition_config"),
        ({"condition_config": {"risk_level": ["high"]}}, "condition_config"),
        ({"condition_config": {"asset": "x"}}, "condition_config"),
        ({"notification_config": {"recipients": ["nobody"]}}, "notification_config"),
        ({"notification_config": {"recipients": "a@b.c"}}, "notification_config"),
    ],
)
def test_a_rule_that_cannot_be_evaluated_is_refused(client, fields, field):
    response = _post(client, _payload(**fields))
    assert response.status_code == 400, response.content[:500]
    assert field in response.json(), response.json()


@pytest.mark.django_db
def test_a_change_that_breaks_a_rule_is_refused(client):
    rule = _rule()
    response = client.patch(
        f"{ALERTS}{rule.pk}/",
        data={"data_source": "assets"},
        content_type="application/json",
        secure=True,
        **_headers(),
    )
    assert response.status_code == 400, response.content[:500]
    assert "data_source" in response.json()


@pytest.mark.django_db
def test_test_reports_the_real_value(client):
    asset = _asset()
    _vulnerability(asset)
    _vulnerability(asset)
    rule = _rule(condition_config={"asset": str(asset.pk)})
    response = client.post(f"{ALERTS}{rule.pk}/test/", secure=True, **_headers())
    assert response.status_code == 200, response.content[:500]
    assert response.json()["current_value"] == 2
    assert response.json()["rule_triggered"] is True


@pytest.mark.django_db
def test_the_notifications_are_listed_newest_first(client, renotify):
    rule = _rule()
    start = timezone.now()
    tasks.record_alert_evaluation(rule.pk, 1.0, True, now=start)
    tasks.record_alert_evaluation(rule.pk, 0.0, False, now=start + DAY)

    response = client.get(
        f"{ALERTS}{rule.pk}/notifications/", secure=True, **_headers(role="member")
    )
    assert response.status_code == 200, response.content[:500]
    body = response.json()
    assert body["count"] == 2
    assert [n["kind"] for n in body["results"]] == ["resolved", "firing"]
    assert body["results"][1]["value"] == 1.0
    assert body["results"][1]["operator"] == "gt"
