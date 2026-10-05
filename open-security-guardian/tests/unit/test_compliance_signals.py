"""Regression tests for the compliance signals (#555).

The post_save receivers of ComplianceResult and ComplianceAssessment asked
``instance.tracker.has_changed('status')``, a django-model-utils FieldTracker
that neither model declares (the package is not even installed). Saving an
existing result or assessment raised AttributeError, so every update through
the API answered 500, and the work the receivers were meant to start on a
status change -- recalculating the assessment's metrics, the high-risk and
completion notifications -- never ran.

The tasks run eagerly here, for real: the metrics row and the notifications
are what is asserted, not the calls that should produce them. The tests
commit (transaction=True), because the receivers queue their tasks on commit.

A compliance notification has no recipients of its own, and no platform-wide
list receives it any more (#678): it is rendered, not sent, and logged. These
tests asserted an e-mail to DEFAULT_NOTIFICATION_RECIPIENTS; they now assert
that the notification is attempted, that nothing is e-mailed, and, by sending
the same notification to a named recipient, that it renders.
"""

import uuid
from datetime import timedelta

import pytest
from apps.compliance import tasks as compliance_tasks
from apps.core.utils import send_notification
from apps.compliance.models import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceException,
    ComplianceFramework,
    ComplianceMetrics,
    ComplianceResult,
)
from django.db import transaction
from django.test import Client
from django.utils import timezone
from guardian.celery import app as celery_app

_GW_SECRET = "test-gateway-secret"
# Every row these tests seed belongs to this team, and every request is
# made as a member of it: guardian answers 404 for another team's rows (#642).
TEAM_ID = str(uuid.uuid4())
_BASE = "/api/v1/compliance/"
RECIPIENT = "compliance@example.com"


@pytest.fixture
def eager(settings, monkeypatch):
    """Run queued tasks in-process.

    A platform-wide list is defined, as an operator who found the old
    setting's name might: it must receive nothing.
    """
    monkeypatch.setattr(celery_app.conf, "task_always_eager", True)
    monkeypatch.setattr(celery_app.conf, "task_eager_propagates", True)
    settings.DEFAULT_NOTIFICATION_RECIPIENTS = ["platform@example.com"]


@pytest.fixture
def attempts(eager, monkeypatch, mailoutbox):
    """Every notification the compliance tasks tried to send, with its outcome."""
    seen = []

    def recording(**kwargs):
        sent = send_notification(**kwargs)
        seen.append({**kwargs, "sent": sent})
        return sent

    monkeypatch.setattr(compliance_tasks, "send_notification", recording)
    return seen


def _subjects(attempts):
    return [attempt["subject"] for attempt in attempts]


def _rendered(attempt, mailoutbox):
    """The e-mail a notification is, once somebody is named to receive it."""
    assert attempt["sent"] is False
    assert mailoutbox == [], "a compliance notification has no recipients (#678)"
    assert send_notification(
        subject=attempt["subject"],
        template=attempt["template"],
        context=attempt["context"],
        recipients=[RECIPIENT],
    )
    (message,) = mailoutbox
    mailoutbox.clear()
    assert message.to == [RECIPIENT]
    return message


@pytest.fixture
def api(settings, monkeypatch, attempts):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client()
    headers = {
        "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_TEAM_ID": TEAM_ID,
        "HTTP_X_WILDBOX_ROLE": "admin",
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        "HTTP_X_WILDBOX_AUTH_TYPE": "session",
    }

    def call(method, url, data):
        return getattr(client, method)(
            url, data=data, content_type="application/json", secure=True, **headers
        )

    return call


def _assessment(status="planned"):
    framework = ComplianceFramework.objects.create(name=f"fw-{uuid.uuid4().hex[:8]}")
    return ComplianceAssessment.objects.create(
        team_id=TEAM_ID,
        name="Q3 audit",
        framework=framework,
        assessment_type="internal_audit",
        status=status,
    )


def _result(assessment, status="compliant", risk_level="low", number=1):
    control = ComplianceControl.objects.create(
        framework=assessment.framework,
        control_id=f"A.5.{number}",
        title="Access control",
        description="d",
        control_type="technical",
    )
    return ComplianceResult.objects.create(
        assessment=assessment, control=control, status=status, risk_level=risk_level
    )


def _metrics(assessment):
    return ComplianceMetrics.objects.get(assessment=assessment)


# --- ComplianceResult -------------------------------------------------------


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("method", ["patch", "put"])
def test_updating_a_result_through_the_api_recalculates_the_metrics(
    api, attempts, mailoutbox, method
):
    assessment = _assessment(status="in_progress")
    result = _result(assessment, status="compliant", risk_level="low")
    _result(assessment, status="compliant", risk_level="low", number=2)
    assert _metrics(assessment).compliant_controls == 2
    attempts.clear()

    data = {"status": "non_compliant", "risk_level": "critical"}
    if method == "put":
        data.update(assessment=str(assessment.pk), control=str(result.control_id))
    response = api(method, f"{_BASE}results/{result.pk}/", data)

    assert response.status_code == 200, response.content[:500]
    assert response.json()["status"] == "non_compliant"
    metrics = _metrics(assessment)
    assert metrics.compliant_controls == 1
    assert metrics.non_compliant_controls == 1
    assert metrics.high_risk_findings == 1
    assert float(metrics.compliance_percentage) == 50.0
    (attempt,) = attempts
    message = _rendered(attempt, mailoutbox)
    assert message.subject == "High Risk Compliance Finding"
    assert "A.5.1" in message.body and "critical" in message.body


@pytest.mark.django_db(transaction=True)
def test_saving_a_result_through_the_orm_does_not_raise(eager):
    assessment = _assessment()
    result = _result(assessment, status="not_tested", risk_level=None)

    result.status = "compliant"
    result.save()

    assert _metrics(assessment).compliant_controls == 1


@pytest.mark.django_db(transaction=True)
def test_a_risk_level_change_alone_recalculates_and_notifies(attempts, mailoutbox):
    assessment = _assessment()
    result = _result(assessment, status="non_compliant", risk_level="low")
    assert _metrics(assessment).high_risk_findings == 0
    assert attempts == []

    result.risk_level = "high"
    result.save()

    assert _metrics(assessment).high_risk_findings == 1
    assert _subjects(attempts) == ["High Risk Compliance Finding"]
    assert mailoutbox == []


@pytest.mark.django_db(transaction=True)
def test_an_unrelated_change_starts_nothing(attempts):
    assessment = _assessment()
    result = _result(assessment, status="non_compliant", risk_level="critical")
    ComplianceMetrics.objects.all().delete()
    attempts.clear()

    result.findings = "Shared admin account on the bastion."
    result.save()

    assert not ComplianceMetrics.objects.exists()
    assert attempts == []


@pytest.mark.django_db(transaction=True)
def test_a_save_with_unchanged_update_fields_starts_nothing(eager):
    assessment = _assessment()
    result = _result(assessment, status="compliant", risk_level="low")
    ComplianceMetrics.objects.all().delete()

    # status differs in memory but is not written, so nothing changed.
    result.status = "non_compliant"
    result.findings = "noted"
    result.save(update_fields=["findings"])

    assert not ComplianceMetrics.objects.exists()


@pytest.mark.django_db(transaction=True)
def test_creating_a_high_risk_result_notifies(attempts, mailoutbox):
    assessment = _assessment()

    _result(assessment, status="partially_compliant", risk_level="high")

    assert _metrics(assessment).partially_compliant_controls == 1
    assert _subjects(attempts) == ["High Risk Compliance Finding"]
    assert mailoutbox == []


@pytest.mark.django_db(transaction=True)
def test_the_metrics_wait_for_the_commit(eager):
    assessment = _assessment()
    result = _result(assessment, status="compliant")
    ComplianceMetrics.objects.all().delete()

    with transaction.atomic():
        result.status = "non_compliant"
        result.save()
        # Queued on commit, so a worker reads the saved status, not the
        # stored one it would see before the commit.
        assert not ComplianceMetrics.objects.exists()

    assert _metrics(assessment).non_compliant_controls == 1


# --- ComplianceAssessment ---------------------------------------------------


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("method", ["patch", "put"])
def test_completing_an_assessment_through_the_api_notifies(
    api, attempts, mailoutbox, method
):
    assessment = _assessment(status="in_progress")
    _result(assessment, status="compliant")
    ComplianceMetrics.objects.all().delete()
    attempts.clear()

    data = {"status": "completed"}
    if method == "put":
        data.update(
            name=assessment.name,
            framework=str(assessment.framework_id),
            assessment_type=assessment.assessment_type,
        )
    response = api(method, f"{_BASE}assessments/{assessment.pk}/", data)

    assert response.status_code == 200, response.content[:500]
    assert response.json()["status"] == "completed"
    assert _metrics(assessment).compliant_controls == 1
    (attempt,) = attempts
    message = _rendered(attempt, mailoutbox)
    assert message.subject == "Compliance Assessment Completed"
    assert "Q3 audit" in message.body


@pytest.mark.django_db(transaction=True)
def test_saving_an_assessment_through_the_orm_does_not_raise(attempts):
    assessment = _assessment()

    assessment.description = "scope agreed"
    assessment.save()

    assert attempts == []


@pytest.mark.django_db(transaction=True)
def test_starting_an_assessment_notifies(attempts, mailoutbox):
    assessment = _assessment(status="planned")

    assessment.status = "in_progress"
    assessment.save()

    assert _subjects(attempts) == ["Compliance Assessment Started"]
    assert "Q3 audit" in _rendered(attempts[0], mailoutbox).body


@pytest.mark.django_db(transaction=True)
def test_creating_an_assessment_in_progress_notifies(attempts):
    _assessment(status="in_progress")

    assert _subjects(attempts) == ["Compliance Assessment Started"]


@pytest.mark.django_db(transaction=True)
def test_saving_a_completed_assessment_again_does_not_renotify(attempts):
    assessment = _assessment(status="in_progress")
    assessment.status = "completed"
    assessment.save()
    attempts.clear()

    assessment.description = "report filed"
    assessment.save()

    assert attempts == []


# --- the notifications' templates -------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_the_scheduled_reminders_render(attempts, settings, mailoutbox):
    # The e-mail templates did not exist, so every compliance notification,
    # these two sweeps' included, failed to render and was only logged.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    now = timezone.now()
    assessment = _assessment(status="planned")
    assessment.due_date = now - timedelta(days=3, hours=1)
    assessment.save()
    control = ComplianceControl.objects.create(
        framework=assessment.framework,
        control_id="A.8.2",
        title="c",
        description="d",
        control_type="preventive",
    )
    ComplianceException.objects.create(
        control=control,
        title="Legacy VPN waiver",
        justification="j",
        status="approved",
        valid_from=now - timedelta(days=300),
        valid_until=now + timedelta(days=10, hours=1),
    )
    attempts.clear()

    assert compliance_tasks.check_overdue_assessments.apply().get() == 1
    assert compliance_tasks.check_expiring_exceptions.apply().get() == 1

    overdue, expiring = [_rendered(attempt, mailoutbox) for attempt in attempts]
    assert overdue.subject == "Compliance Assessment Overdue"
    assert "Q3 audit" in overdue.body and "3 days overdue" in overdue.body
    assert expiring.subject == "Compliance Exception Expiring Soon"
    assert "Legacy VPN waiver" in expiring.body and "A.8.2" in expiring.body
    assert "in 10 days" in expiring.body


# --- recipients ---------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_a_compliance_notification_is_not_sent_and_says_so(
    attempts, mailoutbox, caplog
):
    """No recipients of its own, and no platform-wide list (#678)."""
    assessment = _assessment()

    with caplog.at_level("WARNING", logger="apps.core.utils"):
        _result(assessment, status="non_compliant", risk_level="critical")

    assert [(a["subject"], a["sent"]) for a in attempts] == [
        ("High Risk Compliance Finding", False)
    ]
    assert mailoutbox == []
    assert (
        "Notification not sent, it has no recipients (compliance): "
        "High Risk Compliance Finding"
    ) in caplog.text
