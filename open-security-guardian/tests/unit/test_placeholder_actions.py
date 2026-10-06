"""The actions that reported work they had not done (#644).

Twenty of them answered ``200 {"status": "success", ...}``, or fixed
figures, without doing anything, and are gone: a route that cannot do what
it says is not served. The others now do it, and these tests look at what
they left behind, not at their answer: the assignee on the ticket, the copy
of the template, the workflow and its steps, the rows of the log that are
no longer there.

tests/unit/test_action_contracts.py keeps a new placeholder from being
added; this file is about the actions #644 found.
"""

import uuid
from datetime import timedelta
from unittest import mock

import pytest
from django.test import Client
from django.utils import timezone

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
INTEGRATIONS = "/api/v1/integrations"
REMEDIATION = "/api/v1/remediation"
SCANNERS = "/api/v1/scanners"
VULNERABILITIES = "/api/v1/vulnerabilities"


@pytest.fixture
def api(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)

    def call(method, url, team, data=None, role="admin", user_id=None):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": user_id or str(uuid.uuid4()),
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": role,
            "HTTP_X_WILDBOX_AUTH_TYPE": "session",
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        }
        if data is not None:
            kwargs.update(data=data, content_type="application/json")
        return getattr(client, method)(url, **kwargs)

    return call


@pytest.fixture
def team():
    return uuid.uuid4()


@pytest.fixture
def dispatched(monkeypatch):
    """The names of the Celery tasks dispatched, instead of a broker."""
    from celery.app.task import Task

    names = []

    def apply_async(self, *args, **kwargs):
        names.append(self.name)
        return mock.Mock(id=str(uuid.uuid4()))

    monkeypatch.setattr(Task, "apply_async", apply_async)
    return names


def _models():
    from apps.integrations import models as integrations
    from apps.remediation import models as remediation
    from apps.scanners import models as scanners

    return integrations, remediation, scanners


def _set(row, **fields):
    """Set fields without save(): no signal, no auto_now."""
    type(row)._base_manager.filter(pk=row.pk).update(**fields)
    row.refresh_from_db()
    return row


def _values(row):
    return type(row)._base_manager.filter(pk=row.pk).values().get()


# --- the placeholders are not served -----------------------------------------

# (method, URL prefix, the action's path, the model whose row the URL names
# or None for a list-level action, the answer). A detail action that is gone
# is 404. A list-level one now reads as the detail route of a row called
# like it: 404 for a GET, and 405 for the POST, which a detail route does
# not take.
REMOVED = [
    ("post", f"{INTEGRATIONS}/systems/", "test_connection", "ExternalSystem", 404),
    ("post", f"{INTEGRATIONS}/systems/", "health_check", "ExternalSystem", 404),
    ("get", f"{INTEGRATIONS}/systems/", "sync_status", "ExternalSystem", 404),
    ("post", f"{INTEGRATIONS}/mappings/", "test_mapping", "IntegrationMapping", 404),
    ("post", f"{INTEGRATIONS}/mappings/", "sync_now", "IntegrationMapping", 404),
    ("get", f"{INTEGRATIONS}/sync-records/", "sync_statistics", None, 404),
    ("post", f"{INTEGRATIONS}/sync-records/", "retry_sync", "SyncRecord", 404),
    ("post", f"{INTEGRATIONS}/webhooks/", "test_webhook", "WebhookEndpoint", 404),
    ("post", f"{INTEGRATIONS}/webhooks/", "trigger_webhook", "WebhookEndpoint", 404),
    ("get", f"{INTEGRATIONS}/logs/", "error_summary", None, 404),
    (
        "post",
        f"{INTEGRATIONS}/notifications/",
        "test_notification",
        "NotificationChannel",
        404,
    ),
    (
        "post",
        f"{INTEGRATIONS}/notifications/",
        "send_notification",
        "NotificationChannel",
        404,
    ),
    ("post", f"{SCANNERS}/scanners/", "test_connection", "Scanner", 404),
    ("post", f"{SCANNERS}/scans/", "start", "Scan", 404),
    ("post", f"{SCANNERS}/scans/", "stop", "Scan", 404),
    ("post", f"{SCANNERS}/scans/", "pause", "Scan", 404),
    ("post", f"{SCANNERS}/scans/", "resume", "Scan", 404),
    ("post", f"{SCANNERS}/scans/", "import_results", None, 405),
    ("post", f"{REMEDIATION}/tickets/", "sync_external", "RemediationTicket", 404),
    ("post", f"{REMEDIATION}/workflows/", "pause", "RemediationWorkflow", 404),
]

# What each of them accepted, so that the 404 is not a refused body.
_BODIES = {
    "start": {"action": "start"},
    "import_results": {"file_format": "csv", "file_content": "eA=="},
    "test_connection": {"success": True, "message": "ok"},
    "send_notification": {"message": "m", "severity": "info"},
    "trigger_webhook": {"event_type": "vulnerability.created"},
}


def _model_named(name):
    for module in _models():
        if hasattr(module, name):
            return getattr(module, name)
    raise LookupError(name)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "method,prefix,action,model,status",
    REMOVED,
    ids=[
        f"{prefix.split('/api/v1/')[1]}{action}" for _, prefix, action, _, _ in REMOVED
    ],
)
def test_a_removed_placeholder_is_not_served(
    api, team, dispatched, method, prefix, action, model, status
):
    row = tf.make(_model_named(model), team) if model else None
    url = f"{prefix}{row.pk}/{action}/" if row is not None else f"{prefix}{action}/"
    before = _values(row) if row is not None else None
    # The row is there and the caller may write to it: the 404 is the route.
    assert api("get", f"{prefix}{row.pk}/" if row else prefix, team).status_code == 200

    data = None if method == "get" else _BODIES.get(action, {})
    response = api(method, url, team, data)

    assert response.status_code == status, response.content[:300]
    assert b"success" not in response.content
    if row is not None:
        assert _values(row) == before
    assert dispatched == []


def test_twenty_placeholders_were_removed():
    # Guards the parametrization above against silently covering nothing.
    assert len(REMOVED) == 20


def test_nothing_pretends_to_deliver_or_verify():
    """The model method and the task that did nothing are gone too."""
    from apps.integrations.models import NotificationChannel
    from guardian.celery import app

    # It counted a notification and returned True having sent nothing.
    assert not hasattr(NotificationChannel, "send_notification")
    # It answered "still_present" for every vulnerability, without a scan.
    app.loader.import_default_modules()
    assert "apps.vulnerabilities.tasks.scan_vulnerability_remediation" not in app.tasks


# --- integrations: log cleanup -----------------------------------------------


def _log(team, days_old, **fields):
    log = tf.integration_log(team)
    return _set(
        log, created_at=timezone.now() - timedelta(days=days_old, hours=1), **fields
    )


@pytest.mark.django_db
def test_cleanup_logs_deletes_the_teams_old_logs_and_no_others(api, team):
    from apps.integrations.models import IntegrationLog

    old, older = _log(team, 31), _log(team, 400)
    recent = _log(team, 29)
    theirs = _log(uuid.uuid4(), 400)

    response = api(
        "delete", f"{INTEGRATIONS}/logs/cleanup_logs/?older_than_days=30", team
    )

    assert response.status_code == 200, response.content[:300]
    assert response.json() == {"deleted": 2, "older_than_days": 30}
    left = set(IntegrationLog.objects.values_list("pk", flat=True))
    assert left == {recent.pk, theirs.pk}
    assert old.pk not in left and older.pk not in left


@pytest.mark.django_db
def test_cleanup_logs_keeps_thirty_days_unless_told(api, team):
    from apps.integrations.models import IntegrationLog

    _log(team, 31)
    kept = _log(team, 10)

    default = api("delete", f"{INTEGRATIONS}/logs/cleanup_logs/", team)
    assert default.json() == {"deleted": 1, "older_than_days": 30}
    assert list(IntegrationLog.objects.values_list("pk", flat=True)) == [kept.pk]

    shorter = api(
        "delete", f"{INTEGRATIONS}/logs/cleanup_logs/?older_than_days=7", team
    )
    assert shorter.json() == {"deleted": 1, "older_than_days": 7}
    assert not IntegrationLog.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize("days", ["abc", "0", "-5", "1.5", "", "999999999"])
def test_cleanup_logs_refuses_a_number_of_days_it_cannot_use(api, team, days):
    from apps.integrations.models import IntegrationLog

    _log(team, 400)

    response = api(
        "delete", f"{INTEGRATIONS}/logs/cleanup_logs/?older_than_days={days}", team
    )

    assert response.status_code == 400, response.content[:300]
    assert "older_than_days" in response.json()
    assert IntegrationLog.objects.count() == 1


@pytest.mark.django_db
def test_cleanup_logs_is_for_owners_and_admins(api, team):
    from apps.integrations.models import IntegrationLog

    _log(team, 400)

    response = api("delete", f"{INTEGRATIONS}/logs/cleanup_logs/", team, role="member")

    assert response.status_code == 403
    assert IntegrationLog.objects.count() == 1


# --- remediation: tickets ----------------------------------------------------


@pytest.mark.django_db
def test_assign_sets_the_tickets_assignee(api, team):
    ticket = tf.ticket(team)
    colleague = tf.user(team)

    response = api(
        "post",
        f"{REMEDIATION}/tickets/{ticket.pk}/assign/",
        team,
        {"assignee_id": colleague.pk},
    )

    assert response.status_code == 200, response.content[:300]
    assert response.json()["assigned_to"] == colleague.pk
    ticket.refresh_from_db()
    assert ticket.assigned_to_id == colleague.pk
    # And the API reads it back.
    read = api("get", f"{REMEDIATION}/tickets/{ticket.pk}/", team)
    assert read.json()["assigned_to"] == colleague.pk


@pytest.mark.django_db
def test_assign_refuses_anyone_who_is_not_a_member_of_the_team(api, team, settings):
    from apps.core.models import TeamMembership

    ticket = tf.ticket(team)
    stranger = tf.user(uuid.uuid4())
    former = tf.user(team)
    TeamMembership.objects.filter(user=former).update(
        last_seen=timezone.now() - settings.TEAM_MEMBERSHIP_MAX_AGE - timedelta(days=1)
    )

    for assignee in (stranger.pk, former.pk, 987654, "nobody", True, [1], None, ""):
        response = api(
            "post",
            f"{REMEDIATION}/tickets/{ticket.pk}/assign/",
            team,
            {"assignee_id": assignee},
        )
        assert response.status_code == 400, (assignee, response.content[:300])
        assert "success" not in response.content.decode()
    # A user that exists elsewhere and one that exists nowhere answer alike.
    answers = {
        api(
            "post",
            f"{REMEDIATION}/tickets/{ticket.pk}/assign/",
            team,
            {"assignee_id": who},
        ).content
        for who in (stranger.pk, 987654)
    }
    assert len(answers) == 1
    ticket.refresh_from_db()
    assert ticket.assigned_to_id is None


@pytest.mark.django_db
def test_assign_does_not_read_true_as_the_first_user(api, team):
    """``{"assignee_id": true}`` is not user 1, even when user 1 is a member."""
    from apps.core.models import TeamMembership
    from django.contrib.auth.models import User

    User.objects.filter(pk=1).delete()
    first = User.objects.create(pk=1, username=str(uuid.uuid4()))
    TeamMembership.objects.create(team_id=team, user=first)
    ticket = tf.ticket(team)
    url = f"{REMEDIATION}/tickets/{ticket.pk}/assign/"

    assert api("post", url, team, {"assignee_id": True}).status_code == 400
    ticket.refresh_from_db()
    assert ticket.assigned_to_id is None
    # By their id, the same user is accepted.
    assert api("post", url, team, {"assignee_id": 1}).status_code == 200


@pytest.mark.django_db
def test_update_status_stores_a_status_the_model_defines(api, team):
    ticket = tf.ticket(team)
    url = f"{REMEDIATION}/tickets/{ticket.pk}/update_status/"

    refused = api("post", url, team, {"status": "bogus"})
    assert refused.status_code == 400, refused.content[:300]
    assert "in_progress" in refused.json()["valid"]
    ticket.refresh_from_db()
    assert ticket.status == "pending"

    assert api("post", url, team, {"status": ["in_progress"]}).status_code == 400
    assert api("post", url, team, {}).status_code == 400

    accepted = api("post", url, team, {"status": "in_progress"})
    assert accepted.status_code == 200, accepted.content[:300]
    ticket.refresh_from_db()
    assert ticket.status == "in_progress"


# --- remediation: workflows --------------------------------------------------


@pytest.mark.django_db
def test_starting_and_completing_a_workflow_records_when(api, team):
    from apps.remediation.models import RemediationWorkflow

    workflow = tf.make(RemediationWorkflow, team)
    _set(workflow, planned_completion_date=timezone.now() + timedelta(days=7))
    url = f"{REMEDIATION}/workflows/{workflow.pk}"
    before = timezone.now()

    assert api("post", f"{url}/start/", team, {}).status_code == 200
    workflow.refresh_from_db()
    assert workflow.status == "in_progress"
    assert workflow.actual_start_date >= before
    assert workflow.actual_completion_date is None
    started = workflow.actual_start_date

    assert api("post", f"{url}/complete/", team, {}).status_code == 200
    workflow.refresh_from_db()
    assert workflow.status == "completed"
    assert workflow.actual_completion_date >= started
    assert workflow.actual_start_date == started
    # What the dates are for: without an end, a workflow completed in time
    # was measured against the clock and turned "missed" a week later.
    assert workflow.duration_days == 0
    _set(workflow, planned_completion_date=workflow.actual_completion_date)
    with mock.patch(
        "django.utils.timezone.now", return_value=before + timedelta(days=30)
    ):
        assert workflow.calculate_sla_status() == "met"


@pytest.mark.django_db
def test_restarting_a_workflow_keeps_its_start_and_drops_its_end(api, team):
    from apps.remediation.models import RemediationWorkflow

    workflow = tf.make(RemediationWorkflow, team)
    began = timezone.now() - timedelta(days=3)
    _set(
        workflow,
        status="completed",
        actual_start_date=began,
        actual_completion_date=timezone.now() - timedelta(days=1),
    )

    assert (
        api(
            "post", f"{REMEDIATION}/workflows/{workflow.pk}/start/", team, {}
        ).status_code
        == 200
    )

    workflow.refresh_from_db()
    assert workflow.status == "in_progress"
    assert workflow.actual_start_date == began
    assert workflow.actual_completion_date is None


@pytest.mark.django_db
def test_a_workflow_is_put_on_hold_with_a_status_the_model_defines(api, team):
    """What replaces ``pause``, which stored a status the API then refused."""
    from apps.remediation.models import RemediationStatus, RemediationWorkflow

    assert "paused" not in RemediationStatus.values
    workflow = tf.make(RemediationWorkflow, team)
    url = f"{REMEDIATION}/workflows/{workflow.pk}/"

    assert api("patch", url, team, {"status": "paused"}).status_code == 400
    refused = api("get", f"{REMEDIATION}/workflows/?status=paused", team)
    assert refused.status_code == 400
    held = api("patch", url, team, {"status": "deferred"})
    assert held.status_code == 200, held.content[:300]
    listed = api("get", f"{REMEDIATION}/workflows/?status=deferred", team)
    assert [row["id"] for row in listed.json()["results"]] == [str(workflow.pk)]


# --- scanners: what replaces the removed actions ------------------------------


@pytest.mark.django_db
def test_a_scans_status_is_set_on_the_record(api, team):
    """What replaces start, stop, pause and resume: the field they set."""
    from apps.scanners.models import Scan

    scan = tf.make(Scan, team)
    url = f"{SCANNERS}/scans/{scan.pk}/"

    # ``stop`` stored "stopped", which a scan cannot be.
    assert api("patch", url, team, {"status": "stopped"}).status_code == 400
    for status in ("running", "paused", "cancelled", "completed"):
        response = api("patch", url, team, {"status": status})
        assert response.status_code == 200, response.content[:300]
        scan.refresh_from_db()
        assert scan.status == status


@pytest.mark.django_db
def test_the_counts_the_removed_statistics_stood_for_are_on_the_lists(api, team):
    """sync_statistics and error_summary answered zeros; the lists count."""
    record = tf.sync_record(team)
    _set(record, sync_status="failed")
    tf.sync_record(team)
    _set(tf.integration_log(team), level="error")
    tf.integration_log(team)

    failed = api("get", f"{INTEGRATIONS}/sync-records/?sync_status=failed", team)
    errors = api("get", f"{INTEGRATIONS}/logs/?level=error", team)

    assert failed.json()["count"] == 1
    assert errors.json()["count"] == 1
    assert api("get", f"{INTEGRATIONS}/sync-records/", team).json()["count"] == 2


# --- remediation: templates --------------------------------------------------

STEPS = [
    {
        "title": "Patch",
        "description": "Install the fixed package",
        "instructions": "apt-get install --only-upgrade openssl",
        "validation_criteria": "openssl version",
        "estimated_duration_minutes": 15,
    },
    {"title": "Restart", "instructions": "systemctl restart nginx"},
]


def _template(team, **fields):
    template = tf.remediation_template(team)
    fields.setdefault("step_templates", STEPS)
    fields.setdefault("rollback_template", "apt-get install openssl=1.1.1")
    fields.setdefault("testing_template", "curl -sI https://host/")
    fields.setdefault("estimated_effort_hours", 2.5)
    fields.setdefault("usage_count", 7)
    fields.setdefault("success_rate", 80.0)
    return _set(template, **fields)


@pytest.mark.django_db
def test_clone_stores_a_copy_of_the_template(api, team):
    from apps.remediation.models import RemediationTemplate

    template = _template(team, default_priority="high", asset_types=["server"])
    caller = str(uuid.uuid4())

    response = api(
        "post",
        f"{REMEDIATION}/templates/{template.pk}/clone/",
        team,
        {},
        user_id=caller,
    )

    assert response.status_code == 201, response.content[:300]
    assert RemediationTemplate.objects.count() == 2
    copy = RemediationTemplate.objects.exclude(pk=template.pk).get()
    assert response.json()["id"] == str(copy.pk)
    assert copy.name == f"{template.name} (copy)"
    assert copy.team_id == team
    assert copy.created_by.username == caller
    for field in (
        "description",
        "category",
        "remediation_type",
        "default_priority",
        "estimated_effort_hours",
        "step_templates",
        "rollback_template",
        "testing_template",
        "vulnerability_types",
        "asset_types",
        "is_active",
    ):
        assert getattr(copy, field) == getattr(template, field), field
    # A copy has not been used: the original's counters are its own.
    assert (copy.usage_count, copy.success_rate) == (0, 0.0)
    template.refresh_from_db()
    assert (template.usage_count, template.success_rate) == (7, 80.0)
    # The copy is the team's: it is listed.
    listed = api("get", f"{REMEDIATION}/templates/", team).json()["results"]
    assert {row["id"] for row in listed} == {str(template.pk), str(copy.pk)}


@pytest.mark.django_db
def test_clone_takes_a_name(api, team):
    from apps.remediation.models import RemediationTemplate

    template = _template(team)
    url = f"{REMEDIATION}/templates/{template.pk}/clone/"

    named = api("post", url, team, {"name": "  Patch (Debian)  "})
    assert named.status_code == 201, named.content[:300]
    assert named.json()["name"] == "Patch (Debian)"

    for name in ("", "   ", 7, ["x"], "n" * 201):
        refused = api("post", url, team, {"name": name})
        assert refused.status_code == 400, (name, refused.content[:300])
        assert "name" in refused.json()
    assert RemediationTemplate.objects.count() == 2


@pytest.mark.django_db
def test_apply_creates_the_workflow_and_its_steps(api, team):
    from apps.remediation.models import RemediationWorkflow

    template = _template(team, default_priority="high", remediation_type="upgrade")
    vulnerability = tf.vulnerability(team)
    caller = str(uuid.uuid4())

    response = api(
        "post",
        f"{REMEDIATION}/templates/{template.pk}/apply/",
        team,
        {"vulnerability_id": str(vulnerability.pk)},
        user_id=caller,
    )

    assert response.status_code == 201, response.content[:300]
    workflow = RemediationWorkflow.objects.get()
    assert response.json()["id"] == str(workflow.pk)
    assert workflow.vulnerability_id == vulnerability.pk
    assert workflow.title == f"{template.name}: {vulnerability.title}"
    assert workflow.remediation_type == "upgrade"
    assert workflow.priority == "high"
    assert workflow.estimated_effort_hours == 2.5
    assert workflow.rollback_plan == template.rollback_template
    assert workflow.testing_plan == template.testing_template
    assert workflow.created_by.username == caller
    steps = list(workflow.steps.order_by("order"))
    assert [(s.order, s.title, s.instructions) for s in steps] == [
        (1, "Patch", "apt-get install --only-upgrade openssl"),
        (2, "Restart", "systemctl restart nginx"),
    ]
    assert steps[0].estimated_duration_minutes == 15
    assert steps[0].validation_criteria == "openssl version"
    template.refresh_from_db()
    assert template.usage_count == 8
    # The workflow is the team's, through its vulnerability.
    assert (
        api("get", f"{REMEDIATION}/workflows/{workflow.pk}/", team).status_code == 200
    )
    assert (
        api("get", f"{REMEDIATION}/workflows/{workflow.pk}/", uuid.uuid4()).status_code
        == 404
    )


@pytest.mark.django_db
def test_apply_takes_a_title(api, team):
    from apps.remediation.models import RemediationWorkflow

    template = _template(team)
    url = f"{REMEDIATION}/templates/{template.pk}/apply/"
    target = {"vulnerability_id": str(tf.vulnerability(team).pk)}

    for title in (7, ["x"], "t" * 501):
        refused = api("post", url, team, {**target, "title": title})
        assert refused.status_code == 400, (title, refused.content[:300])
    assert not RemediationWorkflow.objects.exists()

    named = api("post", url, team, {**target, "title": "Patch web-01"})
    assert named.status_code == 201, named.content[:300]
    assert RemediationWorkflow.objects.get().title == "Patch web-01"


@pytest.mark.django_db
def test_apply_refuses_a_second_workflow_for_a_vulnerability(api, team):
    from apps.remediation.models import RemediationStep, RemediationWorkflow

    template = _template(team)
    vulnerability = tf.vulnerability(team)
    url = f"{REMEDIATION}/templates/{template.pk}/apply/"
    body = {"vulnerability_id": str(vulnerability.pk)}
    assert api("post", url, team, body).status_code == 201

    again = api("post", url, team, body)

    assert again.status_code == 409, again.content[:300]
    assert again.json()["code"] == "WORKFLOW_EXISTS"
    assert RemediationWorkflow.objects.count() == 1
    assert RemediationStep.objects.count() == 2
    template.refresh_from_db()
    assert template.usage_count == 8  # counted once


@pytest.mark.django_db
def test_apply_leaves_nothing_behind_when_it_fails(api, team):
    """No workflow without its steps, and no use counted for it."""
    from apps.remediation.models import (
        RemediationStep,
        RemediationTemplate,
        RemediationWorkflow,
    )

    template = _template(team)
    vulnerability = tf.vulnerability(team)
    created = RemediationStep.objects.create

    def fail_on_the_second_step(**fields):
        if fields["order"] == 2:
            raise RuntimeError("the database went away")
        return created(**fields)

    with mock.patch.object(
        RemediationStep.objects, "create", side_effect=fail_on_the_second_step
    ):
        response = api(
            "post",
            f"{REMEDIATION}/templates/{template.pk}/apply/",
            team,
            {"vulnerability_id": str(vulnerability.pk)},
        )

    assert response.status_code == 500
    assert not RemediationWorkflow.objects.exists()
    assert not RemediationStep.objects.exists()
    assert RemediationTemplate.objects.get(pk=template.pk).usage_count == 7


@pytest.mark.django_db
def test_apply_needs_a_vulnerability_of_the_team(api, team):
    from apps.remediation.models import RemediationWorkflow

    template = _template(team)
    theirs = tf.vulnerability(uuid.uuid4())
    url = f"{REMEDIATION}/templates/{template.pk}/apply/"

    answers = []
    for target in (str(theirs.pk), str(uuid.uuid4()), "not-a-uuid", 7, ["x"]):
        response = api("post", url, team, {"vulnerability_id": target})
        assert response.status_code == 400, (target, response.content[:300])
        answers.append(response.content)
    # Another team's vulnerability and one that does not exist answer alike.
    assert answers[0] == answers[1]
    assert api("post", url, team, {}).status_code == 400
    assert not RemediationWorkflow.objects.exists()
    template.refresh_from_db()
    assert template.usage_count == 7  # a refused request is not a use


@pytest.mark.django_db
@pytest.mark.parametrize(
    "steps",
    [
        "patch it",
        ["patch it"],
        [{"title": 7}],
        [{"title": "t" * 201}],
        [{"title": "ok"}, {"instructions": ["a", "b"]}],
        [{"estimated_duration_minutes": "soon"}],
        [{"estimated_duration_minutes": -1}],
        [{"estimated_duration_minutes": True}],
    ],
)
def test_apply_refuses_a_template_whose_steps_cannot_be_created(api, team, steps):
    from apps.remediation.models import RemediationStep, RemediationWorkflow

    template = _template(team, step_templates=steps)
    vulnerability = tf.vulnerability(team)

    response = api(
        "post",
        f"{REMEDIATION}/templates/{template.pk}/apply/",
        team,
        {"vulnerability_id": str(vulnerability.pk)},
    )

    assert response.status_code == 400, response.content[:300]
    assert response.json()["code"] == "TEMPLATE_STEPS_INVALID"
    # Nothing half-made: no workflow without its steps.
    assert not RemediationWorkflow.objects.exists()
    assert not RemediationStep.objects.exists()
    template.refresh_from_db()
    assert template.usage_count == 7


@pytest.mark.django_db
def test_a_template_without_steps_still_makes_a_workflow(api, team):
    from apps.remediation.models import RemediationWorkflow

    template = _template(team, step_templates=[])

    response = api(
        "post",
        f"{REMEDIATION}/templates/{template.pk}/apply/",
        team,
        {"vulnerability_id": str(tf.vulnerability(team).pk)},
    )

    assert response.status_code == 201, response.content[:300]
    assert RemediationWorkflow.objects.get().steps.count() == 0


# --- vulnerabilities: bulk actions -------------------------------------------


def _bulk(api, team, vulnerabilities, action, **fields):
    body = {"vulnerability_ids": [str(v.pk) for v in vulnerabilities], "action": action}
    body.update(fields)
    return api("post", f"{VULNERABILITIES}/bulk_action/", team, body)


@pytest.mark.django_db
def test_a_bulk_reopen_reopens(api, team):
    from apps.vulnerabilities.models import VulnerabilityHistory

    resolved = _set(
        tf.vulnerability(team), status="resolved", resolved_at=timezone.now()
    )
    accepted = _set(tf.vulnerability(team), status="accepted")

    response = _bulk(api, team, [resolved, accepted], "reopen", reason="came back")

    assert response.status_code == 200, response.content[:300]
    assert response.json()["updated_count"] == 2
    for vulnerability, was in ((resolved, "resolved"), (accepted, "accepted")):
        vulnerability.refresh_from_db()
        assert vulnerability.status == "open"
        assert vulnerability.resolved_at is None
        entry = VulnerabilityHistory.objects.get(
            vulnerability=vulnerability, change_reason="Reopened: came back"
        )
        # The status it had, not "resolved" whatever it was.
        assert (entry.old_value, entry.new_value) == (was, "open")


@pytest.mark.django_db
def test_a_bulk_untag_removes_the_tag(api, team):
    tagged = _set(tf.vulnerability(team), tags=["kev", "edge"])
    other = _set(tf.vulnerability(team), tags=["edge"])

    response = _bulk(api, team, [tagged, other], "untag", tag="kev")

    assert response.status_code == 200, response.content[:300]
    tagged.refresh_from_db()
    other.refresh_from_db()
    assert tagged.tags == ["edge"]
    assert other.tags == ["edge"]


@pytest.mark.django_db
def test_a_bulk_assign_sets_what_it_names_and_keeps_the_rest(api, team, dispatched):
    """A group alone unassigned every user; a user alone cleared every group."""
    owner, colleague = tf.user(team), tf.user(team)
    vulnerability = _set(
        tf.vulnerability(team), assigned_to=owner, assignee_group="platform"
    )

    grouped = _bulk(api, team, [vulnerability], "assign", assignee_group="network")
    assert grouped.status_code == 200, grouped.content[:300]
    vulnerability.refresh_from_db()
    assert (vulnerability.assigned_to_id, vulnerability.assignee_group) == (
        owner.pk,
        "network",
    )

    # A group names nobody to tell.
    assert dispatched == []

    handed = _bulk(api, team, [vulnerability], "assign", assigned_to=colleague.pk)
    assert handed.status_code == 200, handed.content[:300]
    vulnerability.refresh_from_db()
    assert (vulnerability.assigned_to_id, vulnerability.assignee_group) == (
        colleague.pk,
        "network",
    )
    # The new assignee is told, as assign/ tells them (#724).
    assert dispatched == [
        "apps.vulnerabilities.tasks.notify_vulnerability_assignment"
    ]


def _bulk_choices():
    from apps.vulnerabilities.serializers import VulnerabilityBulkActionSerializer

    return sorted(VulnerabilityBulkActionSerializer().fields["action"].choices)


@pytest.mark.django_db
@pytest.mark.parametrize("action", _bulk_choices())
def test_every_bulk_action_the_api_accepts_is_performed(api, team, dispatched, action):
    """An action the serializer lists and the view skips cannot come back."""
    colleague = tf.user(team)
    extras = {
        "assign": {"assigned_to": colleague.pk},
        "tag": {"tag": "kev"},
        "untag": {"tag": "edge"},
        "priority": {"priority": "p1"},
    }
    start = {"reopen": {"status": "resolved"}, "untag": {"tags": ["edge"]}}
    vulnerability = _set(tf.vulnerability(team), **start.get(action, {}))
    before = _values(vulnerability)

    response = _bulk(api, team, [vulnerability], action, **extras.get(action, {}))

    assert response.status_code == 200, response.content[:300]
    assert response.json()["updated_count"] == 1
    after = _values(vulnerability)
    changed = {name for name in after if after[name] != before[name]}
    assert changed - {"updated_at", "last_detected"}, (action, response.content)


def test_the_bulk_actions_are_the_six_documented():
    assert _bulk_choices() == ["assign", "close", "priority", "reopen", "tag", "untag"]


@pytest.mark.django_db
def test_a_bulk_action_the_view_does_not_perform_is_refused(api, team, monkeypatch):
    """Not "Bulk action completed on 0 vulnerabilities"."""
    from apps.vulnerabilities.serializers import VulnerabilityBulkActionSerializer
    from rest_framework import serializers

    # The next action someone adds to the serializer and not to the view.
    monkeypatch.setitem(
        VulnerabilityBulkActionSerializer._declared_fields,
        "action",
        serializers.ChoiceField(choices=[*_bulk_choices(), "archive"]),
    )
    vulnerability = tf.vulnerability(team)
    before = _values(vulnerability)

    response = _bulk(api, team, [vulnerability], "archive")

    assert response.status_code == 400, response.content[:300]
    assert "archive" in response.json()["action"][0]
    assert _values(vulnerability) == before
    # And one the serializer does not know is refused by it.
    assert _bulk(api, team, [vulnerability], "delete").status_code == 400


# --- vulnerabilities: assign, close, reopen ----------------------------------


@pytest.mark.django_db
def test_assigning_to_nobody_is_refused(api, team, dispatched):
    vulnerability = tf.vulnerability(team)
    before = _values(vulnerability)

    for body in ({}, {"assigned_to": None}, {"assigned_to": "", "assignee_group": ""}):
        response = api(
            "post", f"{VULNERABILITIES}/{vulnerability.pk}/assign/", team, body
        )
        assert response.status_code == 400, (body, response.content[:300])
        assert "successfully" not in response.content.decode()

    assert _values(vulnerability) == before
    assert dispatched == []  # and nobody is notified of an assignment

    group = api(
        "post",
        f"{VULNERABILITIES}/{vulnerability.pk}/assign/",
        team,
        {"assignee_group": "platform"},
    )
    assert group.status_code == 200, group.content[:300]
    vulnerability.refresh_from_db()
    assert vulnerability.assignee_group == "platform"


@pytest.mark.django_db
def test_close_and_reopen_record_the_status_the_vulnerability_had(api, team):
    from apps.vulnerabilities.models import VulnerabilityHistory

    vulnerability = _set(tf.vulnerability(team), status="in_progress")
    url = f"{VULNERABILITIES}/{vulnerability.pk}"

    assert api("post", f"{url}/close/", team, {"reason": "patched"}).status_code == 200
    closed = VulnerabilityHistory.objects.get(
        vulnerability=vulnerability, change_reason="Closed: patched"
    )
    assert (closed.old_value, closed.new_value) == ("in_progress", "resolved")
    vulnerability.refresh_from_db()
    assert vulnerability.status == "resolved"
    assert vulnerability.metadata["resolution"]["reason"] == "patched"

    _set(vulnerability, status="false_positive")
    assert (
        api("post", f"{url}/reopen/", team, {"reason": "it is real"}).status_code == 200
    )
    reopened = VulnerabilityHistory.objects.get(
        vulnerability=vulnerability, change_reason="Reopened: it is real"
    )
    assert (reopened.old_value, reopened.new_value) == ("false_positive", "open")


# --- vulnerabilities: trends -------------------------------------------------


def _trend(api, team, **kwargs):
    response = api("get", f"{VULNERABILITIES}/trends/?days=1", team, **kwargs)
    assert response.status_code == 200, response.content[:300]
    days = response.json()
    assert len(days) == 2
    return {
        "discovered": sum(day["discovered_count"] for day in days),
        "resolved": sum(day["resolved_count"] for day in days),
        "open": days[-1]["total_open"],
    }


@pytest.mark.django_db
def test_trends_count_the_rows_the_list_shows(api, team):
    """The team's rows and, for a member, their own: as the list (#642).

    The audit that led to #644 read ``trends`` as counting every
    vulnerability whoever asked. It did until #642, which made it start from
    ``get_queryset`` like the list; this pins it.
    """
    from django.contrib.auth.models import User

    member_id = str(uuid.uuid4())
    api(
        "get", f"{VULNERABILITIES}/", team, role="member", user_id=member_id
    )  # mirrors the user
    member = User.objects.get(username=member_id)
    _set(tf.vulnerability(team), assigned_to=member)
    _set(
        tf.vulnerability(team),
        created_by=member,
        status="resolved",
        resolved_at=timezone.now(),
    )
    tf.vulnerability(team)
    tf.vulnerability(uuid.uuid4())
    as_member = {"role": "member", "user_id": member_id}

    def listed(**kwargs):
        return api("get", f"{VULNERABILITIES}/", team, **kwargs).json()["count"]

    # An admin: the team's three, and not the other team's one.
    assert listed() == 3
    assert _trend(api, team) == {"discovered": 3, "resolved": 1, "open": 2}
    # A member: the two assigned to or created by them.
    assert listed(**as_member) == 2
    assert _trend(api, team, **as_member) == {"discovered": 2, "resolved": 1, "open": 1}


@pytest.mark.django_db
@pytest.mark.parametrize("days", ["abc", "-1", "1.5", "", "367", "100000"])
def test_trends_refuse_a_window_they_cannot_compute(api, team, days):
    response = api("get", f"{VULNERABILITIES}/trends/?days={days}", team)

    assert response.status_code == 400, response.content[:300]
    assert "days" in response.json()


@pytest.mark.django_db
def test_trends_window_is_inclusive(api, team):
    assert len(api("get", f"{VULNERABILITIES}/trends/?days=0", team).json()) == 1
    assert len(api("get", f"{VULNERABILITIES}/trends/", team).json()) == 31
    assert len(api("get", f"{VULNERABILITIES}/trends/?days=366", team).json()) == 367


# --- assets: discovery rules -------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("discovery_type", ["cloud_api", "cmdb_import", "dns_zone"])
def test_a_rule_of_an_unimplemented_type_is_not_executed(
    api, team, dispatched, discovery_type
):
    from apps.core.models import TeamTask

    rule = _set(tf.discovery_rule(team), discovery_type=discovery_type)

    response = api(
        "post", f"/api/v1/assets/discovery-rules/{rule.pk}/execute/", team, {}
    )

    assert response.status_code == 501, response.content[:300]
    body = response.json()
    assert body["code"] == "DISCOVERY_TYPE_NOT_IMPLEMENTED"
    assert discovery_type in body["detail"]
    assert "task_id" not in body
    assert dispatched == []
    assert not TeamTask.objects.exists()
    rule.refresh_from_db()
    assert rule.last_run is None


@pytest.mark.django_db
def test_a_network_scan_rule_is_executed(api, team, dispatched):
    rule = tf.discovery_rule(team)

    response = api(
        "post", f"/api/v1/assets/discovery-rules/{rule.pk}/execute/", team, {}
    )

    assert response.status_code == 200, response.content[:300]
    assert dispatched == ["apps.assets.tasks.execute_discovery_rule"]


@pytest.mark.django_db
def test_a_rule_reports_the_scans_it_queued_not_assets_it_found(dispatched):
    """It counted each network as a discovered asset."""
    from apps.assets import tasks

    rule = _set(
        tf.discovery_rule(uuid.uuid4()),
        target_specification={"networks": ["192.0.2.0/30", "198.51.100.0/30"]},
    )

    result = tasks.execute_discovery_rule.apply(args=(rule.pk,)).get()

    assert result == {
        "status": "completed",
        "rule_name": rule.name,
        "networks_queued": 2,
    }
    assert dispatched == ["apps.assets.tasks.discover_assets"] * 2
    # No function is left that "discovers" by logging that it does not.
    for name in (
        "_execute_cloud_discovery",
        "_execute_cmdb_import",
        "_discover_aws_assets",
    ):
        assert not hasattr(tasks, name)
