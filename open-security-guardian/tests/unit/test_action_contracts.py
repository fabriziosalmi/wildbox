"""No action answers success without doing what it says (#644).

guardian had twenty-odd actions that answered ``200 {"status": "success"}``,
or fixed figures, and did nothing: no external system contacted, no log
deleted, no ticket assigned, no template copied. Nothing told a client, an
operator or a test which answers were real.

Every custom action the URLconf routes is listed here, from the URLconf and
not by hand, and must be classified in ``CONTRACTS`` as one of:

* ``Effect``: a request that changes something. The test sends it and
  compares everything guardian stores, the Celery tasks dispatched and the
  e-mails sent, before and after. A 2xx answer with nothing changed is a
  placeholder, and fails. So does one that leaves a stored value its model
  does not define (a status that is not among the field's choices).
* ``Evaluates``: a request other than a GET that computes an answer and
  stores nothing (testing a widget or an alert rule). Its answer must
  follow the data: the test changes the data and expects another answer.
* ``Refuses``: an action that always answers an error and changes nothing
  (what guardian cannot do, said honestly).
* ``Reads``: a GET. It must store nothing, and its answer must follow the
  data: fixed figures (``{"status": "healthy", "response_time_ms": 150}``)
  fail.

An action added without a contract fails ``test_every_action_is_classified``
with the instructions; one that answers success and does nothing cannot be
given a contract that passes. Run against the code before #644, with a
contract for each of the twenty actions it removed, these checks fail
seventeen of them.

What they cannot see is an action that changes something other than what it
says: ``scans/{id}/start/`` set the stored status to "running" and started
no scan, and passes as an ``Effect``. That is for the action's own tests and
its review: what each action changes in particular is asserted next to it
(test_placeholder_actions.py for the ones #644 made real). The views that
are not viewset actions are listed in ``VIEWS``.
"""

import uuid
from datetime import timedelta
from pathlib import Path
from unittest import mock

import pytest
from django.apps import apps
from django.core import mail
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
_STANDARD = {"list", "create", "retrieve", "update", "partial_update", "destroy"}
# Not guardian's API: Django's admin, and the schema and its UIs, which are
# routed in development only (guardian/urls.py).
_NOT_API = ("admin/", "api/schema/", "docs/", "redoc/", "__debug__/")
# Rows a request writes whatever it does: who made it and when.
_REQUEST_BOOKKEEPING = {"core.TeamMembership", "core.AuditLog"}
_GUARDIAN_APPS = {
    "assets",
    "vulnerabilities",
    "scanners",
    "remediation",
    "compliance",
    "integrations",
    "reporting",
    "core",
}
# Fields of a response that differ between two identical calls.
_VOLATILE = {"last_updated", "test_time"}


# --- what the URLconf routes -------------------------------------------------


def _walk(patterns, prefix=""):
    for entry in patterns:
        part = str(entry.pattern).lstrip("^").rstrip("$")
        if isinstance(entry, URLResolver):
            yield from _walk(entry.url_patterns, prefix + part)
        elif isinstance(entry, URLPattern):
            yield prefix + part, entry.callback


class Route:
    def __init__(self, method, path, view_cls, name):
        self.method = method
        self.path = "/" + path
        self.view_cls = view_cls
        self.name = name
        self.detail = "(?P<pk>" in path

    @property
    def model(self):
        return self.view_cls.queryset.model

    def url(self, row=None):
        if not self.detail:
            return self.path
        return self.path.replace("(?P<pk>[^/.]+)", str(row.pk))


def _routed():
    """({"ViewSet.action.method": Route}, {path: view class name})."""
    actions, views = {}, {}
    for path, callback in _walk(get_resolver().url_patterns):
        if path.startswith(_NOT_API) or "format" in path:
            continue
        view_cls = getattr(callback, "cls", None) or getattr(
            callback, "view_class", None
        )
        mapping = getattr(callback, "actions", None)
        if mapping is None:
            name = getattr(view_cls, "__name__", repr(callback))
            if name != "APIRootView":  # DRF's own listing of a router
                views["/" + path] = name
            continue
        for method, name in mapping.items():
            if name not in _STANDARD:
                key = f"{view_cls.__name__}.{name}.{method}"
                actions[key] = Route(method, path, view_cls, name)
    return actions, views


ROUTED, ROUTED_VIEWS = _routed()


# --- the contracts -----------------------------------------------------------


class Ctx:
    """What a contract's callables are given."""

    def __init__(self, team, row):
        self.team = team
        self.row = row

    def member(self):
        """The id of a user who is a member of the team."""
        return tf.user(self.team).pk


class _Contract:
    def __init__(self, body=None, prepare=None, query=""):
        self._body = body
        self._prepare = prepare
        self.query = query

    def prepare(self, ctx):
        if self._prepare is not None:
            self._prepare(ctx)

    def body(self, ctx):
        body = self._body(ctx) if callable(self._body) else self._body
        return {} if body is None else body


class Effect(_Contract):
    """Succeeds, and something guardian keeps or sends is different after."""

    def __init__(self, body=None, prepare=None, query="", status=200):
        super().__init__(body, prepare, query)
        self.status = status


class Evaluates(_Contract):
    """Computes an answer and stores nothing; ``vary`` changes the answer."""

    def __init__(self, vary, body=None, prepare=None):
        super().__init__(body, prepare)
        self.vary = vary


class Refuses(_Contract):
    """Always an error, with nothing changed."""

    def __init__(self, status, code=None, body=None, prepare=None):
        super().__init__(body, prepare)
        self.status = status
        self.code = code


class Reads(_Contract):
    """A GET whose answer follows the data: ``populate`` changes it.

    Without ``populate``, a list-level action is expected to answer
    differently once the team has a row of the viewset's model.
    """

    def __init__(self, populate=None, prepare=None, status=200):
        super().__init__(None, prepare)
        self.populate = populate
        self.status = status


def _set(row, **fields):
    """Set fields without save(): no signal, no auto_now, no validation."""
    type(row)._base_manager.filter(pk=row.pk).update(**fields)
    for name, value in fields.items():
        setattr(row, name, value)
    return row


def _aged_log(ctx):
    log = tf.integration_log(ctx.team)
    _set(log, created_at=timezone.now() - timedelta(days=400))


def _group_with_a_matching_asset(ctx):
    # The asset first: creating one applies the rules the groups have then.
    tf.asset(ctx.team, asset_type="server")
    _set(ctx.row, auto_assignment_rules={"asset_type": "server"})


def _group_with_an_asset(ctx):
    ctx.asset = tf.asset(ctx.team)
    ctx.row.assets.add(ctx.asset)


def _control_result(ctx, control, assessment):
    from apps.compliance.models import ComplianceResult

    return ComplianceResult.objects.create(
        assessment=assessment,
        control=control,
        status="non_compliant",
        risk_level="high",
        findings="f",
    )


def _control_evidence(ctx, control, assessment):
    from apps.compliance.models import ComplianceEvidence

    return ComplianceEvidence.objects.create(
        assessment=assessment, control=control, title="e", evidence_type="document"
    )


def _framework_metrics(ctx):
    from apps.compliance.models import ComplianceMetrics

    ComplianceMetrics.objects.create(
        team_id=ctx.team,
        framework=ctx.row,
        metric_date=timezone.now(),
        total_controls=4,
        compliant_controls=1,
        non_compliant_controls=3,
        partially_compliant_controls=0,
        not_applicable_controls=0,
        not_tested_controls=0,
        compliance_percentage=25,
    )


def _history_entry(ctx):
    from apps.vulnerabilities.models import VulnerabilityHistory

    VulnerabilityHistory.objects.create(
        vulnerability=ctx.row, field_name="severity", old_value="low", new_value="high"
    )


def _scan_result(ctx):
    from apps.scanners.models import ScanResult

    ScanResult.objects.create(
        scan=ctx.row,
        plugin_id="1",
        plugin_name="p",
        severity="high",
        host="192.0.2.1",
        description="d",
    )


def _workflow_step(ctx):
    from apps.remediation.models import RemediationStep

    RemediationStep.objects.create(
        workflow=ctx.row, title="s", description="d", order=1, instructions="i"
    )


def _template_report(ctx):
    from apps.reporting.models import Report

    Report.objects.create(template=ctx.row, name="r", format="json")


def _template_metrics(ctx):
    from apps.reporting.models import ReportMetrics

    ReportMetrics.objects.create(
        template=ctx.row,
        metric_date=timezone.now(),
        generation_count=5,
        success_rate=100,
    )


def _report_file(ctx):
    """A completed report whose file is where generate_report writes it."""
    from apps.reporting.tasks import team_reports_dir

    directory = Path(team_reports_dir(ctx.team))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{ctx.row.pk}.json"
    path.write_text("{}")
    _set(ctx.row, status="completed", file_path=str(path))


def _rule_notification(ctx):
    from apps.reporting.models import AlertNotification

    AlertNotification.objects.create(rule=ctx.row, kind="firing", value=1)


def _overdue_assessment(ctx):
    _set(tf.assessment(ctx.team), due_date=timezone.now() - timedelta(days=1))


def _approved_exception(ctx):
    _set(tf.exception(ctx.team), status="approved")


CONTRACTS = {
    # --- assets ---
    "AssetViewSet.scan.post": Effect(
        prepare=lambda c: _set(c.row, ip_address="192.0.2.10")
    ),
    "AssetViewSet.add_software.post": Effect(
        body={"name": "nginx", "version": "1.25"}, status=201
    ),
    "AssetViewSet.add_port.post": Effect(
        body={"port_number": 443, "protocol": "tcp"}, status=201
    ),
    "AssetViewSet.add_tag.post": Effect(body={"tag": "edge"}),
    "AssetViewSet.remove_tag.delete": Effect(
        body={"tag": "edge"}, prepare=lambda c: _set(c.row, tags=["edge"])
    ),
    "AssetViewSet.discover.post": Effect(body={"network_range": "192.0.2.0/30"}),
    "AssetViewSet.statistics.get": Reads(),
    "AssetGroupViewSet.apply_rules.post": Effect(prepare=_group_with_a_matching_asset),
    "AssetGroupViewSet.add_assets.post": Effect(
        body=lambda c: {"asset_ids": [str(tf.asset(c.team).pk)]}
    ),
    "AssetGroupViewSet.remove_assets.delete": Effect(
        body=lambda c: {"asset_ids": [str(c.asset.pk)]}, prepare=_group_with_an_asset
    ),
    "AssetDiscoveryRuleViewSet.execute.post": Effect(),
    "AssetDiscoveryRuleViewSet.enable.post": Effect(
        prepare=lambda c: _set(c.row, enabled=False)
    ),
    "AssetDiscoveryRuleViewSet.disable.post": Effect(),
    "AssetSoftwareViewSet.inventory.get": Reads(),
    "AssetPortViewSet.summary.get": Reads(
        populate=lambda c: _set(tf.asset_port(c.team), state="open")
    ),
    # --- vulnerabilities ---
    "VulnerabilityViewSet.assign.post": Effect(
        body=lambda c: {"assigned_to": c.member()}
    ),
    "VulnerabilityViewSet.close.post": Effect(body={"reason": "patched"}),
    "VulnerabilityViewSet.reopen.post": Effect(
        prepare=lambda c: _set(c.row, status="resolved")
    ),
    "VulnerabilityViewSet.add_tag.post": Effect(body={"tag": "kev"}),
    "VulnerabilityViewSet.remove_tag.post": Effect(
        body={"tag": "kev"}, prepare=lambda c: _set(c.row, tags=["kev"])
    ),
    "VulnerabilityViewSet.history.get": Reads(populate=_history_entry),
    "VulnerabilityViewSet.bulk_action.post": Effect(
        body=lambda c: {
            "vulnerability_ids": [str(tf.vulnerability(c.team).pk)],
            "action": "close",
        }
    ),
    "VulnerabilityViewSet.stats.get": Reads(),
    "VulnerabilityViewSet.trends.get": Reads(),
    # --- scanners ---
    "ScannerViewSet.stats.get": Reads(),
    "ScanViewSet.results.get": Reads(populate=_scan_result),
    # A scan schedule would never run (#548): asked to, guardian says so.
    "ScanScheduleViewSet.trigger.post": Refuses(400),
    "ScanScheduleViewSet.enable.post": Refuses(
        400, prepare=lambda c: _set(c.row, is_active=False)
    ),
    "ScanScheduleViewSet.disable.post": Effect(),
    # --- remediation ---
    "RemediationTicketViewSet.assign.post": Effect(
        body=lambda c: {"assignee_id": c.member()}
    ),
    "RemediationTicketViewSet.update_status.post": Effect(
        body={"status": "in_progress"}
    ),
    "RemediationWorkflowViewSet.start.post": Effect(),
    "RemediationWorkflowViewSet.complete.post": Effect(),
    "RemediationWorkflowViewSet.progress.get": Reads(populate=_workflow_step),
    "RemediationStepViewSet.execute.post": Effect(),
    "RemediationStepViewSet.complete.post": Effect(),
    "RemediationStepViewSet.skip.post": Effect(),
    "RemediationTemplateViewSet.clone.post": Effect(status=201),
    "RemediationTemplateViewSet.apply.post": Effect(
        body=lambda c: {"vulnerability_id": str(tf.vulnerability(c.team).pk)},
        status=201,
    ),
    "RemediationTemplateViewSet.categories.get": Reads(),
    # --- compliance ---
    "ComplianceFrameworkViewSet.controls.get": Reads(
        populate=lambda c: tf.control(c.team, c.row)
    ),
    "ComplianceFrameworkViewSet.assessments.get": Reads(
        populate=lambda c: tf.assessment(c.team, c.row)
    ),
    "ComplianceFrameworkViewSet.metrics.get": Reads(
        populate=_framework_metrics, status=404
    ),
    "ComplianceControlViewSet.results.get": Reads(
        populate=lambda c: _control_result(
            c, c.row, tf.assessment(c.team, c.row.framework)
        )
    ),
    "ComplianceControlViewSet.evidence.get": Reads(
        populate=lambda c: _control_evidence(
            c, c.row, tf.assessment(c.team, c.row.framework)
        )
    ),
    "ComplianceAssessmentViewSet.results.get": Reads(
        populate=lambda c: _control_result(
            c, tf.control(c.team, c.row.framework), c.row
        )
    ),
    "ComplianceAssessmentViewSet.evidence.get": Reads(
        populate=lambda c: _control_evidence(
            c, tf.control(c.team, c.row.framework), c.row
        )
    ),
    "ComplianceAssessmentViewSet.summary.get": Reads(
        populate=lambda c: _control_result(
            c, tf.control(c.team, c.row.framework), c.row
        )
    ),
    "ComplianceAssessmentViewSet.overdue.get": Reads(populate=_overdue_assessment),
    "ComplianceResultViewSet.non_compliant.get": Reads(),
    "ComplianceResultViewSet.high_risk.get": Reads(),
    "ComplianceExceptionViewSet.pending.get": Reads(),
    "ComplianceExceptionViewSet.expiring_soon.get": Reads(populate=_approved_exception),
    "ComplianceExceptionViewSet.needs_review.get": Reads(populate=_approved_exception),
    "ComplianceMetricsViewSet.dashboard.get": Reads(),
    # --- integrations ---
    "IntegrationLogViewSet.cleanup_logs.delete": Effect(
        prepare=_aged_log, query="?older_than_days=30"
    ),
    # --- reports ---
    "ReportTemplateViewSet.generate.post": Effect(body={"format": "json"}, status=202),
    "ReportTemplateViewSet.reports.get": Reads(populate=_template_report),
    "ReportTemplateViewSet.metrics.get": Reads(populate=_template_metrics),
    "ReportScheduleViewSet.run_now.post": Effect(status=202),
    "ReportScheduleViewSet.due.get": Reads(),
    # 400 "not ready" until the report is completed and its file is there.
    "ReportViewSet.download.get": Reads(populate=_report_file, status=400),
    "ReportViewSet.recent.get": Reads(),
    "ReportViewSet.failed.get": Reads(
        populate=lambda c: _set(tf.report(c.team), status="failed")
    ),
    "DashboardViewSet.data.get": Reads(
        populate=lambda c: _set(
            c.row, widgets_config=[{"type": "metric", "data_source": "assets"}]
        )
    ),
    "DashboardViewSet.share.post": Effect(body=lambda c: {"user_ids": [c.member()]}),
    "WidgetViewSet.data.get": Reads(populate=lambda c: tf.asset(c.team)),
    "WidgetViewSet.test.post": Evaluates(vary=lambda c: tf.asset(c.team)),
    "ReportMetricsViewSet.summary.get": Reads(),
    "AlertRuleViewSet.test.post": Evaluates(vary=lambda c: tf.vulnerability(c.team)),
    "AlertRuleViewSet.notifications.get": Reads(populate=_rule_notification),
    "AlertRuleViewSet.check_all.post": Effect(),
}

# The routed views that are not viewset actions, and the test module that
# shows what each does. A view added to the URLconf must be added here, with
# tests of its own.
VIEWS = {
    "/health/": ("HealthCheckView", "test_action_contracts.py"),
    "/metrics/": ("MetricsView", "test_action_contracts.py"),
    "/internal/team-memberships/revoke/": (
        "RevokeTeamMembershipsView",
        "test_team_membership_revocation.py",
    ),
    "/api/v1/tasks/<uuid:task_id>/": ("TaskStatusView", "test_celery_dispatch.py"),
}


# --- nothing is left unclassified --------------------------------------------


def test_the_urlconf_routes_actions():
    # Guards the parametrized tests below against silently covering nothing.
    assert len(ROUTED) > 60, sorted(ROUTED)


def test_every_action_is_classified():
    missing = sorted(set(ROUTED) - set(CONTRACTS))
    assert not missing, (
        f"{missing} have no contract. Add each to CONTRACTS in "
        "tests/unit/test_action_contracts.py as Effect (it changes "
        "something), Evaluates (it computes an answer and stores nothing), "
        "Refuses (it always answers an error) or Reads (a GET): an action "
        "that answers success without doing what it says is a placeholder, "
        "and guardian has none (#644)."
    )
    stale = sorted(set(CONTRACTS) - set(ROUTED))
    assert not stale, f"{stale} are no longer routed: remove their contracts."


def test_a_get_reads_and_only_a_get_reads():
    for key, contract in CONTRACTS.items():
        is_get = key.endswith(".get")
        assert isinstance(contract, Reads) == is_get, key


def test_every_other_view_is_accounted_for():
    expected = {path: name for path, (name, _) in VIEWS.items()}
    assert ROUTED_VIEWS == expected, (
        "A view was added to or removed from guardian/urls.py: list it in "
        "VIEWS (tests/unit/test_action_contracts.py) with the tests that show "
        "what it does."
    )
    tests_dir = Path(__file__).parent
    for path, (_, module) in VIEWS.items():
        # The module exists and exercises that path.
        fragment = path.split("<")[0]
        assert fragment in (tests_dir / module).read_text(), (path, module)


# --- the harness -------------------------------------------------------------


@pytest.fixture
def api(settings, monkeypatch, tmp_path):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    settings.MEDIA_ROOT = str(tmp_path)
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    caller = str(uuid.uuid4())

    def call(method, url, team, data=None, role="admin"):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": caller,
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
def dispatched(monkeypatch):
    """The names of the Celery tasks dispatched, instead of a broker."""
    from celery.app.task import Task

    names = []

    def apply_async(self, *args, **kwargs):
        names.append(self.name)
        return mock.Mock(id=str(uuid.uuid4()))

    monkeypatch.setattr(Task, "apply_async", apply_async)
    return names


def _world(dispatched):
    """Everything guardian keeps or sends that an action could change."""
    rows = {}
    for model in apps.get_models(include_auto_created=True):
        meta = model._meta
        if meta.app_label not in _GUARDIAN_APPS or meta.label in _REQUEST_BOOKKEEPING:
            continue
        # A save() that changes nothing moves these, and only these.
        clock = {
            field.attname
            for field in meta.concrete_fields
            if getattr(field, "auto_now", False)
        }
        rows[meta.label] = {
            repr(values[meta.pk.attname]): {
                name: value for name, value in values.items() if name not in clock
            }
            for values in model._base_manager.values()
        }
    return {"rows": rows, "tasks": list(dispatched), "mail": len(mail.outbox)}


def _changed(before, after):
    """The models whose rows differ, for the failure message."""
    changed = [
        label
        for label in after["rows"]
        if after["rows"][label] != before["rows"].get(label)
    ]
    if after["tasks"] != before["tasks"]:
        changed.append(f"tasks {after['tasks'][len(before['tasks']):]}")
    if after["mail"] != before["mail"]:
        changed.append("mail")
    return changed


def _undefined_values():
    """(model, pk, field, value) for every stored value its field's choices
    do not define. ``scans/{id}/stop/`` stored the status "stopped" and
    ``workflows/{id}/pause/`` "paused": neither model has it."""
    found = []
    for model in apps.get_models():
        meta = model._meta
        if meta.app_label not in _GUARDIAN_APPS:
            continue
        chosen = {
            field.attname: {choice for choice, _ in field.flatchoices}
            for field in meta.concrete_fields
            if field.choices
        }
        if not chosen:
            continue
        for values in model._base_manager.values(meta.pk.attname, *chosen):
            for name, allowed in chosen.items():
                if values[name] not in allowed and values[name] not in (None, ""):
                    found.append(
                        (meta.label, values[meta.pk.attname], name, values[name])
                    )
    return found


def _comparable(body):
    if isinstance(body, dict):
        return {k: _comparable(v) for k, v in body.items() if k not in _VOLATILE}
    if isinstance(body, list):
        return [_comparable(v) for v in body]
    return body


def _answer(response):
    is_json = response.get("Content-Type", "").startswith("application/json")
    body = _comparable(response.json()) if is_json else response.content
    return response.status_code, body


def _context(route):
    team = uuid.uuid4()
    row = tf.make(route.model, team) if route.detail else None
    return Ctx(team, row)


def _of_kind(kind):
    return [
        pytest.param(key, id=key)
        for key, contract in CONTRACTS.items()
        if isinstance(contract, kind) and key in ROUTED
    ]


def _warm_up(api, ctx):
    # The first request of a user mirrors them and records their
    # membership: not what the action under test does.
    api("get", "/api/v1/assets/assets/", ctx.team)


@pytest.mark.django_db
@pytest.mark.parametrize("key", _of_kind(Effect))
def test_an_action_that_answers_success_changed_something(api, dispatched, key):
    route, contract = ROUTED[key], CONTRACTS[key]
    ctx = _context(route)
    contract.prepare(ctx)
    body = contract.body(ctx)
    _warm_up(api, ctx)
    before = _world(dispatched)

    response = api(route.method, route.url(ctx.row) + contract.query, ctx.team, body)

    assert response.status_code == contract.status, response.content[:400]
    after = _world(dispatched)
    assert _changed(before, after), (
        f"{key} answered {response.status_code} {response.content[:200]!r} and "
        "changed nothing guardian keeps or sends: a placeholder (#644)."
    )
    assert not _undefined_values(), f"{key} stored a value its model does not define"


@pytest.mark.django_db
@pytest.mark.parametrize("key", _of_kind(Refuses))
def test_an_action_guardian_cannot_perform_says_so(api, dispatched, key):
    route, contract = ROUTED[key], CONTRACTS[key]
    ctx = _context(route)
    contract.prepare(ctx)
    _warm_up(api, ctx)
    before = _world(dispatched)

    response = api(route.method, route.url(ctx.row), ctx.team, contract.body(ctx))

    assert response.status_code == contract.status, response.content[:400]
    assert response.status_code >= 400
    body = response.json()
    assert body.get("detail"), body
    if contract.code is not None:
        assert body.get("code") == contract.code, body
    assert not _changed(before, _world(dispatched))


@pytest.mark.django_db
@pytest.mark.parametrize("key", _of_kind(Evaluates))
def test_an_evaluation_follows_the_data_and_stores_nothing(api, dispatched, key):
    route, contract = ROUTED[key], CONTRACTS[key]
    ctx = _context(route)
    contract.prepare(ctx)
    _warm_up(api, ctx)
    before = _world(dispatched)

    first = api(route.method, route.url(ctx.row), ctx.team, contract.body(ctx))

    assert first.status_code == 200, first.content[:400]
    assert not _changed(before, _world(dispatched)), key
    contract.vary(ctx)
    second = api(route.method, route.url(ctx.row), ctx.team, contract.body(ctx))
    assert second.status_code == 200, second.content[:400]
    assert _answer(second) != _answer(first), (
        f"{key} answers {first.content[:200]!r} whatever the data: fixed "
        "figures, not an evaluation (#644)."
    )


@pytest.mark.django_db
@pytest.mark.parametrize("key", _of_kind(Reads))
def test_a_read_follows_the_data_and_stores_nothing(api, dispatched, key):
    route, contract = ROUTED[key], CONTRACTS[key]
    ctx = _context(route)
    contract.prepare(ctx)
    _warm_up(api, ctx)
    before = _world(dispatched)

    first = api("get", route.url(ctx.row), ctx.team)

    assert first.status_code == contract.status, first.content[:400]
    assert not _changed(before, _world(dispatched)), f"{key}: a GET stored something"
    if contract.populate is not None:
        contract.populate(ctx)
    else:
        assert not route.detail, f"{key}: a detail read needs a populate"
        tf.make(route.model, ctx.team)
    second = api("get", route.url(ctx.row), ctx.team)
    assert second.status_code == 200, second.content[:400]
    assert _answer(second) != _answer(first), (
        f"{key} answers {first.content[:200]!r} whatever the team's data: "
        "fixed figures, not a reading of it (#644)."
    )


# --- the harness catches a placeholder ---------------------------------------


@pytest.mark.django_db
def test_the_harness_fails_a_placeholder(api, dispatched, monkeypatch):
    """What #644 removed, put back: the check above must not pass it."""
    from apps.remediation.views import RemediationTicketViewSet
    from rest_framework.response import Response

    def placeholder(self, request, pk=None):
        self.get_object().save()  # a save that changes nothing is nothing
        return Response({"status": "success", "message": "Ticket assigned"})

    monkeypatch.setattr(RemediationTicketViewSet, "assign", placeholder)
    key = "RemediationTicketViewSet.assign.post"
    route, contract = ROUTED[key], CONTRACTS[key]
    ctx = _context(route)
    body = contract.body(ctx)
    _warm_up(api, ctx)
    before = _world(dispatched)

    response = api("post", route.url(ctx.row), ctx.team, body)

    assert response.status_code == 200
    assert not _changed(before, _world(dispatched))


# --- the views that are not viewset actions (VIEWS) --------------------------


@pytest.fixture
def local_cache(settings):
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }


@pytest.mark.django_db
def test_health_reports_what_it_checked(local_cache):
    client = Client()
    healthy = client.get("/health/", secure=True)
    assert healthy.status_code == 200, healthy.content[:300]
    assert healthy.json()["checks"]["database"] == {"status": "healthy"}

    # Not a fixed answer: a database that does not answer is reported.
    with mock.patch("apps.core.views.connection.cursor", side_effect=OSError("down")):
        unhealthy = client.get("/health/", secure=True)
    assert unhealthy.status_code == 503
    assert unhealthy.json()["status"] == "unhealthy"
    assert unhealthy.json()["checks"]["database"] == {"status": "unhealthy"}


def test_metrics_serves_the_prometheus_registry_or_says_it_is_off(settings):
    from prometheus_client import Counter

    Counter("guardian_contract_probe", "A metric this test registers").inc()
    client = Client()
    settings.PROMETHEUS_ENABLED = True
    served = client.get("/metrics/", secure=True)
    assert served.status_code == 200
    assert b"guardian_contract_probe_total 1.0" in served.content

    settings.PROMETHEUS_ENABLED = False
    assert client.get("/metrics/", secure=True).status_code == 404
