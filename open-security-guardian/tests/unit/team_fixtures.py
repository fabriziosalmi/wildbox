"""Rows of every model a guardian viewset serves, for a given team (#642).

``make(Model, team_id)`` stores one row of ``Model`` owned by ``team_id``,
with whatever parent rows it needs, also owned by ``team_id``. A model a
viewset serves without a factory here makes the isolation tests fail, so a
new viewset cannot go untested.

The rows' names carry ``MARKER`` and the team id, so a response that leaks
one can be recognized.
"""

import uuid
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.utils import timezone

MARKER = "tenancy-probe"


def _tag(team_id):
    return f"{MARKER}-{str(team_id)[:8]}-{uuid.uuid4().hex[:6]}"


def _quiet():
    """Leave out the Celery work row creation queues from signals."""
    patches = [
        mock.patch("apps.assets.signals.scan_asset_ports"),
        mock.patch("apps.reporting.signals.check_alert_rule"),
        mock.patch("apps.compliance.signals.send_compliance_notification"),
        mock.patch("apps.compliance.signals.calculate_compliance_metrics"),
    ]
    for patch in patches:
        patch.start()
    return patches


def _stop(patches):
    for patch in reversed(patches):
        patch.stop()


def user(team_id=None, username=None):
    """A mirrored gateway user, a member of ``team_id`` if given."""
    from apps.core.models import TeamMembership

    member = User.objects.create(username=username or str(uuid.uuid4()))
    if team_id is not None:
        TeamMembership.objects.create(team_id=team_id, user=member)
    return member


# --- assets ------------------------------------------------------------------


def environment(team_id):
    from apps.assets.models import Environment

    return Environment.objects.create(team_id=team_id, name=_tag(team_id))


def business_function(team_id):
    from apps.assets.models import BusinessFunction

    return BusinessFunction.objects.create(team_id=team_id, name=_tag(team_id))


def asset(team_id, **fields):
    from apps.assets.models import Asset

    fields.setdefault("name", _tag(team_id))
    return Asset.objects.create(team_id=team_id, **fields)


def asset_group(team_id):
    from apps.assets.models import AssetGroup

    return AssetGroup.objects.create(team_id=team_id, name=_tag(team_id))


def discovery_rule(team_id):
    from apps.assets.models import AssetDiscoveryRule

    return AssetDiscoveryRule.objects.create(
        team_id=team_id,
        name=_tag(team_id),
        discovery_type="network_scan",
        target_specification={"networks": ["192.0.2.0/30"]},
        schedule="*/5 * * * *",
    )


def asset_software(team_id):
    from apps.assets.models import AssetSoftware

    return AssetSoftware.objects.create(asset=asset(team_id), name=_tag(team_id))


def asset_port(team_id):
    from apps.assets.models import AssetPort

    return AssetPort.objects.create(
        asset=asset(team_id), port_number=22, protocol="tcp", service=_tag(team_id)
    )


# --- vulnerabilities ---------------------------------------------------------


def vulnerability(team_id, **fields):
    from apps.vulnerabilities.models import Vulnerability

    fields.setdefault("title", _tag(team_id))
    fields.setdefault("description", "d")
    return Vulnerability.objects.create(asset=asset(team_id), **fields)


def vulnerability_template(team_id):
    from apps.vulnerabilities.models import VulnerabilityTemplate

    return VulnerabilityTemplate.objects.create(
        team_id=team_id,
        cve_id=f"CVE-{uuid.uuid4().int % 10**8}",
        title=_tag(team_id),
        description_template="d",
        solution_template="s",
        severity="high",
    )


def vulnerability_assessment(team_id):
    from apps.vulnerabilities.models import VulnerabilityAssessment

    return VulnerabilityAssessment.objects.create(
        vulnerability=vulnerability(team_id), assessment_notes=_tag(team_id)
    )


# --- compliance --------------------------------------------------------------


def framework(team_id):
    from apps.compliance.models import ComplianceFramework

    return ComplianceFramework.objects.create(team_id=team_id, name=_tag(team_id))


def control(team_id, framework_=None):
    from apps.compliance.models import ComplianceControl

    return ComplianceControl.objects.create(
        framework=framework_ or framework(team_id),
        control_id=_tag(team_id)[-12:],
        title=_tag(team_id),
        description="d",
        control_type="technical",
    )


def assessment(team_id, framework_=None):
    from apps.compliance.models import ComplianceAssessment

    return ComplianceAssessment.objects.create(
        team_id=team_id,
        name=_tag(team_id),
        framework=framework_ or framework(team_id),
        assessment_type="internal_audit",
    )


def evidence(team_id):
    from apps.compliance.models import ComplianceEvidence

    owned = assessment(team_id)
    return ComplianceEvidence.objects.create(
        assessment=owned,
        control=control(team_id, owned.framework),
        title=_tag(team_id),
        evidence_type="document",
    )


def result(team_id):
    from apps.compliance.models import ComplianceResult

    owned = assessment(team_id)
    return ComplianceResult.objects.create(
        assessment=owned,
        control=control(team_id, owned.framework),
        status="non_compliant",
        risk_level="high",
        findings=_tag(team_id),
    )


def exception(team_id):
    from apps.compliance.models import ComplianceException

    now = timezone.now()
    return ComplianceException.objects.create(
        team_id=team_id,
        control=control(team_id),
        title=_tag(team_id),
        justification="j",
        status="pending",
        valid_from=now,
        valid_until=now + timedelta(days=10),
        review_date=now - timedelta(days=1),
    )


def compliance_metrics(team_id):
    from apps.compliance.models import ComplianceMetrics

    return ComplianceMetrics.objects.create(
        team_id=team_id,
        framework=framework(team_id),
        metric_date=timezone.now(),
        total_controls=7,
        compliant_controls=3,
        non_compliant_controls=4,
        partially_compliant_controls=0,
        not_applicable_controls=0,
        not_tested_controls=0,
        compliance_percentage=42,
    )


# --- integrations ------------------------------------------------------------


def external_system(team_id):
    from apps.integrations.models import ExternalSystem

    return ExternalSystem.objects.create(
        team_id=team_id,
        name=_tag(team_id),
        system_type="ticketing",
        base_url="https://jira.example.com",
    )


def mapping(team_id, system=None):
    from apps.integrations.models import IntegrationMapping

    return IntegrationMapping.objects.create(
        system=system or external_system(team_id),
        guardian_entity="vulnerability",
        external_entity=_tag(team_id),
    )


def sync_record(team_id):
    from apps.integrations.models import SyncRecord

    owned = mapping(team_id)
    return SyncRecord.objects.create(
        system=owned.system,
        mapping=owned,
        guardian_record_id=uuid.uuid4(),
        external_record_id=_tag(team_id),
        last_sync_direction="guardian_to_external",
    )


def webhook(team_id):
    from apps.integrations.models import WebhookEndpoint

    return WebhookEndpoint.objects.create(
        system=external_system(team_id),
        name=_tag(team_id),
        endpoint_url=f"/hooks/{uuid.uuid4().hex}",
    )


def integration_log(team_id):
    from apps.integrations.models import IntegrationLog

    return IntegrationLog.objects.create(
        system=external_system(team_id), operation="api_call", message=_tag(team_id)
    )


def notification_channel(team_id):
    from apps.integrations.models import NotificationChannel

    return NotificationChannel.objects.create(
        team_id=team_id, name=_tag(team_id), channel_type="slack"
    )


# --- remediation -------------------------------------------------------------


def ticket(team_id):
    from apps.remediation.models import RemediationTicket

    return RemediationTicket.objects.create(
        team_id=team_id,
        title=_tag(team_id),
        description="d",
        system="jira",
        # Unique per (team, system, id): a test may need two tickets in a team.
        external_ticket_id=f"SEC-{uuid.uuid4().hex[:8]}",
        priority="high",
    )


def workflow(team_id):
    from apps.remediation.models import RemediationWorkflow

    return RemediationWorkflow.objects.create(
        vulnerability=vulnerability(team_id),
        title=_tag(team_id),
        remediation_type="patch",
        priority="high",
    )


def step(team_id):
    from apps.remediation.models import RemediationStep

    return RemediationStep.objects.create(
        workflow=workflow(team_id),
        title=_tag(team_id),
        description="d",
        order=1,
        instructions="i",
    )


def comment(team_id):
    from apps.remediation.models import RemediationComment

    return RemediationComment.objects.create(
        workflow=workflow(team_id), author=user(team_id), content=_tag(team_id)
    )


def remediation_template(team_id):
    from apps.remediation.models import RemediationTemplate

    return RemediationTemplate.objects.create(
        team_id=team_id,
        name=_tag(team_id),
        description="d",
        category=_tag(team_id),
        remediation_type="patch",
    )


# --- reporting ---------------------------------------------------------------


def report_template(team_id):
    from apps.reporting.models import ReportTemplate

    return ReportTemplate.objects.create(
        team_id=team_id,
        name=_tag(team_id),
        report_type="vulnerability_summary",
        template_content="x",
        default_format="json",
    )


def report_schedule(team_id):
    from apps.reporting.models import ReportSchedule

    return ReportSchedule.objects.create(
        template=report_template(team_id),
        name=_tag(team_id),
        frequency="daily",
        format="json",
        next_run=timezone.now() - timedelta(minutes=1),
    )


def report(team_id):
    from apps.reporting.models import Report

    return Report.objects.create(
        template=report_template(team_id), name=_tag(team_id), format="json"
    )


def dashboard(team_id):
    from apps.reporting.models import Dashboard

    return Dashboard.objects.create(
        team_id=team_id,
        name=_tag(team_id),
        dashboard_type="security",
        is_public=True,
    )


def widget(team_id):
    from apps.reporting.models import Widget

    return Widget.objects.create(
        team_id=team_id, name=_tag(team_id), widget_type="metric", data_source="assets"
    )


def report_metrics(team_id):
    from apps.reporting.models import ReportMetrics

    return ReportMetrics.objects.create(
        template=report_template(team_id),
        metric_date=timezone.now(),
        generation_count=5,
        success_rate=100,
    )


def alert_rule(team_id, **fields):
    from apps.reporting.models import AlertRule

    fields.setdefault("name", _tag(team_id))
    fields.setdefault("data_source", "vulnerabilities.unresolved")
    fields.setdefault("condition_type", "threshold")
    fields.setdefault("operator", "gt")
    fields.setdefault("threshold_value", 0)
    return AlertRule.objects.create(team_id=team_id, **fields)


# --- scanners ----------------------------------------------------------------


def scanner(team_id):
    from apps.scanners.models import Scanner

    return Scanner.objects.create(
        team_id=team_id,
        name=_tag(team_id),
        scanner_type="nessus",
        base_url="https://scanner.example.com",
    )


def scan_profile(team_id, scanner_=None):
    from apps.scanners.models import ScanProfile

    return ScanProfile.objects.create(
        scanner=scanner_ or scanner(team_id), name=_tag(team_id)
    )


def scan(team_id):
    from apps.scanners.models import Scan

    return Scan.objects.create(
        scanner=scanner(team_id), name=_tag(team_id), total_vulnerabilities_found=3
    )


def scan_result(team_id):
    from apps.scanners.models import ScanResult

    return ScanResult.objects.create(
        scan=scan(team_id),
        plugin_id="1",
        plugin_name=_tag(team_id),
        severity="high",
        host="192.0.2.1",
        description="d",
    )


def scan_schedule(team_id):
    from apps.scanners.models import ScanSchedule

    owned = scanner(team_id)
    return ScanSchedule.objects.create(
        scanner=owned,
        profile=scan_profile(team_id, owned),
        name=_tag(team_id),
        cron_expression="0 2 * * *",
    )


def _factories():
    from apps.assets import models as assets
    from apps.compliance import models as compliance
    from apps.integrations import models as integrations
    from apps.remediation import models as remediation
    from apps.reporting import models as reporting
    from apps.scanners import models as scanners
    from apps.vulnerabilities import models as vulns

    return {
        assets.Environment: environment,
        assets.BusinessFunction: business_function,
        assets.Asset: asset,
        assets.AssetGroup: asset_group,
        assets.AssetDiscoveryRule: discovery_rule,
        assets.AssetSoftware: asset_software,
        assets.AssetPort: asset_port,
        vulns.Vulnerability: vulnerability,
        vulns.VulnerabilityTemplate: vulnerability_template,
        vulns.VulnerabilityAssessment: vulnerability_assessment,
        compliance.ComplianceFramework: framework,
        compliance.ComplianceControl: control,
        compliance.ComplianceAssessment: assessment,
        compliance.ComplianceEvidence: evidence,
        compliance.ComplianceResult: result,
        compliance.ComplianceException: exception,
        compliance.ComplianceMetrics: compliance_metrics,
        integrations.ExternalSystem: external_system,
        integrations.IntegrationMapping: mapping,
        integrations.SyncRecord: sync_record,
        integrations.WebhookEndpoint: webhook,
        integrations.IntegrationLog: integration_log,
        integrations.NotificationChannel: notification_channel,
        remediation.RemediationTicket: ticket,
        remediation.RemediationWorkflow: workflow,
        remediation.RemediationStep: step,
        remediation.RemediationComment: comment,
        remediation.RemediationTemplate: remediation_template,
        reporting.ReportTemplate: report_template,
        reporting.ReportSchedule: report_schedule,
        reporting.Report: report,
        reporting.Dashboard: dashboard,
        reporting.Widget: widget,
        reporting.ReportMetrics: report_metrics,
        reporting.AlertRule: alert_rule,
        scanners.Scanner: scanner,
        scanners.ScanProfile: scan_profile,
        scanners.Scan: scan,
        scanners.ScanResult: scan_result,
        scanners.ScanSchedule: scan_schedule,
    }


def make(model, team_id):
    """One row of ``model`` owned by ``team_id`` (see the module docstring)."""
    factory = _factories().get(model)
    if factory is None:
        raise LookupError(
            f"No factory for {model.__name__}: add one to tests/unit/team_fixtures.py "
            "so the isolation tests cover its viewset."
        )
    patches = _quiet()
    try:
        return factory(team_id)
    finally:
        _stop(patches)
