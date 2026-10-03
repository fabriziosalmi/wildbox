from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Q, Sum, Avg
from django.template.loader import render_to_string
from django.conf import settings
import os
import json
import logging
from datetime import timedelta

from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction

from apps.core.locks import single_instance
from apps.core.tenancy import normalize_team_id, scope_to_team
from apps.reporting.models import SUPPORTED_REPORT_FORMATS, SUPPORTED_REPORT_TYPES

logger = logging.getLogger(__name__)


@shared_task
def generate_report(report_id):
    """
    Generate a report based on template and parameters
    """
    try:
        from .models import Report
        
        report = Report.objects.get(id=report_id)
        report.status = 'generating'
        report.save()
        
        start_time = timezone.now()

        # Fail, with the reason, a report that would otherwise be "completed"
        # with placeholder or no data, or in a format that is not written.
        if report.template.report_type not in SUPPORTED_REPORT_TYPES:
            raise ValueError(
                f"{report.template.get_report_type_display()} reports cannot be "
                "generated: they have no data behind them"
            )
        if report.format not in SUPPORTED_REPORT_FORMATS:
            raise ValueError(f"{report.format} reports are not generated yet")

        # Get data based on template type, from the report's team's rows
        # only (#642)
        data = get_report_data(report.template, report.parameters, report.filters)
        
        # Render report content
        content = render_report_content(report, data)
        
        # Save report file
        file_path = save_report_file(report, content)
        
        # Calculate file size and hash
        file_size = os.path.getsize(file_path)
        file_hash = calculate_file_hash(file_path)
        
        # Update report
        generation_time = timezone.now() - start_time
        report.status = 'completed'
        report.file_path = file_path
        report.file_size = file_size
        report.file_hash = file_hash
        report.generation_time = generation_time
        
        # Set expiration (30 days from now)
        report.expires_at = timezone.now() + timedelta(days=30)
        report.save()
        
        # Update metrics
        update_report_metrics.delay(report.template.id)
        
        logger.info(f"Report {report.name} generated successfully in {generation_time}")
        if report.schedule_id:
            notify_scheduled_report(report)
        return report.id
        
    except Exception as e:
        logger.error(f"Error generating report {report_id}: {str(e)}")
        
        # Update report status
        try:
            report = Report.objects.get(id=report_id)
            report.status = 'failed'
            report.error_message = str(e)
            report.save()
        except Exception:
            pass
        
        return None


def get_report_data(template, parameters, filters):
    """
    Get data for report based on template type

    A report holds its template's team's data and nothing else (#642).
    """
    from apps.assets.models import Asset
    from apps.vulnerabilities.models import Vulnerability
    from apps.compliance.models import ComplianceAssessment, ComplianceResult

    team_id = template.team_id
    data = {}
    
    # list(): a QuerySet is lazy, and json.dumps(default=str) wrote its
    # truncated repr instead of the rows.
    if template.report_type == 'vulnerability_summary':
        data['vulnerabilities'] = list(scope_to_team(Vulnerability.objects.filter(
            **apply_filters(filters, 'vulnerability')
        ), team_id).values())
        data['vulnerability_stats'] = get_vulnerability_stats(filters, team_id)
        
    elif template.report_type == 'asset_inventory':
        data['assets'] = list(scope_to_team(Asset.objects.filter(
            **apply_filters(filters, 'asset')
        ), team_id).values())
        data['asset_stats'] = get_asset_stats(filters, team_id)
        
    elif template.report_type == 'compliance_status':
        data['assessments'] = list(scope_to_team(ComplianceAssessment.objects.filter(
            **apply_filters(filters, 'compliance')
        ), team_id).values())
        data['compliance_stats'] = get_compliance_stats(filters, team_id)
        
    elif template.report_type == 'risk_assessment':
        data['risk_data'] = get_risk_assessment_data(filters)
        
    elif template.report_type == 'executive_dashboard':
        data['executive_summary'] = get_executive_summary(filters, team_id)
        
    return data


def apply_filters(filters, data_type):
    """
    Apply filters to queryset based on data type
    """
    query_filters = {}
    
    if 'date_range' in filters:
        start_date = filters['date_range'].get('start')
        end_date = filters['date_range'].get('end')
        if start_date and end_date:
            if data_type == 'vulnerability':
                # Vulnerability has no discovered_at (#548).
                query_filters['first_discovered__range'] = [start_date, end_date]
            elif data_type == 'asset':
                query_filters['created_at__range'] = [start_date, end_date]
            elif data_type == 'compliance':
                query_filters['created_at__range'] = [start_date, end_date]
    
    if 'severity' in filters and data_type == 'vulnerability':
        query_filters['severity__in'] = filters['severity']
    
    if 'asset_type' in filters and data_type == 'asset':
        query_filters['asset_type__in'] = filters['asset_type']
    
    return query_filters


def get_vulnerability_stats(filters, team_id):
    """
    Get a team's vulnerability statistics
    """
    from apps.vulnerabilities.models import Vulnerability

    vulns = scope_to_team(
        Vulnerability.objects.filter(**apply_filters(filters, 'vulnerability')), team_id
    )
    
    return {
        'total_count': vulns.count(),
        'by_severity': dict(vulns.values('severity').annotate(count=Count('id')).values_list('severity', 'count')),
        'by_status': dict(vulns.values('status').annotate(count=Count('id')).values_list('status', 'count')),
        'open_count': vulns.filter(status='open').count(),
        'critical_count': vulns.filter(severity='critical').count(),
    }


def get_asset_stats(filters, team_id):
    """
    Get a team's asset statistics
    """
    from apps.assets.models import Asset

    assets = scope_to_team(Asset.objects.filter(**apply_filters(filters, 'asset')), team_id)
    
    return {
        'total_count': assets.count(),
        'by_type': dict(assets.values('asset_type').annotate(count=Count('id')).values_list('asset_type', 'count')),
        'by_environment': dict(assets.values('environment').annotate(count=Count('id')).values_list('environment', 'count')),
        # Asset has no is_active; its status says whether it is (#548).
        'active_count': assets.filter(status='active').count(),
    }


def get_compliance_stats(filters, team_id):
    """
    Get a team's compliance statistics
    """
    from apps.compliance.models import ComplianceAssessment, ComplianceResult

    assessments = scope_to_team(
        ComplianceAssessment.objects.filter(**apply_filters(filters, 'compliance')), team_id
    )
    results = ComplianceResult.objects.filter(assessment__in=assessments)
    
    return {
        'total_assessments': assessments.count(),
        'completed_assessments': assessments.filter(status='completed').count(),
        'compliance_results': dict(results.values('status').annotate(count=Count('id')).values_list('status', 'count')),
        'high_risk_findings': results.filter(risk_level__in=['high', 'critical']).count(),
    }


def get_risk_assessment_data(filters):
    """
    Get risk assessment data
    """
    # Implementation would depend on risk calculation logic
    return {
        'overall_risk_score': 7.5,
        'risk_trends': [],
        'top_risks': [],
    }


def get_executive_summary(filters, team_id):
    """
    Get a team's executive summary data
    """
    return {
        'key_metrics': {
            'total_assets': get_asset_stats(filters, team_id)['total_count'],
            'total_vulnerabilities': get_vulnerability_stats(filters, team_id)['total_count'],
            'critical_vulnerabilities': get_vulnerability_stats(filters, team_id)['critical_count'],
        },
        'trends': {},
        'recommendations': [],
    }


def render_report_content(report, data):
    """
    Render report content in the report's format.

    JSON is the data itself. Every other format starts from HTML, rendered
    with one template for all report types: the per-type templates this
    looked up ('reporting/<report_type>.html') never existed, and JSON was
    chosen by comparing the report *type* with 'json', which no type is, so
    every report failed with TemplateDoesNotExist (#548).
    """
    if report.format == 'json':
        return json.dumps(data, indent=2, cls=DjangoJSONEncoder)

    return render_to_string(
        'reporting/report.html',
        {
            'report': report,
            'template': report.template,
            'sections': report_sections(data),
        },
    )


def report_sections(data):
    """The report data as titled tables, for the HTML template.

    A list of rows becomes a table with a column per field; a mapping
    becomes a two-column table; nested values are shown as JSON.
    """
    def cell(value):
        if isinstance(value, (dict, list)):
            return json.dumps(value, cls=DjangoJSONEncoder)
        return value

    sections = []
    for key, value in data.items():
        title = key.replace('_', ' ').capitalize()
        if isinstance(value, list):
            columns = list(value[0].keys()) if value and isinstance(value[0], dict) else ['value']
            rows = [
                [cell(row.get(column)) for column in columns] if isinstance(row, dict) else [cell(row)]
                for row in value
            ]
        elif isinstance(value, dict):
            columns = ['name', 'value']
            rows = [[name, cell(item)] for name, item in value.items()]
        else:
            columns = ['value']
            rows = [[cell(value)]]
        sections.append({'title': title, 'columns': columns, 'rows': rows})
    return sections


def reports_root():
    """The directory every generated report is written under."""
    return os.path.join(settings.MEDIA_ROOT, 'reports')


def team_reports_dir(team_id):
    """A team's own report directory (#642).

    Reports of different teams never share a directory. Rows without a
    team (written before guardian kept one) go under "unassigned".
    """
    team_id = normalize_team_id(team_id)
    return os.path.join(reports_root(), str(team_id) if team_id else 'unassigned')


def report_file_is_served(file_path, team_id):
    """True if ``file_path`` is a report file ``team_id`` may download.

    A file in the team's own report directory, or one written before
    reports were kept per team (directly in the reports directory). Never
    a file of another team's directory, nor one outside the reports
    directory, whatever a row says (#642).
    """
    root = os.path.realpath(reports_root())
    path = os.path.realpath(file_path)
    allowed = {root, os.path.realpath(team_reports_dir(team_id))}
    return os.path.dirname(path) in allowed and os.path.isfile(path)


def save_report_file(report, content):
    """
    Save report content to file, in the report's team's directory
    """
    # Create the team's reports directory if it doesn't exist
    reports_dir = team_reports_dir(report.template.team_id)
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename — sanitize format to prevent path traversal
    safe_format = os.path.basename(str(report.format)).replace(os.sep, '')
    if safe_format not in ('pdf', 'html', 'json', 'csv', 'xlsx'):
        safe_format = 'html'
    filename = f"{report.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.{safe_format}"
    file_path = os.path.join(reports_dir, filename)
    # Verify resolved path stays inside reports_dir
    if not os.path.realpath(file_path).startswith(os.path.realpath(reports_dir)):
        raise ValueError("Invalid report filename: path traversal detected")
    
    # Save content based on format
    if report.format == 'json':
        with open(file_path, 'w') as f:
            f.write(content)
    elif report.format == 'html':
        with open(file_path, 'w') as f:
            f.write(content)
    elif report.format == 'pdf':
        # Convert HTML to PDF (would need weasyprint or similar)
        file_path = convert_html_to_pdf(content, file_path)
    elif report.format == 'csv':
        # Convert data to CSV
        file_path = convert_data_to_csv(report, file_path)
    
    return file_path


def convert_html_to_pdf(html_content, output_path):
    """
    Convert HTML content to PDF
    """
    # This would require weasyprint or similar library
    # For now, just save as HTML
    with open(output_path.replace('.pdf', '.html'), 'w') as f:
        f.write(html_content)
    return output_path.replace('.pdf', '.html')


def convert_data_to_csv(report, output_path):
    """
    Convert report data to CSV
    """
    import csv
    
    # Basic CSV conversion - would need more sophisticated logic
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Report', 'Generated', 'Status'])
        writer.writerow([report.name, report.generated_at, report.status])
    
    return output_path


def calculate_file_hash(file_path):
    """
    Calculate SHA-256 hash of file
    """
    import hashlib
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()


@shared_task
def update_report_metrics(template_id):
    """
    Update metrics for a report template
    """
    try:
        from .models import ReportTemplate, ReportMetrics
        
        template = ReportTemplate.objects.get(id=template_id)
        today = timezone.now().date()
        
        # Get reports from today
        today_reports = template.reports.filter(generated_at__date=today)
        
        # Calculate metrics
        generation_count = today_reports.count()
        completed_count = today_reports.filter(status='completed').count()
        success_rate = (completed_count / generation_count * 100) if generation_count > 0 else 0
        
        avg_generation_time = today_reports.filter(
            generation_time__isnull=False
        ).aggregate(avg=Avg('generation_time'))['avg']
        
        total_file_size = today_reports.filter(
            file_size__isnull=False
        ).aggregate(total=Sum('file_size'))['total'] or 0
        
        unique_users = today_reports.values('generated_by').distinct().count()
        error_count = today_reports.filter(status='failed').count()
        
        # Create or update metrics
        metrics, created = ReportMetrics.objects.update_or_create(
            template=template,
            metric_date=today,
            defaults={
                'generation_count': generation_count,
                'avg_generation_time': avg_generation_time,
                'success_rate': success_rate,
                'total_file_size': total_file_size,
                'unique_users': unique_users,
                'download_count': 0,  # Would need to track downloads separately
                'error_count': error_count,
            }
        )
        
        logger.info(f"Updated metrics for template {template.name}: {generation_count} reports generated")
        return metrics.id
        
    except Exception as e:
        logger.error(f"Error updating report metrics: {str(e)}")
        return None


def process_widget_data(widget_config, filters=None, team_id=None):
    """
    Process widget data based on configuration

    Over ``team_id``'s rows only (#642): the dashboard's or widget's team.
    """
    if isinstance(widget_config, dict):
        # Widget config from dashboard
        widget_type = widget_config.get('type')
        data_source = widget_config.get('data_source')
        query_config = widget_config.get('query_config', {})
    else:
        # Widget object
        widget_type = widget_config.widget_type
        data_source = widget_config.data_source
        query_config = widget_config.query_config
    
    # Get data based on data source
    if data_source == 'vulnerabilities':
        return get_vulnerability_widget_data(widget_type, query_config, filters, team_id)
    elif data_source == 'assets':
        return get_asset_widget_data(widget_type, query_config, filters, team_id)
    elif data_source == 'compliance':
        return get_compliance_widget_data(widget_type, query_config, filters, team_id)
    
    return {'error': 'Unknown data source'}


def get_vulnerability_widget_data(widget_type, query_config, filters, team_id=None):
    """
    Get a team's vulnerability data for widgets
    """
    from apps.vulnerabilities.models import Vulnerability

    queryset = scope_to_team(Vulnerability.objects.all(), team_id)
    
    if widget_type == 'metric':
        return {
            'value': queryset.count(),
            'label': 'Total Vulnerabilities'
        }
    elif widget_type == 'chart':
        return {
            'labels': ['Critical', 'High', 'Medium', 'Low'],
            'data': [
                queryset.filter(severity='critical').count(),
                queryset.filter(severity='high').count(),
                queryset.filter(severity='medium').count(),
                queryset.filter(severity='low').count(),
            ]
        }
    
    return {'data': list(queryset.values()[:10])}


def get_asset_widget_data(widget_type, query_config, filters, team_id=None):
    """
    Get a team's asset data for widgets
    """
    from apps.assets.models import Asset

    queryset = scope_to_team(Asset.objects.all(), team_id)
    
    if widget_type == 'metric':
        return {
            'value': queryset.count(),
            'label': 'Total Assets'
        }
    
    return {'data': list(queryset.values()[:10])}


def get_compliance_widget_data(widget_type, query_config, filters, team_id=None):
    """
    Get a team's compliance data for widgets
    """
    from apps.compliance.models import ComplianceResult

    queryset = scope_to_team(ComplianceResult.objects.all(), team_id)
    
    if widget_type == 'gauge':
        compliant = queryset.filter(status='compliant').count()
        total = queryset.count()
        percentage = (compliant / total * 100) if total > 0 else 0
        
        return {
            'value': percentage,
            'max': 100,
            'label': 'Compliance Percentage'
        }
    
    return {'data': list(queryset.values()[:10])}


@shared_task
def check_alert_rule(rule_id, test_mode=False):
    """
    Evaluate an alert rule and notify on a change of state (#549).

    The rule's metric is computed from guardian's data (alert_metrics.py)
    and compared with its threshold. Outside test mode the result is
    recorded on the rule, and a notification goes out when the rule starts
    firing, at most once per settings.ALERT_RENOTIFY_INTERVAL while it keeps
    firing, and once when it recovers. A rule guardian cannot evaluate
    (an unknown metric, a condition other than a threshold) is reported as
    an error, never as a value of 0.
    """
    from .alert_metrics import UnsupportedAlertRule
    from .models import AlertRule

    try:
        rule = AlertRule.objects.get(id=rule_id)
        current_value = get_current_value_for_rule(rule)
    except AlertRule.DoesNotExist:
        logger.error(f"Alert rule {rule_id} not found")
        return {'triggered': False, 'error': 'rule_not_found', 'rule_id': str(rule_id)}
    except UnsupportedAlertRule as exc:
        logger.warning(f"Alert rule {rule_id} cannot be evaluated: {exc}")
        return {'triggered': False, 'error': str(exc), 'rule_id': str(rule_id)}

    triggered = evaluate_alert_condition(rule, current_value)
    result = {
        'triggered': triggered,
        'current_value': current_value,
        'rule_id': str(rule_id),
    }
    if test_mode:
        return result

    notification = record_alert_evaluation(rule.pk, current_value, triggered)
    result['state'] = AlertRule.STATE_FIRING if triggered else AlertRule.STATE_OK
    result['notification'] = notification.kind if notification else None
    if notification is not None:
        deliver_alert_notification(notification)
    return result


def get_current_value_for_rule(rule):
    """
    The current value of the rule's metric.

    This returned 0 for every rule, whatever it measured (#549). It raises
    alert_metrics.UnsupportedAlertRule for a rule that names no supported
    metric or condition.
    """
    from .alert_metrics import current_value

    return current_value(rule)


def record_alert_evaluation(rule_id, current_value, triggered, now=None):
    """
    Record an evaluation on the rule; the notification it calls for, if any.

    Notifies on the transition to firing, again only once
    ALERT_RENOTIFY_INTERVAL has passed since the last notification while
    the rule keeps firing, and on the transition back. The rule row is
    locked for the decision, so two evaluations at once (the sweep and a
    check queued by hand) cannot both see "not firing yet" and both notify.
    """
    from .models import AlertNotification, AlertRule

    now = now or timezone.now()
    interval = settings.ALERT_RENOTIFY_INTERVAL
    with transaction.atomic():
        rule = AlertRule.objects.select_for_update().get(pk=rule_id)
        kind = None
        if triggered:
            if rule.state != AlertRule.STATE_FIRING:
                kind = AlertNotification.KIND_FIRING
                rule.state = AlertRule.STATE_FIRING
                rule.firing_since = now
                rule.last_triggered = now
                rule.trigger_count += 1
            elif interval is not None and (
                rule.last_notified_at is None or now - rule.last_notified_at >= interval
            ):
                kind = AlertNotification.KIND_REPEAT
        elif rule.state == AlertRule.STATE_FIRING:
            kind = AlertNotification.KIND_RESOLVED
            rule.state = AlertRule.STATE_OK
            rule.firing_since = None
        rule.last_value = current_value
        rule.last_evaluated_at = now
        notification = None
        if kind is not None:
            rule.last_notified_at = now
            notification = AlertNotification.objects.create(
                rule=rule,
                kind=kind,
                value=current_value,
                threshold_value=rule.threshold_value,
                operator=rule.operator,
                recipients=alert_recipients(rule),
                created_at=now,
            )
        rule.save(update_fields=[
            'state', 'firing_since', 'last_triggered', 'trigger_count',
            'last_value', 'last_evaluated_at', 'last_notified_at',
        ])
    return notification


def alert_recipients(rule):
    """notification_config['recipients'], else DEFAULT_NOTIFICATION_RECIPIENTS."""
    configured = (rule.notification_config or {}).get('recipients') or []
    return list(configured) or list(getattr(settings, 'DEFAULT_NOTIFICATION_RECIPIENTS', []))


def evaluate_alert_condition(rule, current_value):
    """
    Evaluate if alert condition is met
    """
    if rule.condition_type == 'threshold' and rule.threshold_value is not None:
        if rule.operator == 'gt':
            return current_value > rule.threshold_value
        elif rule.operator == 'lt':
            return current_value < rule.threshold_value
        elif rule.operator == 'eq':
            return current_value == rule.threshold_value
        elif rule.operator == 'gte':
            return current_value >= rule.threshold_value
        elif rule.operator == 'lte':
            return current_value <= rule.threshold_value
        elif rule.operator == 'ne':
            return current_value != rule.threshold_value

    return False


def notify_scheduled_report(report):
    """E-mail a scheduled report's recipients that it is ready (#548).

    This lived in a post_save signal that read ``instance.tracker``, which
    Report does not have, so saving a completed report raised and
    generate_report recorded it as failed. The schedule's recipients were
    never used; without any, DEFAULT_NOTIFICATION_RECIPIENTS are told.
    """
    from apps.core.utils import send_notification

    schedule = report.schedule
    return send_notification(
        subject=f"Scheduled Report Generated: {report.name}",
        template='reporting/report_generated.html',
        context={'report': report, 'schedule': schedule},
        notification_type='report',
        recipients=list(schedule.recipients or []) or None,
    )


def deliver_alert_notification(notification):
    """
    E-mail a recorded notification and record whether it went out.

    Sent after the evaluation is committed, so a slow mail server does not
    hold the rule's row lock. The template this used,
    reporting/alert_notification.html, did not exist, so no alert e-mail
    was ever sent (#549).
    """
    from apps.core.utils import send_notification

    rule = notification.rule
    subjects = {
        'firing': f"Alert: {rule.name}",
        'repeat': f"Alert still firing: {rule.name}",
        'resolved': f"Resolved: {rule.name}",
    }
    delivered = bool(notification.recipients) and send_notification(
        subject=subjects[notification.kind],
        template='reporting/alert_notification.html',
        context={
            'rule': rule,
            'notification': notification,
            'current_value': notification.value,
            'triggered_at': notification.created_at,
        },
        notification_type='alert',
        recipients=notification.recipients,
    )
    if delivered:
        type(notification).objects.filter(pk=notification.pk).update(delivered=True)
        notification.delivered = True
    else:
        logger.warning(
            f"Alert rule {rule.name}: {notification.kind} notification not sent"
            + ("" if notification.recipients else " (no recipients configured)")
        )
    return delivered


@shared_task
@single_instance
def check_all_alert_rules(team_id=None):
    """
    Check active alert rules: every team's (the beat sweep), or one team's
    (POST .../alerts/check_all/ checks the caller's team's rules only, #642)

    Each rule is evaluated over its own team's data (alert_metrics).
    """
    from .models import AlertRule

    active_rules = AlertRule.objects.filter(is_active=True)
    if team_id is not None:
        active_rules = scope_to_team(active_rules, team_id)
    
    results = []
    for rule in active_rules:
        result = check_alert_rule(rule.id)
        results.append(result)
    
    logger.info(f"Checked {len(active_rules)} alert rules")
    return results


@shared_task
def cleanup_expired_reports():
    """
    Clean up expired reports
    """
    from .models import Report
    
    expired_reports = Report.objects.filter(
        expires_at__lt=timezone.now(),
        status='completed'
    )
    
    count = 0
    for report in expired_reports:
        try:
            # Delete file
            if report.file_path and os.path.exists(report.file_path):
                os.remove(report.file_path)
            
            # Delete report record
            report.delete()
            count += 1
            
        except Exception as e:
            logger.error(f"Error deleting expired report {report.id}: {str(e)}")
    
    logger.info(f"Cleaned up {count} expired reports")
    return count
