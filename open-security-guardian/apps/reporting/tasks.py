from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Q, Sum, Avg
from django.template.loader import render_to_string
from django.conf import settings
import os
import json
import logging
from datetime import timedelta

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
        
        # Get data based on template type
        data = get_report_data(report.template, report.parameters, report.filters)
        
        # Render report content
        content = render_report_content(report.template, data)
        
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
        return report.id
        
    except Exception as e:
        logger.error(f"Error generating report {report_id}: {str(e)}")
        
        # Update report status
        try:
            report = Report.objects.get(id=report_id)
            report.status = 'failed'
            report.error_message = str(e)
            report.save()
        except:
            pass
        
        return None


def get_report_data(template, parameters, filters):
    """
    Get data for report based on template type
    """
    from apps.assets.models import Asset
    from apps.vulnerabilities.models import Vulnerability
    from apps.compliance.models import ComplianceAssessment, ComplianceResult
    
    data = {}
    
    if template.report_type == 'vulnerability_summary':
        data['vulnerabilities'] = Vulnerability.objects.filter(
            **apply_filters(filters, 'vulnerability')
        ).values()
        data['vulnerability_stats'] = get_vulnerability_stats(filters)
        
    elif template.report_type == 'asset_inventory':
        data['assets'] = Asset.objects.filter(
            **apply_filters(filters, 'asset')
        ).values()
        data['asset_stats'] = get_asset_stats(filters)
        
    elif template.report_type == 'compliance_status':
        data['assessments'] = ComplianceAssessment.objects.filter(
            **apply_filters(filters, 'compliance')
        ).values()
        data['compliance_stats'] = get_compliance_stats(filters)
        
    elif template.report_type == 'risk_assessment':
        data['risk_data'] = get_risk_assessment_data(filters)
        
    elif template.report_type == 'executive_dashboard':
        data['executive_summary'] = get_executive_summary(filters)
        
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
                query_filters['discovered_at__range'] = [start_date, end_date]
            elif data_type == 'asset':
                query_filters['created_at__range'] = [start_date, end_date]
            elif data_type == 'compliance':
                query_filters['created_at__range'] = [start_date, end_date]
    
    if 'severity' in filters and data_type == 'vulnerability':
        query_filters['severity__in'] = filters['severity']
    
    if 'asset_type' in filters and data_type == 'asset':
        query_filters['asset_type__in'] = filters['asset_type']
    
    return query_filters


def get_vulnerability_stats(filters):
    """
    Get vulnerability statistics
    """
    from apps.vulnerabilities.models import Vulnerability
    
    vulns = Vulnerability.objects.filter(**apply_filters(filters, 'vulnerability'))
    
    return {
        'total_count': vulns.count(),
        'by_severity': dict(vulns.values('severity').annotate(count=Count('id')).values_list('severity', 'count')),
        'by_status': dict(vulns.values('status').annotate(count=Count('id')).values_list('status', 'count')),
        'open_count': vulns.filter(status='open').count(),
        'critical_count': vulns.filter(severity='critical').count(),
    }


def get_asset_stats(filters):
    """
    Get asset statistics
    """
    from apps.assets.models import Asset
    
    assets = Asset.objects.filter(**apply_filters(filters, 'asset'))
    
    return {
        'total_count': assets.count(),
        'by_type': dict(assets.values('asset_type').annotate(count=Count('id')).values_list('asset_type', 'count')),
        'by_environment': dict(assets.values('environment').annotate(count=Count('id')).values_list('environment', 'count')),
        'active_count': assets.filter(is_active=True).count(),
    }


def get_compliance_stats(filters):
    """
    Get compliance statistics
    """
    from apps.compliance.models import ComplianceAssessment, ComplianceResult
    
    assessments = ComplianceAssessment.objects.filter(**apply_filters(filters, 'compliance'))
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


def get_executive_summary(filters):
    """
    Get executive summary data
    """
    return {
        'key_metrics': {
            'total_assets': get_asset_stats(filters)['total_count'],
            'total_vulnerabilities': get_vulnerability_stats(filters)['total_count'],
            'critical_vulnerabilities': get_vulnerability_stats(filters)['critical_count'],
        },
        'trends': {},
        'recommendations': [],
    }


def render_report_content(template, data):
    """
    Render report content using template
    """
    if template.report_type == 'json':
        return json.dumps(data, indent=2, default=str)
    
    # For other formats, render HTML template
    html_content = render_to_string(
        f'reporting/{template.report_type}.html',
        {'data': data, 'template': template}
    )
    
    return html_content


def save_report_file(report, content):
    """
    Save report content to file
    """
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename
    filename = f"{report.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.{report.format}"
    file_path = os.path.join(reports_dir, filename)
    
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


def process_widget_data(widget_config, filters=None):
    """
    Process widget data based on configuration
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
        return get_vulnerability_widget_data(widget_type, query_config, filters)
    elif data_source == 'assets':
        return get_asset_widget_data(widget_type, query_config, filters)
    elif data_source == 'compliance':
        return get_compliance_widget_data(widget_type, query_config, filters)
    
    return {'error': 'Unknown data source'}


def get_vulnerability_widget_data(widget_type, query_config, filters):
    """
    Get vulnerability data for widgets
    """
    from apps.vulnerabilities.models import Vulnerability
    
    queryset = Vulnerability.objects.all()
    
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


def get_asset_widget_data(widget_type, query_config, filters):
    """
    Get asset data for widgets
    """
    from apps.assets.models import Asset
    
    queryset = Asset.objects.all()
    
    if widget_type == 'metric':
        return {
            'value': queryset.count(),
            'label': 'Total Assets'
        }
    
    return {'data': list(queryset.values()[:10])}


def get_compliance_widget_data(widget_type, query_config, filters):
    """
    Get compliance data for widgets
    """
    from apps.compliance.models import ComplianceResult
    
    queryset = ComplianceResult.objects.all()
    
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
    Check if an alert rule should trigger
    """
    try:
        from .models import AlertRule
        
        rule = AlertRule.objects.get(id=rule_id)
        
        # Get current value based on data source
        current_value = get_current_value_for_rule(rule)
        
        # Check condition
        triggered = evaluate_alert_condition(rule, current_value)
        
        result = {
            'triggered': triggered,
            'current_value': current_value,
            'rule_id': rule_id
        }
        
        if triggered and not test_mode:
            # Send notification
            send_alert_notification(rule, current_value)
            
            # Update rule
            rule.last_triggered = timezone.now()
            rule.trigger_count += 1
            rule.save()
        
        return result
        
    except Exception as e:
        logger.error(f"Error checking alert rule {rule_id}: {str(e)}")
        return {'triggered': False, 'error': str(e)}


def get_current_value_for_rule(rule):
    """
    Get current value for alert rule evaluation
    """
    # This would be implemented based on the specific data source
    # For now, return a placeholder
    return 0


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


def send_alert_notification(rule, current_value):
    """
    Send alert notification
    """
    from apps.core.utils import send_notification
    
    send_notification(
        subject=f"Alert: {rule.name}",
        template='reporting/alert_notification.html',
        context={
            'rule': rule,
            'current_value': current_value,
            'triggered_at': timezone.now()
        },
        notification_type='alert'
    )


@shared_task
def check_all_alert_rules():
    """
    Check all active alert rules
    """
    from .models import AlertRule
    
    active_rules = AlertRule.objects.filter(is_active=True)
    
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
