from celery import shared_task
from django.apps import apps as django_apps
from django.db import transaction
from django.utils import timezone
from django.db.models import Count, Q
from .models import ComplianceAssessment, ComplianceResult, ComplianceMetrics
from apps.core.locks import single_instance
from apps.core.notifications import notify_team_from_template
from apps.core.tenancy import scope_to_team, team_lookup
import logging

logger = logging.getLogger(__name__)

#: Each compliance notification: its subject, its template, and the model
#: of the row it is about. The row's team is who is told.
COMPLIANCE_NOTIFICATIONS = {
    'high_risk_finding': (
        'High Risk Compliance Finding',
        'compliance/high_risk_finding.html',
        'ComplianceResult',
    ),
    'assessment_completed': (
        'Compliance Assessment Completed',
        'compliance/assessment_completed.html',
        'ComplianceAssessment',
    ),
    'assessment_started': (
        'Compliance Assessment Started',
        'compliance/assessment_started.html',
        'ComplianceAssessment',
    ),
    'exception_expiring': (
        'Compliance Exception Expiring Soon',
        'compliance/exception_expiring.html',
        'ComplianceException',
    ),
    'assessment_overdue': (
        'Compliance Assessment Overdue',
        'compliance/assessment_overdue.html',
        'ComplianceAssessment',
    ),
}


@shared_task
def calculate_compliance_metrics(assessment_id):
    """
    Calculate compliance metrics for an assessment
    """
    # One calculation per assessment at a time, the assessment row being the
    # lock. Two running together (the worker takes two tasks at once, and
    # every result saved queues one) could each find no metrics row for today
    # and both insert one; every later update_or_create would then fail.
    with transaction.atomic():
        return _calculate_compliance_metrics(assessment_id)


def _calculate_compliance_metrics(assessment_id):
    try:
        assessment = ComplianceAssessment.objects.select_for_update().get(id=assessment_id)
        results = assessment.results.all()
        
        # Calculate metrics
        total_controls = results.count()
        if total_controls == 0:
            return
            
        compliant = results.filter(status='compliant').count()
        non_compliant = results.filter(status='non_compliant').count()
        partially_compliant = results.filter(status='partially_compliant').count()
        not_applicable = results.filter(status='not_applicable').count()
        not_tested = results.filter(status='not_tested').count()
        
        compliance_percentage = (compliant / total_controls) * 100 if total_controls > 0 else 0
        
        high_risk = results.filter(risk_level__in=['high', 'critical']).count()
        medium_risk = results.filter(risk_level='medium').count()
        low_risk = results.filter(risk_level='low').count()
        
        # Open exceptions of the assessment's team on this framework's
        # controls: a shared framework's controls carry every team's (#642)
        from .models import ComplianceException

        open_exceptions = scope_to_team(
            ComplianceException.objects.filter(
                control__framework=assessment.framework,
                status='approved',
                valid_until__gt=timezone.now(),
            ),
            assessment.team_id,
        ).values('control').distinct().count()
        
        # Create or update metrics: one row per assessment and day. metric_date
        # is a DateTimeField; today's midnight, aware, is the value a bare date
        # was stored as, without the naive-datetime warning on every run.
        today = timezone.localtime().replace(hour=0, minute=0, second=0, microsecond=0)
        metrics, created = ComplianceMetrics.objects.update_or_create(
            framework=assessment.framework,
            assessment=assessment,
            metric_date=today,
            defaults={
                'team_id': assessment.team_id,
                'total_controls': total_controls,
                'compliant_controls': compliant,
                'non_compliant_controls': non_compliant,
                'partially_compliant_controls': partially_compliant,
                'not_applicable_controls': not_applicable,
                'not_tested_controls': not_tested,
                'compliance_percentage': compliance_percentage,
                'high_risk_findings': high_risk,
                'medium_risk_findings': medium_risk,
                'low_risk_findings': low_risk,
                'open_exceptions': open_exceptions,
            }
        )
        
        logger.info(f"Calculated compliance metrics for assessment {assessment.name}: {compliance_percentage}% compliant")
        return metrics.id
        
    except ComplianceAssessment.DoesNotExist:
        logger.error(f"Assessment {assessment_id} not found")
        return None
    except Exception as e:
        logger.error(f"Error calculating compliance metrics: {str(e)}")
        return None


def _moment(data, key):
    """The moment of an event as its caller wrote it: a short text, or ''."""
    value = data.get(key) if isinstance(data, dict) else None
    return str(value)[:40] if value else ''


def _compliance_context(notification_type, row, data):
    """What a compliance e-mail says, read from the row it is about."""
    now = timezone.now()
    if notification_type == 'high_risk_finding':
        return {
            'assessment': row.assessment.name,
            'control': row.control.control_id,
            'status': row.status,
            'risk_level': row.risk_level,
        }
    if notification_type == 'exception_expiring':
        return {
            'exception': row.title,
            'control': row.control.control_id,
            'expiry_date': row.valid_until.isoformat(),
            'days_until_expiry': (row.valid_until - now).days,
        }
    context = {'assessment': row.name, 'framework': row.framework.name}
    if notification_type == 'assessment_overdue':
        context['due_date'] = row.due_date.isoformat() if row.due_date else ''
        context['days_overdue'] = (now - row.due_date).days if row.due_date else 0
    elif notification_type == 'assessment_started':
        context['started_at'] = _moment(data, 'started_at')
    elif notification_type == 'assessment_completed':
        context['completed_at'] = _moment(data, 'completed_at')
    return context


@shared_task
def send_compliance_notification(notification_type, object_id, data):
    """
    Tell a team's owners and admins of a compliance event of that team

    A compliance notification has no recipients of its own: an assessment,
    a result and an exception name none. It was sent to the platform-wide
    DEFAULT_NOTIFICATION_RECIPIENTS, which nothing defined and which would
    have received every team's findings (#678), and then to nobody. It
    goes to the owners and admins of the team the row belongs to, as
    identity lists them when it is sent (#705).

    The team, and everything the e-mail says about the row, are read from
    the row ``object_id`` names when the e-mail is written: a team's e-mail
    cannot carry what a caller passed about another row. From ``data`` only
    the moment of the event is taken (``started_at``, ``completed_at``). A
    notification about a row that is gone, or that belongs to no team, is
    not sent. Returns whether it was sent; when it was not, the log says why.
    """
    try:
        if notification_type not in COMPLIANCE_NOTIFICATIONS:
            logger.error(f"Unknown notification type: {notification_type}")
            return False

        subject, template, model_name = COMPLIANCE_NOTIFICATIONS[notification_type]
        model = django_apps.get_model('compliance', model_name)
        row = model.objects.filter(pk=object_id).first()
        if row is None:
            logger.warning(
                f"Compliance notification not sent ({notification_type}): "
                f"{model_name} {object_id} no longer exists"
            )
            return False
        team_id = model.objects.filter(pk=row.pk).values_list(
            team_lookup(model), flat=True
        )[0]

        delivery = notify_team_from_template(
            team_id,
            subject,
            template,
            _compliance_context(notification_type, row, data or {}),
            kind='compliance',
        )
        return delivery.sent

    except Exception as e:
        logger.error(f"Error sending compliance notification: {str(e)}")
        return False


@shared_task
@single_instance
def check_overdue_assessments():
    """
    Check for overdue assessments and send notifications
    """
    try:
        overdue_assessments = ComplianceAssessment.objects.filter(
            due_date__lt=timezone.now(),
            status__in=['planned', 'in_progress']
        )
        
        count = 0
        for assessment in overdue_assessments:
            send_compliance_notification.delay(
                'assessment_overdue',
                assessment.id,
                {
                    'assessment': assessment.name,
                    'framework': assessment.framework.name,
                    'due_date': assessment.due_date.isoformat(),
                    'days_overdue': (timezone.now() - assessment.due_date).days
                }
            )
            count += 1
            
        logger.info(f"Queued overdue notifications for {count} assessments")
        return count
        
    except Exception as e:
        logger.error(f"Error checking overdue assessments: {str(e)}")
        return 0


@shared_task
@single_instance
def check_expiring_exceptions():
    """
    Check for exceptions expiring in the next 30 days
    """
    try:
        from datetime import timedelta
        from .models import ComplianceException
        
        expiring_soon = ComplianceException.objects.filter(
            valid_until__lte=timezone.now() + timedelta(days=30),
            valid_until__gt=timezone.now(),
            status='approved'
        )
        
        count = 0
        for exception in expiring_soon:
            send_compliance_notification.delay(
                'exception_expiring',
                exception.id,
                {
                    'exception': exception.title,
                    'control': exception.control.control_id,
                    'expiry_date': exception.valid_until.isoformat(),
                    'days_until_expiry': (exception.valid_until - timezone.now()).days
                }
            )
            count += 1
            
        logger.info(f"Queued expiry notifications for {count} exceptions")
        return count
        
    except Exception as e:
        logger.error(f"Error checking expiring exceptions: {str(e)}")
        return 0


@shared_task
def generate_compliance_report(framework_id, report_type='summary', team_id=None):
    """
    Generate a team's compliance report for a framework

    From the team's own metrics and results (#642): a shared framework
    carries every team's. None is the rows without a team.
    """
    try:
        from .models import ComplianceFramework

        framework = scope_to_team(ComplianceFramework.objects.all(), team_id).get(id=framework_id)
        latest_metrics = scope_to_team(
            ComplianceMetrics.objects.filter(framework=framework), team_id
        ).order_by('-metric_date').first()
        
        if not latest_metrics:
            logger.error(f"No metrics found for framework {framework.name}")
            return None
            
        report_data = {
            'framework': framework.name,
            'report_date': timezone.now().isoformat(),
            'compliance_percentage': float(latest_metrics.compliance_percentage),
            'total_controls': latest_metrics.total_controls,
            'compliant_controls': latest_metrics.compliant_controls,
            'non_compliant_controls': latest_metrics.non_compliant_controls,
            'high_risk_findings': latest_metrics.high_risk_findings,
            'open_exceptions': latest_metrics.open_exceptions,
        }
        
        # Generate detailed report if requested
        if report_type == 'detailed':
            # Add detailed control results
            controls_data = []
            for control in framework.controls.all():
                latest_result = scope_to_team(
                    ComplianceResult.objects.filter(control=control), team_id
                ).order_by('-tested_at').first()
                if latest_result:
                    controls_data.append({
                        'control_id': control.control_id,
                        'title': control.title,
                        'status': latest_result.status,
                        'risk_level': latest_result.risk_level,
                        'last_tested': latest_result.tested_at.isoformat() if latest_result.tested_at else None
                    })
            report_data['controls'] = controls_data
            
        logger.info(f"Generated {report_type} compliance report for {framework.name}")
        return report_data
        
    except ComplianceFramework.DoesNotExist:
        logger.error(f"Framework {framework_id} not found")
        return None
    except Exception as e:
        logger.error(f"Error generating compliance report: {str(e)}")
        return None
