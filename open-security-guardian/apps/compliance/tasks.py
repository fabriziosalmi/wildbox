from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Q
from .models import ComplianceAssessment, ComplianceResult, ComplianceMetrics
from apps.core.utils import send_notification
import logging

logger = logging.getLogger(__name__)


@shared_task
def calculate_compliance_metrics(assessment_id):
    """
    Calculate compliance metrics for an assessment
    """
    try:
        assessment = ComplianceAssessment.objects.get(id=assessment_id)
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
        
        # Get open exceptions for this framework
        open_exceptions = assessment.framework.controls.filter(
            exceptions__status='approved',
            exceptions__valid_until__gt=timezone.now()
        ).distinct().count()
        
        # Create or update metrics
        metrics, created = ComplianceMetrics.objects.update_or_create(
            framework=assessment.framework,
            assessment=assessment,
            metric_date=timezone.now().date(),
            defaults={
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


@shared_task
def send_compliance_notification(notification_type, object_id, data):
    """
    Send compliance-related notifications
    """
    try:
        notification_templates = {
            'high_risk_finding': {
                'subject': 'High Risk Compliance Finding',
                'template': 'compliance/high_risk_finding.html'
            },
            'assessment_completed': {
                'subject': 'Compliance Assessment Completed',
                'template': 'compliance/assessment_completed.html'
            },
            'assessment_started': {
                'subject': 'Compliance Assessment Started',
                'template': 'compliance/assessment_started.html'
            },
            'exception_expiring': {
                'subject': 'Compliance Exception Expiring Soon',
                'template': 'compliance/exception_expiring.html'
            },
            'assessment_overdue': {
                'subject': 'Compliance Assessment Overdue',
                'template': 'compliance/assessment_overdue.html'
            }
        }
        
        if notification_type not in notification_templates:
            logger.error(f"Unknown notification type: {notification_type}")
            return False
            
        template_config = notification_templates[notification_type]
        
        # Send notification using core utility
        return send_notification(
            subject=template_config['subject'],
            template=template_config['template'],
            context=data,
            notification_type='compliance'
        )
        
    except Exception as e:
        logger.error(f"Error sending compliance notification: {str(e)}")
        return False


@shared_task
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
            
        logger.info(f"Sent overdue notifications for {count} assessments")
        return count
        
    except Exception as e:
        logger.error(f"Error checking overdue assessments: {str(e)}")
        return 0


@shared_task
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
            
        logger.info(f"Sent expiry notifications for {count} exceptions")
        return count
        
    except Exception as e:
        logger.error(f"Error checking expiring exceptions: {str(e)}")
        return 0


@shared_task
def generate_compliance_report(framework_id, report_type='summary'):
    """
    Generate compliance reports
    """
    try:
        from .models import ComplianceFramework
        
        framework = ComplianceFramework.objects.get(id=framework_id)
        latest_metrics = framework.metrics.order_by('-metric_date').first()
        
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
                latest_result = control.results.order_by('-tested_at').first()
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
