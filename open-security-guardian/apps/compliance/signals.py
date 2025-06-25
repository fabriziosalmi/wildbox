from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone
from .models import ComplianceAssessment, ComplianceResult, ComplianceMetrics
from .tasks import calculate_compliance_metrics, send_compliance_notification


@receiver(post_save, sender=ComplianceResult)
def compliance_result_updated(sender, instance, created, **kwargs):
    """
    Update compliance metrics when a result is created or updated
    """
    if created or instance.tracker.has_changed('status'):
        # Trigger metrics calculation for the assessment
        calculate_compliance_metrics.delay(instance.assessment.id)
        
        # Send notification for non-compliant results
        if instance.status in ['non_compliant', 'partially_compliant'] and instance.risk_level in ['high', 'critical']:
            send_compliance_notification.delay(
                'high_risk_finding',
                instance.id,
                {
                    'assessment': instance.assessment.name,
                    'control': instance.control.control_id,
                    'status': instance.status,
                    'risk_level': instance.risk_level
                }
            )


@receiver(post_save, sender=ComplianceAssessment)
def compliance_assessment_updated(sender, instance, created, **kwargs):
    """
    Handle assessment status changes
    """
    if not created and instance.tracker.has_changed('status'):
        if instance.status == 'completed':
            # Calculate final metrics
            calculate_compliance_metrics.delay(instance.id)
            
            # Send completion notification
            send_compliance_notification.delay(
                'assessment_completed',
                instance.id,
                {
                    'assessment': instance.name,
                    'framework': instance.framework.name,
                    'completed_at': timezone.now().isoformat()
                }
            )
        elif instance.status == 'in_progress' and created:
            # Send start notification
            send_compliance_notification.delay(
                'assessment_started',
                instance.id,
                {
                    'assessment': instance.name,
                    'framework': instance.framework.name,
                    'started_at': timezone.now().isoformat()
                }
            )
