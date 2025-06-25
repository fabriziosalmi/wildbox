from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone
from .models import Report, ReportSchedule, AlertRule
from .tasks import update_report_metrics, check_alert_rule


@receiver(post_save, sender=Report)
def report_generated(sender, instance, created, **kwargs):
    """
    Handle report generation completion
    """
    if instance.status == 'completed' and instance.tracker.has_changed('status'):
        # Update metrics for the template
        update_report_metrics.delay(instance.template.id)
        
        # Send notification if scheduled report
        if instance.schedule:
            from apps.core.utils import send_notification
            send_notification(
                subject=f"Scheduled Report Generated: {instance.name}",
                template='reporting/report_generated.html',
                context={
                    'report': instance,
                    'schedule': instance.schedule
                },
                notification_type='report'
            )


@receiver(post_save, sender=ReportSchedule)
def schedule_updated(sender, instance, created, **kwargs):
    """
    Handle schedule updates
    """
    if not created and instance.tracker.has_changed('status'):
        if instance.status == 'active':
            # Calculate next run time
            from datetime import timedelta
            from django.utils import timezone
            
            now = timezone.now()
            if instance.frequency == 'daily':
                instance.next_run = now + timedelta(days=1)
            elif instance.frequency == 'weekly':
                instance.next_run = now + timedelta(weeks=1)
            elif instance.frequency == 'monthly':
                instance.next_run = now + timedelta(days=30)
            elif instance.frequency == 'quarterly':
                instance.next_run = now + timedelta(days=90)
            
            instance.save(update_fields=['next_run'])


@receiver(post_save, sender=AlertRule)
def alert_rule_created(sender, instance, created, **kwargs):
    """
    Handle alert rule creation
    """
    if created and instance.is_active:
        # Test the alert rule
        check_alert_rule.delay(instance.id, test_mode=True)
