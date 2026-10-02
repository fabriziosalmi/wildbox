from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

from apps.core.schedules import next_frequency_run

from .models import ReportSchedule, AlertRule
from .tasks import check_alert_rule


# A completed scheduled report is announced by generate_report itself
# (tasks.notify_scheduled_report). The post_save receiver that did it read
# ``instance.tracker``, which neither Report nor ReportSchedule has, so
# saving a completed report or editing a schedule raised (#548).


@receiver(pre_save, sender=ReportSchedule)
def schedule_reactivated(sender, instance, **kwargs):
    """Skip the runs a schedule missed while it was paused or disabled (#548).

    When a schedule becomes active again with a next_run already past, the
    dispatcher would run it at once for a date long gone; next_run moves to
    the first run after now instead, at the same time of day. A one-off
    schedule keeps its date: switching it back on means "run it".
    """
    if kwargs.get('raw') or instance._state.adding or instance.status != 'active':
        return
    previous = (
        ReportSchedule.objects.filter(pk=instance.pk)
        .values_list('status', flat=True)
        .first()
    )
    if previous in (None, 'active'):
        return
    now = timezone.now()
    if instance.next_run and instance.next_run <= now:
        upcoming = next_frequency_run(instance.frequency, instance.next_run, now)
        if upcoming is not None:
            instance.next_run = upcoming


@receiver(post_save, sender=AlertRule)
def alert_rule_created(sender, instance, created, **kwargs):
    """
    Handle alert rule creation
    """
    if created and instance.is_active:
        # Test the alert rule
        check_alert_rule.delay(instance.id, test_mode=True)
