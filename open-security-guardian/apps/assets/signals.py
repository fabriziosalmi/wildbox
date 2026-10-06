"""
Asset Management Signals

Django signals for asset management events and automation.
"""

from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver
from django.utils import timezone
import logging

from apps.core.schedules import InvalidSchedule, next_cron_run

from .models import Asset, AssetDiscoveryRule
from .networks import check_address
from .tasks import scan_asset_ports

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Asset)
def asset_post_save(sender, instance, created, **kwargs):
    """Handle asset creation and updates"""
    if created:
        logger.info(f"New asset created: {instance.name} ({instance.ip_address})")
        
        # Auto-assign to the groups of the asset's team, by their rules:
        # another team's group never collects it (#642)
        from apps.core.tenancy import scope_to_team

        from .models import AssetGroup
        for group in scope_to_team(AssetGroup.objects.all(), instance.team_id):
            if group.auto_assignment_rules:
                group.apply_auto_assignment_rules()
        
        # If asset has IP and no ports, schedule port scan: unless the
        # address is one guardian does not scan (#748). The asset is stored
        # either way; an inventory lists internal hosts too.
        if instance.ip_address and not instance.ports.exists():
            _, refusal = check_address(instance.ip_address)
            if refusal is None:
                scan_asset_ports.delay(instance.id)
            else:
                logger.info(
                    f"Asset {instance.name} is not port scanned on creation: {refusal}"
                )
    
    else:
        # Update last_seen on any modification
        if instance.last_seen != timezone.now().date():
            Asset.objects.filter(id=instance.id).update(last_seen=timezone.now())


@receiver(pre_delete, sender=Asset)
def asset_pre_delete(sender, instance, **kwargs):
    """Handle asset deletion"""
    logger.info(f"Asset being deleted: {instance.name} ({instance.ip_address})")
    
    # Could trigger cleanup tasks here if needed
    # e.g., removing from external systems, notifications, etc.


@receiver(pre_save, sender=AssetDiscoveryRule)
def discovery_rule_next_run(sender, instance, **kwargs):
    """Keep next_run in step with the rule's schedule (#548).

    apps.core.tasks.dispatch_due_schedules runs a rule when next_run is due
    and moves next_run on in the same conditional UPDATE that claims the
    run. Here next_run is computed afresh when a rule is created, when its
    schedule changes and when it is enabled again, so a rule that was off
    for a week does not run the moment it is switched back on. Otherwise
    next_run and last_run are the database's: a rule loaded before the
    dispatcher moved next_run on and saved afterwards (an edit through the
    API) would write the old value back and run a second time.
    """
    if kwargs.get('raw'):
        return
    update_fields = kwargs.get('update_fields')
    if update_fields is not None and not {'schedule', 'enabled'} & set(update_fields):
        # A partial save that leaves the schedule alone, such as
        # execute_discovery_rule recording last_run.
        return
    previous = None
    if not instance._state.adding and instance.pk is not None:
        previous = (
            AssetDiscoveryRule.objects.filter(pk=instance.pk)
            .values('schedule', 'enabled', 'next_run', 'last_run', 'last_run_result')
            .first()
        )
    if previous is not None:
        # The run's, always: only execute_discovery_rule writes it, in a
        # partial save. A rule read before a run ended and saved after it
        # (an edit through the API) would put the run before back (#775).
        instance.last_run_result = previous['last_run_result']
    rescheduled = (
        previous is None
        or previous['schedule'] != instance.schedule
        or (instance.enabled and not previous['enabled'])
    )
    if not rescheduled:
        instance.next_run = previous['next_run']
        instance.last_run = previous['last_run']
        return
    try:
        instance.next_run = next_cron_run(instance.schedule, timezone.now())
    except InvalidSchedule as exc:
        # The API refuses such a schedule; one written another way (a
        # shell, SQL) is reported by the dispatcher and never run.
        logger.warning(f"Discovery rule {instance.name}: {exc}")
        instance.next_run = None
