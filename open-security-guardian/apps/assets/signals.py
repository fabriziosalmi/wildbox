"""
Asset Management Signals

Django signals for asset management events and automation.
"""

from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone
import logging

from .models import Asset, AssetDiscoveryRule
from .tasks import scan_asset_ports

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Asset)
def asset_post_save(sender, instance, created, **kwargs):
    """Handle asset creation and updates"""
    if created:
        logger.info(f"New asset created: {instance.name} ({instance.ip_address})")
        
        # Auto-assign to groups based on rules
        from .models import AssetGroup
        for group in AssetGroup.objects.all():
            if group.auto_assignment_rules:
                group.apply_auto_assignment_rules()
        
        # If asset has IP and no ports, schedule port scan
        if instance.ip_address and not instance.ports.exists():
            scan_asset_ports.delay(instance.id)
    
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


@receiver(post_save, sender=AssetDiscoveryRule)
def discovery_rule_post_save(sender, instance, created, **kwargs):
    """Handle discovery rule creation and updates"""
    if created:
        logger.info(f"New discovery rule created: {instance.name}")
        
        # Schedule next run based on cron schedule
        # This would typically be handled by a cron job scheduler like celery-beat
        if instance.enabled:
            from .tasks import execute_discovery_rule
            # Could schedule the first run here
            pass
