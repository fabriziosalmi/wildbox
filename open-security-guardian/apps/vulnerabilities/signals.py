"""
Vulnerability Management Signals

What happens to a vulnerability whenever it is saved, whoever saves it: the
API, a bulk action, a task, a management command.

* its history gets an entry for every tracked field that changed;
* ``resolved_at`` follows its status: set when the status becomes
  "resolved", cleared when it stops being so.

Not here, on purpose: the assignment e-mail. The views that assign a
vulnerability queue it (apps.vulnerabilities.views), once for each
assignment a caller makes. A handler here would queue a second one for
``assign/``, and one for every save that sets an assignee without anybody
having assigned anything: an import, a row copied by a task.
"""

import logging

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

from .models import Vulnerability, VulnerabilityHistory, VulnerabilityStatus

logger = logging.getLogger(__name__)

#: The fields whose changes are written to a vulnerability's history.
TRACKED_FIELDS = (
    'status', 'severity', 'priority', 'assigned_to',
    'assignee_group', 'risk_score', 'cvss_v3_score',
)


def _history_value(value):
    """Render a field value for VulnerabilityHistory.old_value/new_value.

    Both columns are ``TextField(blank=True)`` and NOT NULL, so "no value"
    (a creation, an unassigned user) is stored as ``''``, the empty value
    Django uses for text columns. Writing ``None`` raised IntegrityError and
    made every vulnerability creation fail (#515).
    """
    return '' if value is None else str(value)


def _follow_status(instance, old_status):
    """Make ``resolved_at`` say when the status became "resolved".

    ``close/`` and ``reopen/`` set it themselves. A status changed any
    other way (``PATCH {"status": "resolved"}``, a bulk action, a task)
    left it as it was: a vulnerability resolved through PATCH had no
    ``resolved_at``, so ``stats/`` left it out of the average resolution
    time and ``trends/`` out of the day's ``resolved_count``, and one
    reopened through PATCH kept the date of a resolution it no longer had.
    The code that was meant to do this ran after the list of changes it
    read had been deleted, and never did anything (#724).

    Returns True if it changed ``resolved_at``.
    """
    resolved = VulnerabilityStatus.RESOLVED
    if instance.status == resolved and old_status != resolved:
        if instance.resolved_at is None:
            instance.resolved_at = timezone.now()
            return True
    elif instance.status != resolved and old_status == resolved:
        if instance.resolved_at is not None:
            instance.resolved_at = None
            return True
    return False


@receiver(pre_save, sender=Vulnerability)
def track_vulnerability_changes(sender, instance, update_fields=None, **kwargs):
    """Note what a save changes, for the history, and follow the status."""
    if not instance.pk:
        return
    try:
        old_instance = Vulnerability.objects.get(pk=instance.pk)
    except Vulnerability.DoesNotExist:
        # A new vulnerability (its key is set before the first save),
        # recorded as already resolved: resolved now, as far as guardian
        # knows.
        _follow_status(instance, None)
        return

    changes = []
    for field in TRACKED_FIELDS:
        old_value = getattr(old_instance, field)
        new_value = getattr(instance, field)
        if field == 'assigned_to':
            old_value = old_value.id if old_value else None
            new_value = new_value.id if new_value else None
        if old_value != new_value:
            changes.append({
                'field_name': field,
                'old_value': _history_value(old_value),
                'new_value': _history_value(new_value),
            })
    instance._tracked_changes = changes

    if _follow_status(instance, old_instance.status):
        # A save that names its fields writes only those: resolved_at is
        # written after it (handle_vulnerability_save).
        instance._resolved_at_unsaved = (
            update_fields is not None and 'resolved_at' not in update_fields
        )


@receiver(post_save, sender=Vulnerability)
def handle_vulnerability_save(sender, instance, created, **kwargs):
    """Write the history of a save."""
    if created:
        logger.info("New vulnerability created: %s", instance.pk)

        VulnerabilityHistory.objects.create(
            vulnerability=instance,
            field_name='status',
            old_value=_history_value(None),
            new_value=_history_value(instance.status),
            change_reason='Vulnerability created'
        )
        return

    for change in instance.__dict__.pop('_tracked_changes', ()):
        VulnerabilityHistory.objects.create(
            vulnerability=instance,
            field_name=change['field_name'],
            old_value=change['old_value'],
            new_value=change['new_value'],
            change_reason='Field updated'
        )

    if instance.__dict__.pop('_resolved_at_unsaved', False):
        # update(), not save(): this is the same change, not another one.
        Vulnerability.objects.filter(pk=instance.pk).update(
            resolved_at=instance.resolved_at
        )
