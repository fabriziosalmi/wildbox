"""Work started when a compliance result or assessment changes (#555).

The receivers used to ask ``instance.tracker.has_changed('status')``, a
django-model-utils FieldTracker that neither model declares (the package is
not installed), so saving an existing result or assessment raised
AttributeError and every update through the API answered 500.

A change is now detected as in the reporting signals' fix (#548): before
the save, ``pre_save`` reads the stored values of the watched fields and
keeps them on the instance; after it, ``post_save`` compares. The tasks are
queued once the transaction commits, so the worker reads the saved row.
"""

from django.db import transaction
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

from .models import ComplianceAssessment, ComplianceResult
from .tasks import calculate_compliance_metrics, send_compliance_notification

# The stored values of the watched fields, read by pre_save.
_PREVIOUS = "_compliance_previous"

# status decides compliance; risk_level the high-risk counts in the metrics
# and the high-risk notification.
RESULT_FIELDS = ("status", "risk_level")
ASSESSMENT_FIELDS = ("status",)

HIGH_RISK_STATUSES = ("non_compliant", "partially_compliant")
HIGH_RISK_LEVELS = ("high", "critical")


def _remember(model, fields, instance, raw):
    """Keep the stored values of ``fields`` on ``instance``; None if new."""
    previous = None
    if not raw and not instance._state.adding:
        previous = model.objects.filter(pk=instance.pk).values(*fields).first()
    setattr(instance, _PREVIOUS, previous)


def _changed(instance, fields, created, update_fields):
    """The watched fields this save wrote with a new value.

    A save that created the row changed all of them. So does one whose
    stored row pre_save did not find (a save forcing an insert, say).
    """
    previous = instance.__dict__.pop(_PREVIOUS, None)
    if update_fields is not None:
        fields = [field for field in fields if field in update_fields]
    if created or previous is None:
        return set(fields)
    return {field for field in fields if getattr(instance, field) != previous[field]}


@receiver(pre_save, sender=ComplianceResult)
def remember_result(sender, instance, raw=False, **kwargs):
    _remember(ComplianceResult, RESULT_FIELDS, instance, raw)


@receiver(pre_save, sender=ComplianceAssessment)
def remember_assessment(sender, instance, raw=False, **kwargs):
    _remember(ComplianceAssessment, ASSESSMENT_FIELDS, instance, raw)


@receiver(post_save, sender=ComplianceResult)
def compliance_result_updated(
    sender, instance, created, raw=False, update_fields=None, **kwargs
):
    """Recalculate the assessment's metrics; announce a high-risk finding."""
    if raw:
        return
    if not _changed(instance, RESULT_FIELDS, created, update_fields):
        return

    assessment_id = str(instance.assessment_id)
    transaction.on_commit(lambda: calculate_compliance_metrics.delay(assessment_id))

    if (
        instance.status in HIGH_RISK_STATUSES
        and instance.risk_level in HIGH_RISK_LEVELS
    ):
        _notify(
            "high_risk_finding",
            instance,
            {
                "assessment": instance.assessment.name,
                "control": instance.control.control_id,
                "status": instance.status,
                "risk_level": instance.risk_level,
            },
        )


@receiver(post_save, sender=ComplianceAssessment)
def compliance_assessment_updated(
    sender, instance, created, raw=False, update_fields=None, **kwargs
):
    """Announce an assessment that starts or completes.

    Completing one also recalculates its final metrics. An assessment
    created as completed (an audit recorded afterwards) has no results yet,
    so it is not announced; one created in progress has started.
    """
    if raw or "status" not in _changed(
        instance, ASSESSMENT_FIELDS, created, update_fields
    ):
        return

    if instance.status == "completed" and not created:
        assessment_id = str(instance.pk)
        transaction.on_commit(lambda: calculate_compliance_metrics.delay(assessment_id))
        _notify(
            "assessment_completed",
            instance,
            {
                "assessment": instance.name,
                "framework": instance.framework.name,
                "completed_at": timezone.now().isoformat(),
            },
        )
    elif instance.status == "in_progress":
        _notify(
            "assessment_started",
            instance,
            {
                "assessment": instance.name,
                "framework": instance.framework.name,
                "started_at": timezone.now().isoformat(),
            },
        )


def _notify(kind, instance, data):
    object_id = str(instance.pk)
    transaction.on_commit(
        lambda: send_compliance_notification.delay(kind, object_id, data)
    )
