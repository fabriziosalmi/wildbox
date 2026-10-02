"""Run the schedules users define through the API (#548).

Asset discovery rules and report schedules were stored with a schedule and
a next_run, and nothing ever read them. ``dispatch_due_schedules`` is one
periodic task, sent by guardian-beat (guardian/schedule.py), that finds
what is due and queues its work on that work's own queue:

* an enabled discovery rule of an implemented type, by its cron
  ``schedule``: ``apps.assets.tasks.execute_discovery_rule``;
* an active report schedule, by its ``frequency``: a Report row and
  ``apps.reporting.tasks.generate_report``. A one-off schedule is disabled
  once it has run.

Scan schedules are not dispatched: guardian cannot start a scan on an
external scanner, and the API refuses them (apps/scanners/views.py).

One task for both kinds rather than one each: they answer the same
question on the same timer, and one entry means one interval to tune
(GUARDIAN_SCHEDULE_USER_SCHEDULES) and one lock. Each kind runs on its own,
so a failure in one does not stop the other.

Exactly once per due time
-------------------------
A run is claimed with one conditional UPDATE: "set next_run to the following
run where the row still has the next_run I read". The database applies it
to a row once; a second sweep that read the same row -- a manual run racing
the scheduled one, or a sweep overlapping the previous one despite the lock
-- updates nothing and queues nothing. The work is queued only after the
claim; if queuing fails (the broker is down), the claim is undone and the
next sweep tries again. A sweep killed between the claim and the queuing
loses that one run: at most once, rather than a chance of twice.
"""

import logging

from apps.core.locks import single_instance
from apps.core.schedules import InvalidSchedule, next_cron_run, next_frequency_run
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


def claim(model, pk, due, values, **conditions):
    """Atomically move a schedule on from ``due``; True if this caller did."""
    claimed = model.objects.filter(pk=pk, next_run=due, **conditions).update(**values)
    return claimed == 1


def dispatch_discovery_rules(now):
    from apps.assets.models import IMPLEMENTED_DISCOVERY_TYPES, AssetDiscoveryRule
    from apps.assets.tasks import execute_discovery_rule

    rules = AssetDiscoveryRule.objects.filter(
        enabled=True, discovery_type__in=IMPLEMENTED_DISCOVERY_TYPES
    )
    outcome = {"dispatched": [], "invalid": [], "scheduled": 0}

    # A rule saved without a next_run (created before #548, or with a
    # schedule that did not parse) gets one now; it runs when that is due.
    for rule in rules.filter(next_run__isnull=True).only("pk", "name", "schedule"):
        try:
            upcoming = next_cron_run(rule.schedule, now)
        except InvalidSchedule as exc:
            logger.warning("Discovery rule %s is not run: %s", rule.name, exc)
            outcome["invalid"].append(rule.pk)
            continue
        if AssetDiscoveryRule.objects.filter(pk=rule.pk, next_run__isnull=True).update(
            next_run=upcoming
        ):
            outcome["scheduled"] += 1

    due_rules = rules.filter(next_run__lte=now).only(
        "pk", "name", "schedule", "next_run", "last_run"
    )
    for rule in due_rules:
        try:
            upcoming = next_cron_run(rule.schedule, now)
        except InvalidSchedule as exc:
            logger.warning("Discovery rule %s is not run: %s", rule.name, exc)
            outcome["invalid"].append(rule.pk)
            continue
        values = {"next_run": upcoming, "last_run": now}
        if not claim(AssetDiscoveryRule, rule.pk, rule.next_run, values, enabled=True):
            continue
        try:
            execute_discovery_rule.delay(rule.pk)
        except Exception:
            claim(
                AssetDiscoveryRule,
                rule.pk,
                upcoming,
                {"next_run": rule.next_run, "last_run": rule.last_run},
            )
            raise
        logger.info("Discovery rule %s dispatched; next run %s", rule.name, upcoming)
        outcome["dispatched"].append(rule.pk)
    return outcome


def dispatch_report_schedules(now):
    from apps.reporting.models import (
        SUPPORTED_REPORT_FORMATS,
        SUPPORTED_REPORT_TYPES,
        Report,
        ReportSchedule,
    )
    from apps.reporting.tasks import generate_report

    due = ReportSchedule.objects.filter(status="active", next_run__lte=now)
    outcome = {"dispatched": [], "invalid": []}
    # Schedules the API refuses today but that may predate the check.
    unsupported = due.exclude(
        template__report_type__in=SUPPORTED_REPORT_TYPES,
        format__in=SUPPORTED_REPORT_FORMATS,
    )
    for schedule in unsupported.only("pk", "name"):
        logger.warning(
            "Report schedule %s is not run: its report type or format cannot "
            "be generated",
            schedule.name,
        )
        outcome["invalid"].append(str(schedule.pk))

    supported = due.filter(
        template__report_type__in=SUPPORTED_REPORT_TYPES,
        format__in=SUPPORTED_REPORT_FORMATS,
    ).select_related("template")
    for schedule in supported:
        try:
            upcoming = next_frequency_run(schedule.frequency, schedule.next_run, now)
        except InvalidSchedule as exc:
            logger.warning("Report schedule %s is not run: %s", schedule.name, exc)
            outcome["invalid"].append(str(schedule.pk))
            continue
        values = {"last_run": now}
        if upcoming is None:
            values["status"] = "disabled"  # a one-off schedule has run
        else:
            values["next_run"] = upcoming
        if not claim(
            ReportSchedule, schedule.pk, schedule.next_run, values, status="active"
        ):
            continue
        report = Report.objects.create(
            name=f"{schedule.name} - {now:%Y-%m-%d %H:%M}",
            template=schedule.template,
            schedule=schedule,
            format=schedule.format,
            parameters=schedule.parameters,
            filters=schedule.filters,
            generated_by_id=schedule.created_by_id,
        )
        try:
            generate_report.delay(report.pk)
        except Exception:
            report.delete()
            undo = {"last_run": schedule.last_run, "status": "active"}
            undo["next_run"] = schedule.next_run
            ReportSchedule.objects.filter(pk=schedule.pk, last_run=now).update(**undo)
            raise
        logger.info(
            "Report schedule %s dispatched (report %s); next run %s",
            schedule.name,
            report.pk,
            upcoming or "none, it ran once",
        )
        outcome["dispatched"].append(str(schedule.pk))
    return outcome


DISPATCHERS = (
    ("discovery_rules", dispatch_discovery_rules),
    ("report_schedules", dispatch_report_schedules),
)


@shared_task
@single_instance
def dispatch_due_schedules():
    """Queue the work of every user-defined schedule that is due."""
    now = timezone.now()
    result = {}
    failure = None
    for kind, dispatch in DISPATCHERS:
        try:
            result[kind] = dispatch(now)
        except Exception as exc:
            logger.exception("Dispatching %s failed", kind)
            result[kind] = {"error": str(exc)}
            failure = failure or exc
    if failure is not None:
        # After the other kinds have had their turn; the task is reported
        # as failed rather than as a success with an error inside.
        raise failure
    return result
