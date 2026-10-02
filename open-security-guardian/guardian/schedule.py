"""guardian's periodic tasks, as loaded into django-celery-beat (#545).

Several guardian tasks only make sense on a timer: they sweep "every overdue
vulnerability", "every active alert rule", "every report past its expiry".
Nothing ever scheduled them. ``build_beat_schedule()`` returns the schedule
as ``CELERY_BEAT_SCHEDULE``; guardian-beat runs django-celery-beat's
DatabaseScheduler, which writes each entry into a ``PeriodicTask`` row when
it starts (creating or updating it by name), so the schedule is versioned
here and still visible in the Django admin.

Every entry can be changed without a rebuild through its environment
variable, read by guardian-beat when it starts:

* an integer: run every that many seconds, e.g. ``900``;
* five crontab fields, ``minute hour day-of-month month day-of-week``, in
  ``CELERY_TIMEZONE`` (UTC unless set), e.g. ``"0 3 * * *"``;
* ``off``: keep the row but disable it. Removing an entry from this file
  would not do that: the scheduler only creates and updates rows, so the
  old row would go on running.

An edit made in the admin to one of these rows lasts until guardian-beat
restarts, when the value from here is written back. Change the variable.

Each run also expires: a run still queued when the next one is due is
dropped instead of executing late (``expire_seconds``). For an interval
that is the interval; for the daily and weekly crontab entries, one hour --
each run redoes the whole sweep, so a run missed while the worker was down
is covered by the next one rather than replayed in a burst when it comes
back (several identical reminder e-mails at once, for instance).
"""

import os
from datetime import timedelta

from celery.schedules import crontab
from django.core.exceptions import ImproperlyConfigured

# Expiry of a crontab run: see the module docstring.
CRONTAB_EXPIRY_SECONDS = 3600

# (entry name, task, environment variable, default). The reasons for each
# default are in docs/guides/deployment.md ("guardian's scheduled tasks").
PERIODIC_TASKS = (
    (
        "vulnerabilities.check_sla_violations",
        "apps.vulnerabilities.tasks.check_sla_violations",
        "GUARDIAN_SCHEDULE_SLA_CHECK",
        "900",
    ),
    (
        "reporting.check_all_alert_rules",
        "apps.reporting.tasks.check_all_alert_rules",
        "GUARDIAN_SCHEDULE_ALERT_RULES",
        "900",
    ),
    (
        "vulnerabilities.update_vulnerability_risk_scores",
        "apps.vulnerabilities.tasks.update_vulnerability_risk_scores",
        "GUARDIAN_SCHEDULE_RISK_SCORES",
        "0 2 * * *",
    ),
    (
        "reporting.cleanup_expired_reports",
        "apps.reporting.tasks.cleanup_expired_reports",
        "GUARDIAN_SCHEDULE_REPORT_CLEANUP",
        "0 3 * * *",
    ),
    (
        "vulnerabilities.cleanup_old_vulnerability_history",
        "apps.vulnerabilities.tasks.cleanup_old_vulnerability_history",
        "GUARDIAN_SCHEDULE_HISTORY_CLEANUP",
        "30 3 * * *",
    ),
    (
        "assets.update_asset_inventory",
        "apps.assets.tasks.update_asset_inventory",
        "GUARDIAN_SCHEDULE_ASSET_INVENTORY",
        "30 4 * * *",
    ),
    (
        "compliance.check_overdue_assessments",
        "apps.compliance.tasks.check_overdue_assessments",
        "GUARDIAN_SCHEDULE_OVERDUE_ASSESSMENTS",
        "0 8 * * *",
    ),
    (
        "compliance.check_expiring_exceptions",
        "apps.compliance.tasks.check_expiring_exceptions",
        "GUARDIAN_SCHEDULE_EXPIRING_EXCEPTIONS",
        "0 8 * * 1",
    ),
    # The schedules users define (discovery rules, report schedules): their
    # cron fields have a one-minute resolution, so a sweep every minute
    # starts each run within a minute of its time (#548).
    (
        "core.dispatch_due_schedules",
        "apps.core.tasks.dispatch_due_schedules",
        "GUARDIAN_SCHEDULE_USER_SCHEDULES",
        "60",
    ),
)


def parse_schedule(value, variable):
    """Return (schedule, expire_seconds) for ``value``; (None, None) for off.

    Raises ImproperlyConfigured for anything else, so a typo stops
    guardian-beat at start-up instead of silently keeping a default.
    """
    text = value.strip()
    if text.lower() == "off":
        return None, None
    if text.isdigit():
        seconds = int(text)
        if seconds <= 0:
            raise ImproperlyConfigured(f"{variable}: the interval must be positive")
        return timedelta(seconds=seconds), seconds
    fields = text.split()
    if len(fields) != 5:
        raise ImproperlyConfigured(
            f"{variable}={value!r}: expected a number of seconds, five crontab "
            "fields (minute hour day-of-month month day-of-week) or 'off'"
        )
    minute, hour, day_of_month, month_of_year, day_of_week = fields
    try:
        schedule = crontab(
            minute=minute,
            hour=hour,
            day_of_month=day_of_month,
            month_of_year=month_of_year,
            day_of_week=day_of_week,
        )
    except ValueError as exc:
        raise ImproperlyConfigured(f"{variable}={value!r}: {exc}") from exc
    return schedule, CRONTAB_EXPIRY_SECONDS


# A firing alert rule notifies when it starts firing, when it recovers, and
# in between at most once per this interval (#549). A day: the alert-rule
# sweep runs every 15 minutes, and a rule notified on every run would send
# 96 e-mails a day for one condition; a condition still true a day later is
# worth one reminder, as the SLA check reminds once per vulnerability per
# day. 'off' sends no reminders at all.
ALERT_RENOTIFY_VARIABLE = "GUARDIAN_ALERT_RENOTIFY_INTERVAL"
ALERT_RENOTIFY_DEFAULT = "86400"


def alert_renotify_interval(environ=None):
    """The re-notification interval as a timedelta; None for 'off'.

    Raises ImproperlyConfigured for anything but a positive number of
    seconds or 'off', so a typo stops guardian at start-up.
    """
    environ = os.environ if environ is None else environ
    value = (environ.get(ALERT_RENOTIFY_VARIABLE) or ALERT_RENOTIFY_DEFAULT).strip()
    if value.lower() == "off":
        return None
    if not value.isdigit() or int(value) <= 0:
        raise ImproperlyConfigured(
            f"{ALERT_RENOTIFY_VARIABLE}={value!r}: expected a positive number of "
            "seconds or 'off'"
        )
    return timedelta(seconds=int(value))


def build_beat_schedule(environ=None):
    """The CELERY_BEAT_SCHEDULE mapping, with overrides from ``environ``.

    An empty variable means the default, so compose can pass every variable
    through as ``${NAME:-}``.
    """
    environ = os.environ if environ is None else environ
    entries = {}
    for name, task, variable, default in PERIODIC_TASKS:
        value = environ.get(variable) or default
        schedule, expire_seconds = parse_schedule(value, variable)
        entry = {
            "task": task,
            "description": f"{task}; set by {variable} (guardian/schedule.py)",
        }
        if schedule is None:
            # A schedule is still required to write the row; the default
            # one is kept, and the row is disabled.
            schedule, expire_seconds = parse_schedule(default, variable)
            entry["enabled"] = False
        else:
            entry["enabled"] = True
        entry["schedule"] = schedule
        entry["options"] = {"expire_seconds": expire_seconds}
        entries[name] = entry
    return entries
