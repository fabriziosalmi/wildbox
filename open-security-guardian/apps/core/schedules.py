"""When a user-defined schedule is next due (#548).

Two kinds of schedule are defined through the API and run by
``apps.core.tasks.dispatch_due_schedules``:

* an asset discovery rule's ``schedule``: five crontab fields, ``minute hour
  day-of-month month day-of-week``, in ``CELERY_TIMEZONE`` (UTC unless set),
  the same syntax and meaning as the ``GUARDIAN_SCHEDULE_*`` variables
  (guardian/schedule.py). They are parsed by Celery's ``crontab``, so a day
  must match both day fields when both are restricted (Celery's rule;
  Vixie cron runs when either matches);
* a report schedule's ``frequency``: once, daily, weekly, monthly or
  quarterly, counted from the ``next_run`` the user chose.

When a schedule is overdue by more than one period -- guardian was down for
a week, say -- it runs once and its next run is the first one after now:
missed runs are skipped, not replayed in a burst.
"""

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from celery.schedules import ParseException, crontab
from dateutil.relativedelta import relativedelta
from django.conf import settings

# An expression that matches no minute in this many years never runs
# ("0 0 31 2 *", February 31st). Four years cover every leap day; with both
# day fields restricted a match can be rarer still (February 29th on a
# Monday), and such a schedule is refused too.
HORIZON_DAYS = 4 * 366


class InvalidSchedule(ValueError):
    """A cron expression that cannot be parsed or never matches."""


def _parse(expression):
    if not isinstance(expression, str):
        raise InvalidSchedule("the schedule must be a string")
    fields = expression.split()
    if len(fields) != 5:
        raise InvalidSchedule(
            f"{expression!r}: expected five crontab fields "
            "(minute hour day-of-month month day-of-week)"
        )
    minute, hour, day_of_month, month_of_year, day_of_week = fields
    try:
        return crontab(
            minute=minute,
            hour=hour,
            day_of_month=day_of_month,
            month_of_year=month_of_year,
            day_of_week=day_of_week,
        )
    except (ValueError, ParseException) as exc:
        raise InvalidSchedule(f"{expression!r}: {exc}") from exc


def schedule_timezone():
    return ZoneInfo(getattr(settings, "CELERY_TIMEZONE", None) or "UTC")


def next_cron_run(expression, after):
    """The first minute matching ``expression`` strictly after ``after``.

    ``after`` is an aware datetime; the result is aware, in the schedule's
    time zone. Raises InvalidSchedule for an expression that does not parse
    or matches nothing within HORIZON_DAYS.
    """
    spec = _parse(expression)
    zone = schedule_timezone()
    start = after.astimezone(zone).replace(second=0, microsecond=0)
    start += timedelta(minutes=1)
    hours = sorted(spec.hour)
    minutes = sorted(spec.minute)
    day = start.date()
    for offset in range(HORIZON_DAYS + 1):
        candidate_day = day + timedelta(days=offset)
        if (
            candidate_day.month not in spec.month_of_year
            or candidate_day.day not in spec.day_of_month
            # Celery numbers days of the week from Sunday = 0.
            or candidate_day.isoweekday() % 7 not in spec.day_of_week
        ):
            continue
        for hour in hours:
            for minute in minutes:
                candidate = datetime(
                    candidate_day.year,
                    candidate_day.month,
                    candidate_day.day,
                    hour,
                    minute,
                    tzinfo=zone,
                )
                if candidate >= start:
                    return candidate
    raise InvalidSchedule(
        f"{expression!r} matches no time in the next {HORIZON_DAYS // 366} years"
    )


def validate_cron(expression):
    """Raise InvalidSchedule unless ``expression`` parses and ever runs."""
    from django.utils import timezone

    next_cron_run(expression, timezone.now())


# A report schedule's frequency, as the step between two runs; None: once.
FREQUENCY_STEPS = {
    "once": None,
    "daily": relativedelta(days=1),
    "weekly": relativedelta(weeks=1),
    "monthly": relativedelta(months=1),
    "quarterly": relativedelta(months=3),
}


def next_frequency_run(frequency, due, now):
    """The first run of a ``frequency`` schedule due at ``due`` after ``now``.

    None for "once". Steps are counted from ``due`` (``due + k * step``,
    not repeated additions), so a monthly schedule due on the 31st runs on
    the last day of shorter months and on the 31st again afterwards.
    """
    if frequency not in FREQUENCY_STEPS:
        raise InvalidSchedule(f"unknown frequency {frequency!r}")
    step = FREQUENCY_STEPS[frequency]
    if step is None:
        return None
    count = 1
    candidate = due + step
    while candidate <= now:
        count += 1
        candidate = due + step * count
    return candidate
