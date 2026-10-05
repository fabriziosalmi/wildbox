"""How many vulnerabilities were open on each past day (#724).

``trends/`` answered, as ``total_open`` for a day, the vulnerabilities
discovered by that day whose status is open *now*: one resolved yesterday was
not open on any day of last month, and the line fell towards today whatever
had happened. The reference said so, and the field still claimed a figure it
was not.

guardian does record what is needed: every change of a vulnerability's status
and risk score is an entry of its history, with the value before, the value
after and the time (apps.vulnerabilities.signals). So the status on a past
day is read backwards from today's: it is the value *before* the first change
that came after that day, or today's value if nothing changed since. Reading
backwards needs only the entries newer than the day asked about, which is why
it holds although guardian keeps a year of history and no more
(``cleanup_old_vulnerability_history``).

What it cannot know: a vulnerability deleted since is not counted on the
days it existed, because its history went with it; and a status changed
behind the model's back (a bulk ``update()``) left no entry, so the change
shows on the day the figure is asked for and not before.
"""

from collections import defaultdict
from datetime import datetime

from django.utils import timezone

from .models import VulnerabilityHistory, VulnerabilityStatus

_FIELDS = ("status", "risk_score")


def _day(moment):
    return timezone.localtime(moment).date()


def _number(text, default):
    try:
        return float(text)
    except (TypeError, ValueError):
        return default


def open_by_day(vulnerabilities, start_date, end_date):
    """[(open at the end of the day, their average risk score then), ...]

    One pair per day from ``start_date`` to ``end_date``, both included, for
    the vulnerabilities of the queryset. Two queries, whatever the window.
    """
    days = (end_date - start_date).days + 1
    window_start = timezone.make_aware(
        datetime.combine(start_date, datetime.min.time())
    )
    vulnerabilities = vulnerabilities.order_by()
    rows = list(
        vulnerabilities.values_list("pk", "status", "risk_score", "first_discovered")
    )

    changes = defaultdict(list)
    history = VulnerabilityHistory.objects.filter(
        vulnerability__in=vulnerabilities.values("pk"),
        field_name__in=_FIELDS,
        timestamp__gte=window_start,
    ).order_by("timestamp", "pk")
    for entry in history.values_list(
        "vulnerability_id", "timestamp", "field_name", "old_value", "new_value"
    ):
        changes[entry[0]].append(entry[1:])

    # Steps: +1 on the first day of a run of open days, -1 on the day after it.
    count_steps = [0] * (days + 1)
    risk_steps = [0.0] * (days + 1)

    def add(first_day, day_after, risk):
        first, after = max(first_day, 0), min(day_after, days)
        if first < after:
            count_steps[first] += 1
            count_steps[after] -= 1
            risk_steps[first] += risk
            risk_steps[after] -= risk

    now = timezone.now()
    for pk, status, risk, discovered in rows:
        events = list(changes.get(pk, ()))
        # Today's values are the row's own. If the history does not end on
        # them, something changed without an entry, nobody knows when: it is
        # taken to have changed now, the one moment it is known to be true.
        logged = {field: new_value for _, field, _, new_value in events}
        if logged.get("status", status) != status:
            events.append((now, "status", None, status))
        if _number(logged.get("risk_score"), risk) != risk:
            events.append((now, "risk_score", None, risk))
        # What it was when the window began: the value before its first
        # change in the window, else what it is now.
        for _, field, old_value, _ in events:
            if field == "status":
                status = old_value
                break
        for _, field, old_value, _ in events:
            if field == "risk_score":
                risk = _number(old_value, risk)
                break
        # Never before it was discovered, whatever the history holds.
        since = (_day(discovered) - start_date).days if discovered else 0
        for moment, field, _, new_value in events:
            # A day ends with the changes made on it.
            changed_on = (_day(moment) - start_date).days
            if status == VulnerabilityStatus.OPEN:
                add(since, changed_on, risk)
            since = max(since, changed_on)
            if field == "status":
                status = new_value
            else:
                risk = _number(new_value, risk)
        if status == VulnerabilityStatus.OPEN:
            add(since, days, risk)

    result, count, risk_sum = [], 0, 0.0
    for index in range(days):
        count += count_steps[index]
        risk_sum += risk_steps[index]
        result.append((count, round(risk_sum / count, 2) if count else 0))
    return result
