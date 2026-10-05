"""Give ``resolved_at`` to the vulnerabilities whose status says "resolved".

Until #724 only ``close/`` and ``reopen/`` wrote ``resolved_at``. A
vulnerability resolved by setting its status (``PATCH {"status":
"resolved"}``) has none, so the statistics leave it out of the average
resolution time and of the day it was resolved on; one reopened the same way
still carries the date of a resolution it no longer has.

The history has what is missing: every status change is an entry with its
time. A resolved vulnerability without ``resolved_at`` gets the time of its
last entry that says the status became "resolved"; one with no such entry
(its history is older than the year guardian keeps) is left without, rather
than given a date nobody recorded. A vulnerability that is not resolved loses
its ``resolved_at``.
"""

from django.db import migrations

RESOLVED = "resolved"


def follow_status(apps, schema_editor):
    Vulnerability = apps.get_model("vulnerabilities", "Vulnerability")
    History = apps.get_model("vulnerabilities", "VulnerabilityHistory")

    undated = Vulnerability.objects.filter(status=RESOLVED, resolved_at__isnull=True)
    for pk in undated.values_list("pk", flat=True).iterator():
        entry = (
            History.objects.filter(
                vulnerability_id=pk, field_name="status", new_value=RESOLVED
            )
            .order_by("-timestamp")
            .first()
        )
        if entry is not None:
            # update(): no signal, no history entry, no auto_now.
            Vulnerability.objects.filter(pk=pk).update(resolved_at=entry.timestamp)

    Vulnerability.objects.exclude(status=RESOLVED).filter(
        resolved_at__isnull=False
    ).update(resolved_at=None)


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0002_team_id"),
    ]

    operations = [
        # Nothing to undo: the dates it writes are the ones the history holds.
        migrations.RunPython(follow_status, migrations.RunPython.noop),
    ]
