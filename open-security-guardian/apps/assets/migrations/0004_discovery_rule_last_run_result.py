"""What a discovery rule's last run did, on the rule (#775).

A rule whose networks were all refused, because it was stored before the
scan target check (#748) or because the operator has since narrowed
``GUARDIAN_ALLOWED_INTERNAL_TARGETS``, ended ``completed`` with nothing
queued. The networks and the reasons were in ``guardian-worker``'s log, which
the rule's owner does not read, and the task route answers with a state and
never a result.

``last_run_result`` is where ``execute_discovery_rule`` now writes the
outcome. One nullable column and no data: every stored rule has ``null``
until its next run, and a guardian of the version before, which does not
know the column, reads and writes the table as it did.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("assets", "0003_disable_rules_that_never_run"),
    ]

    operations = [
        migrations.AddField(
            model_name="assetdiscoveryrule",
            name="last_run_result",
            field=models.JSONField(blank=True, null=True),
        ),
    ]
