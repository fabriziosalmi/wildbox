"""Drop the two payload columns of the integration log (#665).

``IntegrationLog.request_data`` and ``response_data`` were meant for the raw
request and response of a call to an external system. guardian makes no such
call and nothing writes an integration log, so nothing ever filled them; the
API never returned them either (``IntegrationLogSerializer`` left them out,
because such payloads carry authorization headers and token responses).

A row can only hold a value that was written to the database by hand. The
values are blanked before the columns are dropped, as in 0004: PostgreSQL's
``DROP COLUMN`` leaves a column's bytes in every row until the row is next
written. When a row did hold one, the operator is told how many, and no
value is printed.

Both columns are blanked by one ``UPDATE``. Two in a row would rewrite, in
the second, rows the first had just written in the same transaction, and
PostgreSQL then queues the checks of the table's deferred foreign keys and
refuses the ``ALTER TABLE`` that follows ("pending trigger events").

Safe to run again. The reverse adds the two columns back empty.
"""

import logging

from django.db import migrations

logger = logging.getLogger(__name__)

COLUMNS = ("request_data", "response_data")


def blank_payloads(apps, schema_editor):
    log = apps.get_model("integrations", "IntegrationLog")
    manager = log.objects.using(schema_editor.connection.alias)
    held = dict.fromkeys(COLUMNS, 0)
    for values in manager.values_list(*COLUMNS).iterator():
        for column, value in zip(COLUMNS, values):
            held[column] += bool(value)
    manager.update(**{column: {} for column in COLUMNS})
    for column, rows in held.items():
        if rows:
            logger.warning(
                "%d integration log row(s) held a value in %s, which guardian "
                "never writes and never returned. It is deleted. A raw "
                "request or response can carry a credential: backups made "
                "before this upgrade still contain it.",
                rows,
                column,
            )


class Migration(migrations.Migration):

    dependencies = [
        ("integrations", "0004_drop_stored_credentials"),
    ]

    operations = [
        migrations.RunPython(blank_payloads, migrations.RunPython.noop),
        migrations.RemoveField(model_name="integrationlog", name="request_data"),
        migrations.RemoveField(model_name="integrationlog", name="response_data"),
    ]
