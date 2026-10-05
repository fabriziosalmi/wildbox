"""Drop the scanner credentials guardian stored and never used (#728).

``Scanner.api_key`` and ``Scanner.password`` held what the API was sent, as
plain text. Nothing read them: guardian has no code that connects to a
scanner, and the API never returned them. They go, with their values.

The values are blanked before the columns are dropped. PostgreSQL's ``DROP
COLUMN`` hides a column and leaves its bytes in every row until the row is
next written, so dropping alone would keep each credential in the live
table for as long as its scanner is not edited. After the update the live
rows no longer carry them and the old row versions are dead, for vacuum to
reclaim. Neither step can undo what is already elsewhere: backups made
before this migration hold the credentials in plain text, which is why the
count is logged for the operator to act on.

Safe to interrupt and to run again: it is one transaction on PostgreSQL,
and blanking an already blank row changes nothing. The reverse adds the
two columns back empty; it has nothing to restore.
"""

import logging

from django.db import migrations

logger = logging.getLogger(__name__)


def blank_credentials(apps, schema_editor):
    Scanner = apps.get_model("scanners", "Scanner")
    manager = Scanner.objects.using(schema_editor.connection.alias)
    held = sum(
        1
        for api_key, password in manager.values_list("api_key", "password").iterator()
        if api_key or password
    )
    manager.update(api_key="", password="")
    if held:
        logger.warning(
            "guardian stored an API key or a password, in plain text, for %d "
            "scanner(s). They are deleted: nothing used them. Backups made "
            "before this upgrade still contain them; if the database or one "
            "of its backups may have been read, change them at the scanner.",
            held,
        )


class Migration(migrations.Migration):

    dependencies = [
        ("scanners", "0002_team_id"),
    ]

    operations = [
        migrations.RunPython(blank_credentials, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="scanner",
            name="api_key",
        ),
        migrations.RemoveField(
            model_name="scanner",
            name="password",
        ),
    ]
