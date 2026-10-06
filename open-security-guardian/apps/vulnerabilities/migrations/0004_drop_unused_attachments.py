"""Drop the attachment table nothing ever wrote to (#665).

``VulnerabilityAttachment`` was a model without a writer: guardian has never
had an upload route, a task or a command that creates a row. Its one reader,
``GET vulnerabilities/{id}/attachments/``, was removed in #724, with the
``file`` URL under ``/media/`` that nothing serves. The model stayed then, so
as not to drop a table an operator might have written to by hand.

This migration drops the table when it is empty, which is every database
guardian itself has written, and refuses when it is not: it raises before
anything is changed, the migration is not recorded, and the table and its
rows are as they were. guardian's entrypoint runs ``migrate`` at start, so
the container then stops with the message below until the rows are dealt
with; they are the operator's, and only the operator knows what they are.

The reverse creates the table again, empty: there was nothing to restore.
"""

from django.db import migrations


class AttachmentsExist(Exception):
    """The table this migration drops has rows."""


def refuse_when_not_empty(apps, schema_editor):
    attachment = apps.get_model("vulnerabilities", "VulnerabilityAttachment")
    rows = attachment.objects.using(schema_editor.connection.alias).count()
    if rows:
        table = attachment._meta.db_table
        raise AttachmentsExist(
            f"{table} holds {rows} row(s). guardian never writes this table "
            "and this migration drops it, so they were written by hand. "
            "This migration changed nothing. Copy what you need (each row's "
            "`file` is a path under MEDIA_ROOT; the files themselves are not "
            "touched), "
            f"then empty the table (DELETE FROM {table};) and run "
            "`python manage.py migrate` again."
        )


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0003_resolved_at_follows_status"),
    ]

    operations = [
        migrations.RunPython(refuse_when_not_empty, migrations.RunPython.noop),
        migrations.DeleteModel(name="VulnerabilityAttachment"),
    ]
