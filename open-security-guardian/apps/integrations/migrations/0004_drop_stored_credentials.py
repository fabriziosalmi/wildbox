"""Drop the integration credentials guardian stored and never used (#728).

Three columns held secrets as plain text and had no reader, in guardian or
through the API, which accepted them and never returned them:

- ``ExternalSystem.auth_config``: API keys, bearer tokens, basic-auth
  passwords. guardian contacts no external system.
- ``WebhookEndpoint.secret_token``: the secret of a verification nothing
  performs. guardian receives no webhooks.
- ``NotificationChannel.config``: Slack and Teams webhook URLs, SMTP
  passwords, push tokens. guardian delivers nothing through a channel.

The values are blanked before the columns are dropped. PostgreSQL's ``DROP
COLUMN`` hides a column and leaves its bytes in every row until the row is
next written, so dropping alone would keep each secret in the live table
for as long as its row is not edited. After the update the live rows no
longer carry them and the old row versions are dead, for vacuum to
reclaim. Neither step can undo what is already elsewhere: backups made
before this migration hold the secrets in plain text, which is why the
counts are logged for the operator to act on.

Safe to interrupt and to run again: it is one transaction on PostgreSQL,
and blanking an already blank row changes nothing. The reverse adds the
three columns back empty; it has nothing to restore.
"""

import logging

from django.db import migrations

logger = logging.getLogger(__name__)

#: (model, column, the empty value, what the log line calls the rows)
COLUMNS = (
    ("ExternalSystem", "auth_config", dict, "external system(s)"),
    ("WebhookEndpoint", "secret_token", str, "webhook endpoint(s)"),
    ("NotificationChannel", "config", dict, "notification channel(s)"),
)


def blank_credentials(apps, schema_editor):
    for model_name, column, empty, rows in COLUMNS:
        model = apps.get_model("integrations", model_name)
        manager = model.objects.using(schema_editor.connection.alias)
        held = sum(
            1 for value in manager.values_list(column, flat=True).iterator() if value
        )
        manager.update(**{column: empty()})
        if held:
            logger.warning(
                "guardian stored %s, in plain text, for %d %s. It is deleted: "
                "nothing used it. Backups made before this upgrade still "
                "contain it; if the database or one of its backups may have "
                "been read, change those secrets where they were issued.",
                column,
                held,
                rows,
            )


class Migration(migrations.Migration):

    dependencies = [
        ("integrations", "0003_webhook_path_unique_per_system"),
    ]

    operations = [
        migrations.RunPython(blank_credentials, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="externalsystem",
            name="auth_config",
        ),
        migrations.RemoveField(
            model_name="notificationchannel",
            name="config",
        ),
        migrations.RemoveField(
            model_name="webhookendpoint",
            name="secret_token",
        ),
    ]
