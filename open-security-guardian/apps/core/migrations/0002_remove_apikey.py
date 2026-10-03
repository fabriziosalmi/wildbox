"""Drop guardian's own API keys (#629).

guardian accepted rows of this table from an X-API-Key header beside the
gateway, as an admin and a superuser, and stored the keys in plain text.
That path is gone and nothing else used the table, so it is dropped, with
the audit log's foreign key to it. Callers authenticate through the gateway
with identity's personal API keys.

Irreversible in practice: reversing recreates an empty table; the keys it
held are not restored and would no longer authenticate anyway.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="auditlog",
            name="api_key",
        ),
        migrations.DeleteModel(
            name="APIKey",
        ),
    ]
