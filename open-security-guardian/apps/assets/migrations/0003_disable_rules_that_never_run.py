"""Switch off the discovery rules that never run (#724).

A discovery rule of a type guardian does not implement (cloud API, CMDB
import, agent report, DNS zone) can no longer be created (#548), and the
schedule dispatcher has never run one. One stored before that could still
say ``enabled: true``, and be "enabled" again through the API. "Enabled"
means "runs on its schedule": the API now refuses to enable such a rule, and
this makes the stored ones say what is true.

The types are spelled out, not imported: this is what was implemented when
the migration was written. A type implemented later is enabled by its owner.
"""

from django.db import migrations

IMPLEMENTED = ("network_scan",)


def disable(apps, schema_editor):
    rule = apps.get_model("assets", "AssetDiscoveryRule")
    rule.objects.exclude(discovery_type__in=IMPLEMENTED).filter(enabled=True).update(
        enabled=False
    )


class Migration(migrations.Migration):

    dependencies = [
        ("assets", "0002_team_id"),
    ]

    operations = [
        # Not undone: which of them were enabled before is not kept, and
        # none of them ran.
        migrations.RunPython(disable, migrations.RunPython.noop),
    ]
