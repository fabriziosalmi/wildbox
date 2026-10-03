"""Assign the rows written before guardian kept a team to a team (#642).

Up to 0.8.x guardian stored no team: every team read and wrote every row.
The migrations that add ``team_id`` leave those rows without one, and no
team reaches a row without a team through the API. This command gives them
to the team that should own them::

    python manage.py assign_guardian_team --list
    python manage.py assign_guardian_team --team <identity team UUID> --dry-run
    python manage.py assign_guardian_team --team <identity team UUID>

Only models that store their team are updated: the rows that belong to
another row (a vulnerability's asset, a scan's scanner, a report's
template) follow it. Compliance frameworks and vulnerability templates
without a team are shared reference data, read by every team; they are
left shared unless ``--include-shared`` is given.
"""

import uuid

from apps.core.tenancy import TEAM_FIELD, has_global_rows, team_lookup
from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


def team_owned_models():
    """Every model that stores its own team_id, in a stable order."""
    found = [model for model in apps.get_models() if team_lookup(model) == TEAM_FIELD]
    return sorted(found, key=lambda model: model._meta.label)


class Command(BaseCommand):
    help = "Assign the rows that have no team (written before 0.9) to a team."

    def add_arguments(self, parser):
        parser.add_argument(
            "--team",
            type=uuid.UUID,
            help="The identity team UUID that owns the rows without a team.",
        )
        parser.add_argument(
            "--list",
            action="store_true",
            help="Count the rows without a team, per model, and change nothing.",
        )
        parser.add_argument(
            "--include-shared",
            action="store_true",
            help=(
                "Also assign compliance frameworks and vulnerability templates, "
                "which are otherwise shared with every team."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be assigned and change nothing.",
        )

    def handle(self, *args, **options):
        if not options["list"] and options["team"] is None:
            raise CommandError("Give --team <uuid>, or --list to count the rows.")

        team = options["team"]
        include_shared = options["include_shared"]
        apply = not (options["list"] or options["dry_run"])
        total = 0
        with transaction.atomic():
            for model in team_owned_models():
                rows = model._default_manager.filter(**{f"{TEAM_FIELD}__isnull": True})
                shared = has_global_rows(model)
                count = rows.count()
                if not count:
                    continue
                label = model._meta.label
                if shared and not include_shared:
                    self.stdout.write(
                        f"{label}: {count} shared row(s), left shared "
                        "(--include-shared assigns them)"
                    )
                    continue
                if apply:
                    rows.update(**{TEAM_FIELD: team})
                    self.stdout.write(f"{label}: {count} row(s) assigned to {team}")
                else:
                    self.stdout.write(f"{label}: {count} row(s) without a team")
                total += count

        if apply:
            self.stdout.write(self.style.SUCCESS(f"Assigned {total} row(s) to {team}."))
        else:
            self.stdout.write(f"{total} row(s) without a team; nothing changed.")
