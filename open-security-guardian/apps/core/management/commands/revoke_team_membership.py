"""Do by hand what identity's notice does when a member leaves a team (#676).

identity tells guardian when it removes a member from a team or deletes an
account, and guardian then stops accepting the user as one of the team's
users and clears the roles they held. That notice is sent once, after the
removal, and does not block it: if guardian was down, identity logs an error
that begins "guardian was not told of", and guardian goes on counting the
user as a member until their membership ages out
(GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS). This command applies the notice
without waiting for that::

    python manage.py revoke_team_membership --team <team UUID> --user <user UUID>
    python manage.py revoke_team_membership --user <user UUID> --all-teams
    python manage.py revoke_team_membership --team <team UUID> --user <user UUID> --dry-run

The ids are identity's: the team's, and the user's. ``--all-teams`` is for
an account that was deleted. It takes no secret and makes no request: it
runs in guardian's container, on guardian's own data.

Only use it for a user identity has removed. A user who is still a member
is recorded as one again by their next request, but the roles this clears
(their assignments, the dashboards shared with them) do not come back.
"""

import uuid

from apps.core import memberships
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


class Command(BaseCommand):
    help = "Stop counting a user as a member of a team, and clear the roles they held in it."

    def add_arguments(self, parser):
        parser.add_argument(
            "--user", type=uuid.UUID, required=True, help="The identity user UUID."
        )
        parser.add_argument(
            "--team", type=uuid.UUID, help="The identity team UUID the user left."
        )
        parser.add_argument(
            "--all-teams",
            action="store_true",
            help="The account is gone: every team, not one.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be cleared and change nothing.",
        )

    def handle(self, *args, **options):
        team, everywhere = options["team"], options["all_teams"]
        if (team is None) == (not everywhere):
            # Neither, or both: never guess between one team and all of them.
            raise CommandError("Give either --team <uuid> or --all-teams.")
        user_id = options["user"]
        user = memberships._mirror(user_id)
        if user is None:
            self.stdout.write(
                f"guardian has never seen user {user_id}: nothing to revoke."
            )
            return

        if options["dry_run"]:
            # Count what would be cleared, then undo it. Not through
            # revoke_membership: its log line would say it happened.
            with transaction.atomic():
                cleared = memberships._clear_roles(user, None if everywhere else team)
                transaction.set_rollback(True)
        elif everywhere:
            cleared = memberships.revoke_user(user_id)
        else:
            cleared = memberships.revoke_membership(team, user_id)

        where = "every team" if everywhere else f"team {team}"
        verb = "Would revoke" if options["dry_run"] else "Revoked"
        self.stdout.write(f"{verb} user {user_id} in {where}.")
        for field, count in sorted(cleared.items()):
            self.stdout.write(f"  {field}: {count} cleared")
        if not cleared:
            self.stdout.write("  They held no role there.")
