"""``assign_guardian_team --dry-run`` shows what the run would do (#724).

The command gives the rows written before guardian kept a team to a team.
It is run once, on real data, and cannot be taken back with another flag; the
dry run is how an operator checks the team id they are about to type in for
good. It printed what ``--list`` prints: "N row(s) without a team", for
whatever team was given, or for a team that does not exist.
"""

import io
import uuid

import pytest
from apps.assets.models import Asset
from apps.compliance.models import ComplianceFramework
from django.core.management import call_command
from django.core.management.base import CommandError

from tests.unit import team_fixtures as tf


def _run(*arguments):
    out = io.StringIO()
    call_command("assign_guardian_team", *arguments, stdout=out)
    return out.getvalue()


@pytest.fixture
def legacy(db):
    """Three assets without a team, a shared framework, and another team's asset."""
    assets = [tf.make(Asset, None) for _ in range(3)]
    return {
        "assets": assets,
        "framework": tf.framework(None),
        "other": tf.make(Asset, uuid.uuid4()),
    }


def test_the_dry_run_names_the_team_and_the_rows(legacy):
    team = uuid.uuid4()

    output = _run("--team", str(team), "--dry-run")

    assert f"assets.Asset: 3 row(s) would be assigned to {team}" in output
    for asset in legacy["assets"]:
        assert f"  {asset.pk}  {asset}" in output
    # Not a row it would assign: another team's, and the shared framework.
    assert str(legacy["other"].pk) not in output
    assert str(legacy["framework"].pk) not in output
    assert "compliance.ComplianceFramework: 1 shared row(s), left shared" in output
    assert output.rstrip().endswith(
        f"Dry run: 3 row(s) would be assigned to {team}; nothing changed."
    )


def test_the_dry_run_changes_nothing(legacy):
    _run("--team", str(uuid.uuid4()), "--dry-run", "--include-shared")

    assert (
        not Asset.objects.filter(team_id__isnull=False)
        .exclude(pk=legacy["other"].pk)
        .exists()
    )
    assert ComplianceFramework.objects.get(pk=legacy["framework"].pk).team_id is None


def test_the_dry_run_is_not_the_list(legacy):
    team = uuid.uuid4()

    listed = _run("--list")
    dry = _run("--team", str(team), "--dry-run")

    assert "assets.Asset: 3 row(s) without a team" in listed
    assert listed.rstrip().endswith("3 row(s) without a team; nothing changed.")
    assert "would be assigned" not in listed
    assert str(team) not in listed
    assert "without a team" not in dry
    assert dry != listed


def test_the_dry_run_says_what_the_run_then_does(legacy):
    """Same arguments without --dry-run: the same rows, to the same team."""
    team = uuid.uuid4()
    dry = _run("--team", str(team), "--dry-run", "--include-shared")

    done = _run("--team", str(team), "--include-shared")

    for label, count in (("assets.Asset", 3), ("compliance.ComplianceFramework", 1)):
        assert f"{label}: {count} row(s) would be assigned to {team}" in dry
        assert f"{label}: {count} row(s) assigned to {team}" in done
    assert f"Assigned 4 row(s) to {team}." in done
    assert "Dry run: 4 row(s) would be assigned" in dry
    assigned = set(Asset.objects.filter(team_id=team).values_list("pk", flat=True))
    assert assigned == {asset.pk for asset in legacy["assets"]}
    assert str(legacy["framework"].pk) in dry


@pytest.mark.django_db
def test_a_long_dry_run_names_the_first_rows_and_counts_the_rest():
    from apps.core.management.commands.assign_guardian_team import DRY_RUN_SAMPLE

    assets = [tf.make(Asset, None) for _ in range(DRY_RUN_SAMPLE + 4)]
    team = str(uuid.uuid4())

    brief = _run("--team", team, "--dry-run")
    full = _run("--team", team, "--dry-run", "-v", "2")

    named = [asset for asset in assets if f"  {asset.pk}  " in brief]
    assert len(named) == DRY_RUN_SAMPLE
    assert "  ... and 4 more (-v 2 names them all)" in brief
    assert all(f"  {asset.pk}  " in full for asset in assets)
    assert "more (" not in full


@pytest.mark.django_db
def test_a_dry_run_with_nothing_to_assign_says_so():
    team = uuid.uuid4()

    output = _run("--team", str(team), "--dry-run")

    assert output.strip() == (
        f"Dry run: 0 row(s) would be assigned to {team}; nothing changed."
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    "arguments",
    [
        (),
        ("--dry-run",),
        ("--include-shared",),
        ("--list", "--dry-run"),
        ("--list", "--team", str(uuid.uuid4())),
    ],
)
def test_arguments_that_do_not_say_what_to_do_are_refused(arguments):
    tf.make(Asset, None)

    with pytest.raises(CommandError):
        _run(*arguments)

    assert not Asset.objects.filter(team_id__isnull=False).exists()
