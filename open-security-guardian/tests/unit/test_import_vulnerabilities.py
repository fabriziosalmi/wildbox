"""``manage.py import_vulnerabilities`` stores what its file holds (#788).

The command could not import a file of either format it reads. It gave the
models names they do not have:

* JSON: ``cvss_score`` and ``discovered_at`` to ``Vulnerability``, whose
  fields are ``cvss_v3_score`` and ``first_discovered``;
* CSV: ``cvss_score`` again, and ``hostname``, which is the asset's;
* both, for an asset it did not know: ``environment='unknown'`` where the
  model has a foreign key, ``is_active`` and ``created_at``, and no
  ``name``.

So every run that reached a row ended ``Import failed: Vulnerability() got
unexpected keyword arguments`` (or the asset's ``Cannot assign "'unknown'"``
before it), and stored nothing. A dry run, which stores nothing by design,
reported what it "would import".

The command is run here as an operator runs it, on files written for the
test, for each source it accepts. The three it accepts and does not
implement (``nist``, ``nessus``, ``openvas``) printed a warning and ended
with status 0, as an import that worked does; they end with an error.
"""

import csv
import json
import uuid
from io import StringIO
from unittest import mock

import pytest
from apps.assets.models import Asset
from apps.vulnerabilities.models import Vulnerability
from django.core.management import call_command
from django.core.management.base import CommandError

FINDINGS = [
    {
        "title": "OpenSSL heap overflow",
        "description": "A crafted certificate overflows a heap buffer.",
        "severity": "critical",
        "cvss_score": 9.8,
        "cve_id": "CVE-2022-3602",
        "hostname": "web01.example.test",
        "port": 443,
        "protocol": "tcp",
    },
    {
        "title": "Default credentials",
        "description": "The admin console accepts admin/admin.",
        "severity": "high",
        "hostname": "web01.example.test",
        "port": 8080,
    },
    {
        "title": "Weak TLS configuration",
        "hostname": "db01.example.test",
    },
]

CSV_COLUMNS = (
    "title",
    "description",
    "severity",
    "cvss_score",
    "cve_id",
    "hostname",
    "port",
    "protocol",
)


@pytest.fixture(autouse=True)
def no_scan():
    """Creating an asset queues a port scan; no broker is needed for this."""
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        yield


def write_json(tmp_path, findings=FINDINGS, columns=None):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"vulnerabilities": findings}), encoding="utf-8")
    return path


def write_csv(tmp_path, findings=FINDINGS, columns=CSV_COLUMNS):
    path = tmp_path / "findings.csv"
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(columns)
        for finding in findings:
            writer.writerow([finding.get(column, "") for column in columns])
    return path


WRITERS = {"json": write_json, "csv": write_csv}


def run(source, path=None, team=None, *flags):
    """Run the command; returns (team, what it printed)."""
    team = team or uuid.uuid4()
    out = StringIO()
    arguments = ["--source", source, "--team-id", str(team), *flags]
    if path is not None:
        arguments += ["--file", str(path)]
    call_command("import_vulnerabilities", *arguments, stdout=out)
    return team, out.getvalue()


def stored(team):
    return {
        (v.asset.hostname, v.cve_id, v.port): v
        for v in Vulnerability.objects.filter(asset__team_id=team)
    }


# --- a file is imported ---------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_a_file_is_imported_into_the_models_fields(tmp_path, source):
    team, out = run(source, WRITERS[source](tmp_path))

    found = stored(team)
    assert set(found) == {
        ("web01.example.test", "CVE-2022-3602", 443),
        ("web01.example.test", "", 8080),
        ("db01.example.test", "", None),
    }
    openssl = found[("web01.example.test", "CVE-2022-3602", 443)]
    assert openssl.title == "OpenSSL heap overflow"
    assert openssl.description == "A crafted certificate overflows a heap buffer."
    assert openssl.severity == "critical"
    # The file's cvss_score is the model's cvss_v3_score.
    assert openssl.cvss_v3_score == 9.8
    assert openssl.protocol == "tcp"
    assert openssl.first_discovered is not None
    # What the file leaves out is the model's default, not a made-up value.
    bare = found[("db01.example.test", "", None)]
    assert bare.title == "Weak TLS configuration"
    assert bare.description == "" and bare.severity == "medium"
    assert bare.cvss_v3_score is None and bare.protocol == ""
    assert f"{source.upper()} import completed: 3 imported, 0 updated" in out


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_the_assets_are_the_teams_and_named(tmp_path, source):
    team, out = run(source, WRITERS[source](tmp_path))

    assets = {asset.hostname: asset for asset in Asset.objects.filter(team_id=team)}
    assert set(assets) == {"web01.example.test", "db01.example.test"}
    assert Asset.objects.count() == 2, "one asset for the two findings of a host"
    web = assets["web01.example.test"]
    assert web.name == "web01.example.test"
    assert web.asset_type == "server" and web.criticality == "medium"
    assert web.status == "active"
    assert web.environment is None
    assert web.discovered_by == "import_vulnerabilities"
    assert "Created asset: web01.example.test" in out


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_a_finding_goes_to_the_asset_the_team_already_has(tmp_path, source):
    team, other_team = uuid.uuid4(), uuid.uuid4()
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        mine = Asset.objects.create(
            team_id=team, name="The web server", hostname="web01.example.test"
        )
        theirs = Asset.objects.create(
            team_id=other_team, name="Theirs", hostname="web01.example.test"
        )

    run(source, WRITERS[source](tmp_path, FINDINGS[:1]), team)

    assert Vulnerability.objects.get().asset == mine
    assert not theirs.vulnerabilities.exists()
    assert Asset.objects.count() == 2


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_the_other_names_a_file_may_use(tmp_path, source):
    """A scanner's export: its own column names, a severity in capitals,
    and 0 for "no port"."""
    row = {
        "vulnerability": "Open mail relay",
        "cve": "CVE-2020-0001",
        "host": "mail.example.test",
        "severity": "High",
        "port": 0,
    }

    team, _ = run(source, WRITERS[source](tmp_path, [row], columns=tuple(row)))

    ((key, finding),) = stored(team).items()
    assert key == ("mail.example.test", "CVE-2020-0001", None)
    assert finding.title == "Open mail relay" and finding.severity == "high"

    # And "target", for a row that has neither of the other two.
    team, _ = run(
        source,
        WRITERS[source](
            tmp_path, [{"title": "t", "target": "10.0.0.9"}], ("title", "target")
        ),
    )
    assert set(stored(team)) == {("10.0.0.9", "", None)}


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_a_dry_run_stores_nothing(tmp_path, source):
    team, out = run(source, WRITERS[source](tmp_path), None, "--dry-run")

    assert not Vulnerability.objects.exists() and not Asset.objects.exists()
    assert "Would import: OpenSSL heap overflow" in out
    assert "3 imported" in out


# --- a file imported twice ------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_a_second_import_skips_what_is_there(tmp_path, source):
    path = WRITERS[source](tmp_path)
    team, _ = run(source, path)

    _, out = run(source, path, team)

    # A finding is the model's (asset, cve_id, port). The one with neither a
    # CVE nor a port has nothing to be known by, and is stored again, as the
    # API stores it (test_vulnerability_records.py).
    assert "Skipping existing: CVE-2022-3602" in out
    assert f"{source.upper()} import completed: 1 imported, 0 updated" in out
    assert Vulnerability.objects.filter(asset__team_id=team).count() == 4
    assert Vulnerability.objects.filter(cve_id="CVE-2022-3602").count() == 1
    assert Vulnerability.objects.filter(port=8080).count() == 1


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_force_updates_what_is_there(tmp_path, source):
    team, _ = run(source, WRITERS[source](tmp_path, FINDINGS[:2]))
    changed = [
        dict(FINDINGS[0], severity="high", cvss_score=7.5, title="OpenSSL, rescored"),
        FINDINGS[1],
    ]

    _, out = run(source, WRITERS[source](tmp_path, changed), team, "--force")

    assert f"{source.upper()} import completed: 0 imported, 2 updated" in out
    assert Vulnerability.objects.count() == 2
    openssl = Vulnerability.objects.get(cve_id="CVE-2022-3602")
    assert (openssl.severity, openssl.cvss_v3_score) == ("high", 7.5)
    assert openssl.title == "OpenSSL, rescored"
    assert openssl.asset.hostname == "web01.example.test"


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_the_same_cve_on_another_port_is_another_finding(tmp_path, source):
    findings = [FINDINGS[0], dict(FINDINGS[0], port=8443)]

    team, out = run(source, WRITERS[source](tmp_path, findings))

    assert "2 imported" in out
    assert {port for _, _, port in stored(team)} == {443, 8443}


@pytest.mark.django_db
def test_another_teams_finding_is_not_mine_to_skip(tmp_path):
    path = write_json(tmp_path, FINDINGS[:1])
    run("json", path)

    team, out = run("json", path)

    assert "1 imported" in out and "Skipping" not in out
    assert Vulnerability.objects.filter(asset__team_id=team).count() == 1
    assert Vulnerability.objects.count() == 2


# --- a file that cannot be imported ----------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
@pytest.mark.parametrize(
    ("field", "value", "said"),
    [
        ("severity", "urgent", "severity"),
        ("cvss_score", "11", "cvss_score"),
        ("cvss_score", "high", "cvss_score"),
        ("port", "70000", "port"),
        ("port", "https", "port"),
    ],
)
def test_a_value_the_model_does_not_take_stops_the_import(
    tmp_path, source, field, value, said
):
    """And nothing of the file is kept: a row before it is not half an import."""
    findings = [FINDINGS[0], dict(FINDINGS[1], **{field: value})]

    with pytest.raises(CommandError) as failure:
        run(source, WRITERS[source](tmp_path, findings))

    message = str(failure.value)
    assert message.startswith("Import failed: ") and said in message
    assert "Default credentials" in message, "the row is named"
    assert not Vulnerability.objects.exists() and not Asset.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "content", ["[]", '{"findings": []}', '{"vulnerabilities": {}}']
)
def test_a_json_file_without_the_list_is_refused(tmp_path, content):
    path = tmp_path / "findings.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(CommandError) as failure:
        run("json", path)

    assert '"vulnerabilities"' in str(failure.value)


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["json", "csv"])
def test_a_source_that_reads_a_file_needs_one(source):
    with pytest.raises(CommandError) as failure:
        run(source)

    assert "File path is required" in str(failure.value)


# --- the sources that are not implemented ---------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("source", ["nist", "nessus", "openvas"])
def test_a_source_that_is_not_implemented_ends_with_an_error(source):
    """Each printed "not yet implemented" and ended like a finished import."""
    with pytest.raises(CommandError) as failure:
        run(source)

    assert f"{source} import is not implemented" in str(failure.value)
    assert not Vulnerability.objects.exists()


def test_the_sources_are_the_ones_tested_here():
    from apps.core.management.commands.import_vulnerabilities import Command

    parser = Command().create_parser("manage.py", "import_vulnerabilities")
    (source,) = [a for a in parser._actions if a.dest == "source"]

    assert set(source.choices) == {"json", "csv", "nist", "nessus", "openvas"}
