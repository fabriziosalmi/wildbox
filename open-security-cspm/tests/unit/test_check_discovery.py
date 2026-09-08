"""Every check on disk must be discovered, and every check_id must be unique.

Both of these were broken and invisible:

  * app/checks/gcp/compute/ had no __init__.py, so pkgutil never walked into it
    and its two checks -- disk encryption and public instance IPs -- had never
    run in any scan.
  * Four check_ids were claimed by two checks each. CheckRegistry keys on
    check_id, so the second registration silently replaced the first: eight
    checks were written, four ever ran.

Neither showed up while 166 generated placeholders padded the catalogue
(WILDBO-QUAL-01). These tests fail if either returns.
"""

import ast
import os
import pathlib

import pytest

# app.checks.runner imports app.config, which builds a Settings() at import time
# and requires SECRET_KEY (min 32 characters) and the credential key. Without
# them the two tests below fail at collection with a pydantic ValidationError
# rather than telling you anything about check discovery -- which is what
# happened in CI, where the unit-test job sets no service configuration. The
# same pattern the tools tests use.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-at-least-32-chars-long")
os.environ.setdefault(
    "CSPM_CREDENTIAL_KEY", "dGVzdC1vbmx5LWtleS1ub3QtdXNlZC1mb3ItY3J5cHRvISE="
)

CHECKS_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "checks"


def _check_classes_on_disk():
    """(module path, class name) for every BaseCheck subclass in the tree."""
    found = []
    for path in sorted(CHECKS_DIR.rglob("check_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {b.id for b in node.bases if isinstance(b, ast.Name)}
            if "BaseCheck" in bases:
                rel = path.relative_to(CHECKS_DIR.parents[1])
                module = str(rel.with_suffix("")).replace("/", ".")
                found.append((module, node.name))
    return found


def test_every_check_directory_is_a_package():
    """A directory without __init__.py is invisible to the loader."""
    missing = [
        str(d.relative_to(CHECKS_DIR))
        for d in CHECKS_DIR.rglob("*")
        if d.is_dir()
        and d.name != "__pycache__"
        and any(d.glob("check_*.py"))
        and not (d / "__init__.py").exists()
    ]
    assert not missing, f"check directories without __init__.py: {missing}"


def test_check_ids_are_unique():
    """Two checks sharing an id means one of them never runs."""
    import re

    seen = {}
    duplicates = []
    for path in sorted(CHECKS_DIR.rglob("check_*.py")):
        for match in re.finditer(
            r'check_id\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8")
        ):
            check_id = match.group(1)
            if check_id in seen:
                duplicates.append(f"{check_id}: {seen[check_id]} and {path.name}")
            else:
                seen[check_id] = path.name
    assert not duplicates, "duplicate check_ids: " + "; ".join(duplicates)


def test_every_check_on_disk_is_discovered():
    """The runner must load every check that exists."""
    runner_mod = pytest.importorskip(
        "app.checks.runner", reason="cloud SDKs not installed"
    )
    runner = runner_mod.CheckRunner()
    loaded = {
        f"{type(c).__module__}.{type(c).__name__}"
        for checks in runner.loaded_checks.values()
        for c in checks
    }
    expected = {f"{m}.{c}" for m, c in _check_classes_on_disk()}
    missing = sorted(expected - loaded)
    assert not missing, f"checks on disk that the runner never loaded: {missing}"


def test_no_unimplemented_checks_are_advertised():
    """Scaffolding must not be counted as capability."""
    runner_mod = pytest.importorskip(
        "app.checks.runner", reason="cloud SDKs not installed"
    )
    runner = runner_mod.CheckRunner()
    advertised = {c["check_id"] for c in runner.get_available_checks()}
    scaffolding = {c.metadata.check_id for c in runner.unimplemented_checks}
    assert not (advertised & scaffolding), (
        "checks declaring implemented=False appear in /api/v1/checks: "
        f"{sorted(advertised & scaffolding)}"
    )
