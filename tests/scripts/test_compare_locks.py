"""Tests for compare_locks.py, the comparison behind compile_requirements.sh --check.

The check compared the compiled lock with the committed one as text, so every
Dependabot pip-group PR failed it: pip-compile writes the same pins with
extras, markers, other comments and another order. These hold the two halves
of the job: a lock written differently with the same pins passes, and a lock
that installs something else (an older version, a missing package, a
different artefact) fails.

The fixtures are four versions of one lock under fixtures/locks/:
uv_compiled.txt as compile_requirements.sh writes it, dependabot.txt with the
same pins as pip-compile writes them, stale.txt with an older uvicorn and no
async-timeout, hash_changed.txt with one hash of typing-extensions replaced.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "compare_locks.py"
LOCKS = Path(__file__).parent / "fixtures" / "locks"
spec = importlib.util.spec_from_file_location("compare_locks", SCRIPT)
cl = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cl
spec.loader.exec_module(cl)


def run(expected: Path, actual: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(expected), str(actual)],
        capture_output=True,
        text=True,
    )


def lock(name: str) -> dict:
    return cl.parse_lock((LOCKS / name).read_text())


def test_dependabot_style_lock_with_the_same_pins_passes():
    # Extras (uvicorn[standard], Celery[redis]), markers, a name in another
    # case and with an underscore, `# via -r requirements.in`, the pip-compile
    # header and another order of packages and of hashes.
    assert cl.compare(lock("uv_compiled.txt"), lock("dependabot.txt")) == []
    result = run(LOCKS / "uv_compiled.txt", LOCKS / "dependabot.txt")
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_lock_is_equal_to_itself():
    assert run(LOCKS / "uv_compiled.txt", LOCKS / "uv_compiled.txt").returncode == 0


def test_stale_lock_fails_and_names_each_difference():
    result = run(LOCKS / "uv_compiled.txt", LOCKS / "stale.txt")
    assert result.returncode == 1
    assert "missing from the lock: async-timeout==5.0.1" in result.stdout
    assert (
        "version differs: uvicorn resolves to 0.24.0, lock has 0.23.2" in result.stdout
    )


def test_a_package_only_in_the_lock_fails():
    # The other direction: requirements.in dropped a package, the lock kept it.
    result = run(LOCKS / "stale.txt", LOCKS / "uv_compiled.txt")
    assert result.returncode == 1
    assert (
        "in the lock but not resolved from requirements.in: async-timeout==5.0.1"
        in result.stdout
    )


def test_same_version_with_a_different_hash_fails():
    result = run(LOCKS / "uv_compiled.txt", LOCKS / "hash_changed.txt")
    assert result.returncode == 1
    assert "hashes differ: typing-extensions==4.15.0" in result.stdout
    assert "+ sha256:" + "0" * 64 in result.stdout


def test_a_hash_missing_from_the_lock_fails():
    expected = cl.parse_lock("six==1.17.0 --hash=sha256:aa --hash=sha256:bb\n")
    actual = cl.parse_lock("six==1.17.0 --hash=sha256:aa\n")
    assert cl.compare(expected, actual) == [
        "hashes differ: six==1.17.0: 1 expected not in the lock, 0 in the lock not expected",
        "    - sha256:bb",
    ]


@pytest.mark.parametrize(
    "name, normalized",
    [
        ("PyJWT", "pyjwt"),
        ("typing_extensions", "typing-extensions"),
        ("zope.interface", "zope-interface"),
        ("a-_.b", "a-b"),
    ],
)
def test_names_are_normalized_as_pep_503_says(name, normalized):
    assert cl.normalize_name(name) == normalized


def test_a_line_that_is_not_a_pin_cannot_pass_as_equal(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("uvicorn>=0.24\n")
    result = run(LOCKS / "uv_compiled.txt", bad)
    assert result.returncode == 2
    assert "not a '==' pin" in result.stderr


def test_the_check_uses_the_comparison():
    # compile_requirements.sh --check is what CI runs; a text diff there
    # would bring back the failure on every Dependabot pip PR.
    script = (REPO / "scripts" / "compile_requirements.sh").read_text()
    assert 'python3 scripts/compare_locks.py "$tmp" "${dir}/requirements.txt"' in script
    assert "diff -q" not in script
