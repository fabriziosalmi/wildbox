"""CI cannot skip the script tests that need Docker (#723).

test_backup_restore.py and the rotation tests start a throwaway PostgreSQL or
Redis and skip where Docker is missing. A skipped test is green, so a runner
without Docker, or a test with a skip of its own, would leave the backup,
restore and rotation scripts untested without anyone noticing.

Two things keep that from happening, and each has a test here:

- the workflow step that runs tests/scripts sets
  WILDBOX_REQUIRE_DOCKER_TESTS=1;
- with that variable set, tests/scripts/conftest.py turns every skipped test
  in this directory into a failed one.
"""

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CONFTEST = Path(__file__).with_name("conftest.py")
VARIABLE = "WILDBOX_REQUIRE_DOCKER_TESTS"


def _runs_the_script_tests(run):
    """True when a line of the script is a pytest command on tests/scripts."""
    for line in run.splitlines():
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        if "-m" in words[:2]:
            words = words[2:]  # python -m pytest ...
        if words[:1] == ["pytest"] and any(
            word.rstrip("/") == "tests/scripts" or word.startswith("tests/scripts/")
            for word in words[1:]
        ):
            return True
    return False


def _steps_running_the_script_tests():
    """(workflow, job, step) for every step that runs pytest on tests/scripts."""
    found = []
    for workflow in sorted(WORKFLOWS.glob("*.y*ml")):
        document = yaml.safe_load(workflow.read_text())
        for job_name, job in (document.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                if _runs_the_script_tests(step.get("run") or ""):
                    found.append((workflow.name, job_name, job, step))
    return found


def test_the_ci_step_that_runs_these_tests_requires_docker():
    steps = _steps_running_the_script_tests()
    assert steps, "no workflow runs pytest on tests/scripts"
    for workflow, job_name, job, step in steps:
        # A step's own env, or the job's: both reach the pytest process.
        env = {**(job.get("env") or {}), **(step.get("env") or {})}
        assert str(env.get(VARIABLE)) == "1", (
            f"{workflow}: job '{job_name}' runs tests/scripts without "
            f"{VARIABLE}=1, so its Docker tests could be skipped"
        )
        # The whole directory, not a selection that could leave a file out.
        assert " -k " not in step["run"] and "--deselect" not in step["run"]


SAMPLE_TESTS = """\
import pytest


def test_needs_docker(docker):
    pass


def test_skips_for_a_reason_of_its_own():
    pytest.skip("a reason of its own")


@pytest.mark.skipif(True, reason="marked")
def test_is_marked_to_skip():
    pass


def test_runs():
    pass
"""


@pytest.fixture
def sample(tmp_path):
    """A directory with this conftest.py and four tests, away from the repo."""
    (tmp_path / "conftest.py").write_text(CONFTEST.read_text())
    (tmp_path / "test_sample.py").write_text(SAMPLE_TESTS)
    # A PATH of its own, with no docker on it: a CI runner has a real one.
    tools = tmp_path / "tools"
    tools.mkdir()

    def run(**extra):
        # This interpreter's own environment, so it finds pytest again.
        env = {k: v for k, v in os.environ.items() if k != VARIABLE}
        env["PATH"] = str(tools)
        env.update(extra)
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(tmp_path),
                "-q",
                "-rA",
                "-p",
                "no:cacheprovider",
                "--rootdir",
                str(tmp_path),
            ],
            env=env,
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=120,
        )

    return run


def test_without_the_variable_a_missing_docker_skips(sample):
    result = sample()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed, 3 skipped" in result.stdout


def test_with_the_variable_no_test_is_skipped(sample):
    result = sample(**{VARIABLE: "1"})
    assert result.returncode == 1, result.stdout + result.stderr
    # A skip in the test body is reported as a failure, one decided before
    # the body runs (a fixture, a marker) as an error: three in all.
    summary = result.stdout.splitlines()[-1]
    counts = {word: int(n) for n, word in re.findall(r"(\d+) ([a-z]+)", summary)}
    assert counts.get("failed", 0) + counts.get("errors", 0) == 3, summary
    assert counts.get("passed") == 1 and "skipped" not in counts, summary
    # Each one is named, with what skipped it.
    assert "docker is required for these tests and is not available" in result.stdout
    for name, reason in (
        ("test_skips_for_a_reason_of_its_own", "a reason of its own"),
        ("test_is_marked_to_skip", "marked"),
    ):
        assert f"{name} was skipped" in result.stdout
        assert reason in result.stdout


def test_the_variable_only_means_something_when_it_is_1(sample):
    result = sample(**{VARIABLE: "0"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "3 skipped" in result.stdout


def test_no_test_file_here_decides_about_docker_on_its_own():
    """One fixture, in conftest.py, so one place honors the variable."""
    for path in sorted(Path(__file__).parent.glob("test_*.py")):
        if path == Path(__file__):
            continue
        text = path.read_text()
        assert "_docker_available" not in text, path.name
        assert VARIABLE not in text, path.name
