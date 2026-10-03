"""Tests for check_test_collection.py, the guard against tests CI never runs.

open-security-agents/tests/test_basic.py sat outside tests/unit/, so no job
ran it and it went on asserting an attribute the client had lost (#582).
These feed the checker workflow dictionaries shaped like the parsed YAML, and
finally run it on the repository's own workflows.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_test_collection.py"
spec = importlib.util.spec_from_file_location("check_test_collection", SCRIPT)
ctc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctc)


def job(*runs, matrix=None, working_directory=None):
    body = {"steps": [{"run": run} for run in runs]}
    if matrix:
        body["strategy"] = {"matrix": matrix}
    if working_directory:
        body["defaults"] = {"run": {"working-directory": working_directory}}
    return body


def targets(*jobs):
    return ctc.workflow_targets({"jobs": {f"j{i}": j for i, j in enumerate(jobs)}})


# --- Reading pytest commands ----------------------------------------------


def test_a_pytest_command_contributes_its_paths():
    assert targets(job("pytest tests/shared -v")) == {"tests/shared"}


def test_python_dash_m_pytest_counts_too():
    assert targets(job("python -m pytest tests/chaos -v -s")) == {"tests/chaos"}


def test_installing_pytest_is_not_running_it():
    assert targets(job("pip install pytest pytest-cov pytest-asyncio")) == set()


def test_option_values_are_not_taken_for_paths():
    run = 'pytest tests/scripts -p no:cacheprovider -o addopts="" -k smoke --tb short'
    assert targets(job(run)) == {"tests/scripts"}


def test_a_continued_line_is_read_whole():
    run = "python -m pytest tests/integration/ \\\n  -v -rs \\\n  --junit-xml=r.xml\n"
    assert targets(job(run)) == {"tests/integration"}


def test_a_node_id_counts_as_its_file():
    assert targets(job("pytest tests/x/test_a.py::test_one")) == {"tests/x/test_a.py"}


def test_a_shell_variable_is_not_a_path():
    assert targets(job("pytest tests/unit/ $COV --cov-report=xml")) == {"tests/unit"}


def test_paths_resolve_against_cd():
    run = "cd service-a\npip install -r requirements.txt\npytest tests/unit/ -v\n"
    assert targets(job(run)) == {"service-a/tests/unit"}


def test_paths_resolve_against_the_working_directory():
    assert targets(job("pytest tests", working_directory="web")) == {"web/tests"}


def test_a_bare_pytest_collects_its_working_directory():
    assert targets(job("cd svc && pytest -q")) == {"svc"}


def test_a_matrix_is_expanded_over_its_values():
    run = "cd open-security-${{ matrix.service }}\npytest tests/unit/\n"
    found = targets(job(run, matrix={"service": ["a", "b"], "python": ["3.11"]}))
    assert found == {"open-security-a/tests/unit", "open-security-b/tests/unit"}


def test_a_matrix_key_the_job_does_not_list_resolves_to_nothing():
    run = "pytest ${{ matrix.suite }}/tests"
    assert targets(job(run, matrix={"service": ["a"]})) == set()


def test_steps_without_run_are_ignored():
    workflow = {"jobs": {"j": {"steps": [{"uses": "actions/checkout@v7"}]}}}
    assert ctc.workflow_targets(workflow) == set()


# --- Deciding what is collected -------------------------------------------


def test_a_file_under_a_target_is_collected():
    assert ctc.is_collected("svc/tests/unit/test_a.py", {"svc/tests/unit"})


def test_a_sibling_with_a_common_prefix_is_not():
    assert not ctc.is_collected("svc/tests/unit2/test_a.py", {"svc/tests/unit"})


def test_a_file_next_to_the_target_is_not():
    assert not ctc.is_collected("svc/tests/test_basic.py", {"svc/tests/unit"})


def test_only_pytest_file_names_are_test_files():
    files = [
        "a/test_x.py",
        "a/x_test.py",
        "a/testing.py",
        "a/conftest.py",
        "a/test_x.js",
    ]
    assert ctc.find_test_files(files) == ["a/test_x.py", "a/x_test.py"]


def test_the_original_gap_is_reported():
    files = [
        "open-security-agents/tests/test_basic.py",
        "open-security-agents/tests/unit/test_wildbox_client_auth.py",
    ]
    uncollected, stale = ctc.check(files, {"open-security-agents/tests/unit"}, {})
    assert uncollected == ["open-security-agents/tests/test_basic.py"]
    assert stale == []


# --- The allow-list --------------------------------------------------------


def test_an_allow_listed_file_is_not_reported():
    allow = {"svc/settings_test.py": "settings, not a test"}
    uncollected, stale = ctc.check(["svc/settings_test.py"], set(), allow)
    assert uncollected == [] and stale == []


def test_an_entry_needs_a_reason():
    entries, errors = ctc.read_allowlist("# header\n\nsvc/settings_test.py\n")
    assert entries == {"svc/settings_test.py": ""}
    assert errors and "no reason" in errors[0]


def test_an_entry_for_a_missing_file_is_stale():
    _, stale = ctc.check([], set(), {"gone/test_x.py": "reason"})
    assert stale == ["gone/test_x.py: no such tracked file"]


def test_an_entry_for_a_collected_file_is_stale():
    _, stale = ctc.check(["t/unit/test_x.py"], {"t/unit"}, {"t/unit/test_x.py": "r"})
    assert stale == ["t/unit/test_x.py: CI already collects it"]


# --- End to end -------------------------------------------------------------


def test_main_fails_on_an_uncollected_file_and_passes_without_it(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        yaml.safe_dump({"jobs": {"unit": job("pytest tests/unit")}})
    )
    (tmp_path / "tests" / "unit").mkdir(parents=True)
    (tmp_path / "tests" / "unit" / "test_ok.py").write_text("")
    (tmp_path / "tests" / "test_stray.py").write_text("")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    assert ctc.main(["--root", str(tmp_path)]) == 1

    allowlist = tmp_path / "scripts" / "test_collection_allowlist.txt"
    allowlist.parent.mkdir()
    allowlist.write_text("tests/test_stray.py  # kept out on purpose\n")
    assert ctc.main(["--root", str(tmp_path)]) == 0


def test_every_test_file_in_this_repository_is_collected():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=REPO, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "suite",
    [
        "open-security-agents/tests/unit",
        "tests/shared",
        "tests/scripts",
        "tests/integration",
    ],
)
def test_the_suites_ci_runs_are_found_in_the_real_workflows(suite):
    assert suite in ctc.collected_targets(REPO / ".github" / "workflows")
