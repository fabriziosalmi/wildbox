"""Tests for check_workflow_pins.py, the guard on what the workflows install.

test.yml and pr-validation.yml installed pytest, black, flake8, isort and mypy
with no version, documentation-quality.yml its npm tools likewise, and
secret-scan.yml ran a downloaded archive nothing verified (#726). These feed
the checker steps as text, then run it on the repository itself.
"""

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_workflow_pins.py"
spec = importlib.util.spec_from_file_location("check_workflow_pins", SCRIPT)
cwp = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cwp
spec.loader.exec_module(cwp)

PINS = {"pytest": "9.1.1", "flake8": "7.4.1", "pytest-asyncio": "1.4.0"}
FILES = {
    "tests/ci-tools/requirements.txt",
    "tests/requirements.txt",
    "open-security-data/requirements.txt",
}


def findings(step: dict) -> list:
    return cwp.step_findings(step, PINS, FILES)


def rules(run: str) -> list:
    return [rule for rule, _, _ in findings({"run": run})]


# --- pip ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "run",
    [
        "pip install pytest pytest-cov pytest-asyncio",  # test.yml, unit tests
        "pip install pytest pytest-asyncio httpx pyyaml",  # test.yml, shared tests
        "pip install black flake8 isort pyyaml",  # test.yml, lint
        "pip install flake8 mypy",  # pr-validation.yml
        "pip install --quiet pytest pytest-asyncio requests httpx",
        "pip install 'pytest>=9'",
        "pip install pytest~=9.1",
        "pip install pytest==9.*",
        "pip install proselint==0.*",
        "pip install pytest==9.1.1 pytest-cov",
        "python -m pip install pytest",
        "pip3 install pytest",
        "cd svc && pip install pytest",
        "if [ -f requirements.txt ]; then pip install pytest; fi",
        "pip install git+https://example.com/x/y.git",
        "pip install --upgrade pip",
        "pip install -U pytest==9.1.1",
    ],
)
def test_an_install_without_an_exact_version_is_refused(run):
    assert rules(run) == ["pip"]


@pytest.mark.parametrize(
    "run",
    [
        "pip install pytest==9.1.1 pytest-cov==7.1.0 pytest-asyncio==1.4.0",
        "pip install --quiet 'bandit[sarif]==1.8.6'",
        "pip install proselint==0.16.0",
        "pip install --quiet --require-hashes -r tests/ci-tools/requirements.txt",
        "pip install -r tests/requirements.txt",
        "cd open-security-data && pip install -r requirements.txt",
        "pip install -r open-security-${{ matrix.service }}/requirements.txt",
        "pip install ./open-security-shared",
        "pip install ../open-security-shared || true",
        'pip install "./open-security-shared[fastapi,auth]"',
        "pip --version",
        "pip check",
    ],
)
def test_a_pinned_install_passes(run):
    assert rules(run) == []


def test_a_version_other_than_the_tools_lock_is_refused():
    found = findings({"run": "pip install pytest==9.0.3"})
    assert [rule for rule, _, _ in found] == ["pip"]
    assert "pins pytest==9.1.1" in found[0][2]
    # Names are compared the way pip compares them.
    assert rules("pip install Pytest_Asyncio==1.3.0") == ["pip"]
    assert rules("pip install Pytest_Asyncio==1.4.0") == []
    # A tool the lock does not hold only needs to be exact.
    assert rules("pip install proselint==0.16.0") == []


def test_a_requirements_file_must_be_tracked():
    found = findings({"run": "pip install -r tests/requirements-missing.txt"})
    assert [rule for rule, _, _ in found] == ["pip"]
    assert "no tracked file" in found[0][2]


def test_a_comment_or_an_echo_is_not_an_install():
    assert rules("# pip install pytest\necho done") == []
    assert rules("# curl -fsSL https://get.example.com/i.sh | sh\necho done") == []
    assert rules("echo 'run: pip install pytest'") == []


# --- npm ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "run",
    [
        "npm install -g markdownlint-cli",
        "npm install -g cspell",
        "npm install --global alex",
        "npm i -g markdown-link-check@latest",
        "npm install -g cspell@10",
        "yarn global add cspell",
        "npm install",
    ],
)
def test_an_unpinned_npm_install_is_refused(run):
    assert rules(run) == ["npm"]


@pytest.mark.parametrize(
    "run",
    [
        "npm install -g markdownlint-cli@0.49.1",
        "npm install -g cspell@10.3.6 alex@11.0.1",
        "npm ci",
        "cd open-security-dashboard\nnpm ci",
        "npx playwright install --with-deps chromium",
        "npm run build",
    ],
)
def test_a_pinned_or_locked_npm_install_passes(run):
    assert rules(run) == []


# --- downloads ---------------------------------------------------------------

ARCHIVE = "https://example.com/releases/v${VERSION}/tool_${VERSION}_linux_x64.tar.gz"


def test_an_unverified_download_is_refused():
    # secret-scan.yml as it stood.
    run = textwrap.dedent(f"""\
        VERSION=8.30.0
        curl -sSL -o /tmp/tool.tar.gz \\
          "{ARCHIVE}"
        tar -xzf /tmp/tool.tar.gz -C /tmp tool
        /tmp/tool detect --source .
        """)
    found = findings({"run": run})
    assert [(rule, subject) for rule, subject, _ in found] == [("download", ARCHIVE)]


def test_a_verified_download_passes():
    run = textwrap.dedent(f"""\
        curl -fsSL -o /tmp/tool.tar.gz "{ARCHIVE}"
        echo "${{SHA256}}  /tmp/tool.tar.gz" | sha256sum -c -
        tar -xzf /tmp/tool.tar.gz -C /tmp tool
        """)
    assert rules(run) == []


@pytest.mark.parametrize(
    "run",
    [
        "curl -fsSL https://get.example.com/install.sh | sh",
        "curl -fsSL https://get.example.com/install.sh | sudo bash -s -- -y",
        "wget -qO- https://get.example.com/install.sh | bash",
        'sh -c "$(curl -fsSL https://get.example.com/install.sh)"',
        "bash <(curl -s https://get.example.com/install.sh)",
        # A URL in a variable: nothing says where it points.
        'curl -fsSL "$INSTALLER_URL" | sh',
    ],
)
def test_a_download_fed_to_a_shell_is_refused(run):
    assert "pipe-to-shell" in rules(run)


@pytest.mark.parametrize(
    "run",
    [
        # How the workflows probe the stack they started.
        "code=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/auth/login)",
        'code=$(curl -sk --max-time 120 "https://localhost$route")',
        'if curl -fsSk "$url" >/dev/null 2>&1; then echo up; fi',
        "curl -sS -o /dev/null -D headers.txt -X OPTIONS http://127.0.0.1:8080/api/v1/x",
        "curl -f http://localhost:8000/health | python3 -m json.tool",
        "docker compose exec -T prometheus wget -q -O - http://alertmanager:9093/-/ready",
    ],
)
def test_a_request_to_the_local_stack_is_not_a_download(run):
    assert rules(run) == []


def test_a_host_that_only_starts_like_localhost_is_remote():
    assert rules("curl -o x https://localhost.example.com/x.tgz") == ["download"]
    assert rules("curl -o x https://127.0.0.1.example.com/x.tgz") == ["download"]


# --- actions -----------------------------------------------------------------


@pytest.mark.parametrize(
    "uses",
    [
        "actions/checkout@v7",
        "aquasecurity/trivy-action@v0.36.0",
        "aquasecurity/setup-trivy@v0.3.1",
        "github/codeql-action/upload-sarif@v4",
        "actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8",
        "./.github/actions/local",
        "docker://alpine:3.20",
    ],
)
def test_an_action_at_a_version_passes(uses):
    assert findings({"uses": uses}) == []


@pytest.mark.parametrize(
    "uses",
    [
        "actions/checkout",
        "actions/checkout@main",
        "actions/checkout@master",
        "actions/checkout@latest",
        "actions/checkout@release/v4",
        "actions/checkout@8e8c483",  # an abbreviated SHA can be a branch name
        "docker://alpine:latest",
        "docker://alpine",
    ],
)
def test_an_action_that_floats_is_refused(uses):
    found = findings({"uses": uses})
    assert [(rule, subject) for rule, subject, _ in found] == [("action", uses)]


def test_a_floating_action_is_told_why():
    assert "names no version" in findings({"uses": "actions/checkout"})[0][2]
    assert "'main'" in findings({"uses": "actions/checkout@main"})[0][2]


# --- A whole workflow, a whole tree ------------------------------------------

WORKFLOW = """\
name: Example
on: [push]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Install linting tools
        run: {install}
  reuse:
    uses: {reusable}
"""
GOOD_INSTALL = "pip install --require-hashes -r tests/ci-tools/requirements.txt"
GOOD_REUSABLE = "octo-org/workflows/.github/workflows/build.yml@v2"


def workflow(install: str = GOOD_INSTALL, reusable: str = GOOD_REUSABLE) -> str:
    return WORKFLOW.format(install=install, reusable=reusable)


def test_a_finding_names_the_job_and_the_step():
    problems = cwp.check_workflow(
        "w.yml", workflow(install="pip install black"), PINS, FILES
    )
    assert len(problems) == 1
    assert "w.yml: job 'lint', step 'Install linting tools': pip [" in problems[0]


def test_a_reusable_workflow_is_an_action_too():
    assert cwp.check_workflow("w.yml", workflow(), PINS, FILES) == []
    problems = cwp.check_workflow(
        "w.yml",
        workflow(reusable="octo-org/workflows/.github/workflows/b.yml@main"),
        PINS,
        FILES,
    )
    assert len(problems) == 1 and "job 'reuse'" in problems[0]


def test_an_expression_in_a_script_is_not_shell():
    run = "pip install -r open-security-${{ matrix.service }}/requirements.txt\necho '${{ toJSON(github) }}'"
    assert rules(run) == []


def test_a_file_without_jobs_is_reported():
    assert "not a workflow" in cwp.check_workflow("w.yml", "name: x\n", PINS, FILES)[0]


def write_tree(root: Path, files: dict) -> None:
    files = {
        "tests/ci-tools/requirements.in": "pytest==9.1.1\nblack==26.10.0\n",
        "tests/ci-tools/requirements.txt": "pytest==9.1.1 \\\n    --hash=sha256:00\n",
        **files,
    }
    for name, text in files.items():
        if text is None:
            continue
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_clean_tree_passes(tmp_path):
    write_tree(tmp_path, {".github/workflows/ci.yml": workflow()})
    result = run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "1 workflow(s) checked; 2 tool version(s)" in result.stdout


def test_an_unpinned_install_fails_the_tree(tmp_path):
    write_tree(
        tmp_path,
        {".github/workflows/ci.yml": workflow(install="pip install black flake8")},
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert "installs black without an exact version" in result.stderr


def test_a_version_that_differs_from_the_lock_fails_the_tree(tmp_path):
    write_tree(
        tmp_path,
        {".github/workflows/ci.yml": workflow(install="pip install black==25.1.0")},
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert "pins black==26.10.0" in result.stderr


def test_a_tree_without_workflows_fails(tmp_path):
    write_tree(tmp_path, {"README.md": "nothing here\n"})
    result = run(tmp_path)
    assert result.returncode == 1
    assert "no workflow found" in result.stderr


def test_a_tree_without_the_tools_lock_fails(tmp_path):
    write_tree(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(install="pip install black==26.10.0"),
            "tests/ci-tools/requirements.in": None,
        },
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert "tests/ci-tools/requirements.in: missing" in result.stderr


def test_a_workflow_that_is_not_yaml_fails(tmp_path):
    write_tree(tmp_path, {".github/workflows/ci.yml": "jobs:\n  a: [\n"})
    result = run(tmp_path)
    assert result.returncode == 1
    assert "ci.yml: cannot be read" in result.stderr


def test_archived_workflows_are_not_read(tmp_path):
    write_tree(
        tmp_path,
        {
            ".github/workflows/ci.yml": workflow(),
            ".github/workflows/archived/old.yml": workflow(install="pip install black"),
        },
    )
    assert run(tmp_path).returncode == 0


# --- The repository ----------------------------------------------------------


def test_the_repository_passes():
    result = run(REPO)
    assert result.returncode == 0, result.stderr


def tools_lock() -> dict:
    return cwp.read_pins(
        (REPO / "tests" / "ci-tools" / "requirements.in").read_text(encoding="utf-8")
    )


def test_the_tools_lock_pins_what_the_workflows_named():
    pins = tools_lock()
    for tool in ("pytest", "pytest-cov", "pytest-asyncio", "httpx", "pyyaml"):
        assert tool in pins, tool
    for tool in ("black", "flake8", "isort", "mypy", "requests", "psycopg2-binary"):
        assert tool in pins, tool
    compiled = cwp.read_pins(
        (REPO / "tests" / "ci-tools" / "requirements.txt").read_text(encoding="utf-8")
    )
    for tool, version in pins.items():
        assert compiled.get(tool) == version, tool
    text = (REPO / "tests" / "ci-tools" / "requirements.txt").read_text(
        encoding="utf-8"
    )
    assert text.count("--hash=sha256:") > len(compiled)


def installs(workflow_name: str) -> list:
    document = yaml.safe_load(
        (REPO / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
    )
    found = []
    for job in document["jobs"].values():
        for step in job.get("steps") or []:
            script = cwp._EXPRESSION.sub("EXPR", str(step.get("run", "")))
            for command in cwp.hygiene.shell_commands(script):
                if cwp.hygiene.pip_arguments(command) is not None:
                    found.append(" ".join(command))
    return found


def test_jobs_on_a_clean_interpreter_install_the_lock():
    lock = "pip install --quiet --require-hashes -r tests/ci-tools/requirements.txt"
    assert installs("test.yml").count(lock) == 2  # shared package tests, lint
    assert installs("integration-tests.yml") == [lock]
    assert installs("production-stack.yml") == [lock]


def test_jobs_on_a_service_lock_name_the_versions_of_the_tools_lock():
    pins = tools_lock()
    unit = (
        f"pip install pytest=={pins['pytest']} pytest-cov=={pins['pytest-cov']} "
        f"pytest-asyncio=={pins['pytest-asyncio']}"
    )
    assert unit in installs("test.yml")
    quality = f"pip install flake8=={pins['flake8']} mypy=={pins['mypy']}"
    assert quality in installs("pr-validation.yml")


def test_the_secret_scanner_is_verified_before_it_runs():
    document = yaml.safe_load(
        (REPO / ".github" / "workflows" / "secret-scan.yml").read_text(encoding="utf-8")
    )
    scripts = [
        step["run"]
        for job in document["jobs"].values()
        for step in job["steps"]
        if "gitleaks" in str(step.get("run", ""))
    ]
    assert len(scripts) == 1
    script = scripts[0]
    assert script.index("sha256sum -c") < script.index("tar -xzf")
    assert "curl -fsSL" in script  # -f: an error page is not an archive


def test_code_quality_runs_the_check():
    text = (REPO / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
    assert "python3 scripts/check_workflow_pins.py" in text
