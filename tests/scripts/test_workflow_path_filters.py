"""A path-filtered workflow runs when what it builds or runs changes (#736).

Four workflows start only for certain paths. Docker Build Validation built
nine images and was triggered by ``open-security-*/app/**``, the lock, the
Dockerfile, ``pyproject.toml`` and ``manage.py``: a change to guardian's code
(``apps/``, ``guardian/``), to the dashboard's (``src/``), to the gateway's
nginx configuration or to a service's entrypoint script changed an image
without building it. Production Stack ran ``scripts/validate_secrets.py`` and
``tests/integration/`` and was triggered by neither.

Two rules, both derived from the workflows themselves:

* a workflow matches every tracked file its steps name, every tracked file
  under a directory its steps name, and itself;
* Docker Build Validation matches every tracked file of each service it
  builds and of the shared package, other than documentation and tests.
"""

import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
BUILD_VALIDATION = "docker-build-validation.yml"


def tracked_files() -> list:
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True
    )
    return [path for path in listed.stdout.decode().split("\0") if path]


TRACKED = tracked_files()
TRACKED_SET = frozenset(TRACKED)


# --- GitHub's path filter ----------------------------------------------------


def pattern_regex(pattern: str) -> re.Pattern:
    """A ``paths`` pattern as a regular expression over a repository path.

    ``*`` stops at a slash, ``**`` does not, ``**/`` also matches nothing.
    """
    out = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("^" + "".join(out) + "$")


def triggers(patterns: list, path: str) -> bool:
    """Whether a change to ``path`` starts a workflow filtered by ``patterns``.

    Patterns are read in order and the last that matches decides; one that
    starts with ``!`` excludes.
    """
    decided = False
    for pattern in patterns:
        if pattern_regex(pattern.lstrip("!")).match(path):
            decided = not pattern.startswith("!")
    return decided


@pytest.mark.parametrize(
    "patterns, path, expected",
    [
        (["open-security-*/app/**"], "open-security-data/app/api/main.py", True),
        (
            ["open-security-*/app/**"],
            "open-security-guardian/apps/core/views.py",
            False,
        ),
        (["open-security-*/Dockerfile"], "open-security-data/Dockerfile", True),
        (["open-security-*/Dockerfile"], "open-security-data/sub/Dockerfile", False),
        (["**.md"], "docs/guides/ports.md", True),
        (["**.md"], "README.md", True),
        (["docs/**"], "docs/a/b.png", True),
        (
            ["open-security-*/**", "!open-security-*/**/*.md"],
            "open-security-data/README.md",
            False,
        ),
        (
            ["open-security-*/**", "!open-security-*/**/*.md"],
            "open-security-data/docs/x.md",
            False,
        ),
        (
            ["open-security-*/**", "!open-security-*/**/*.md"],
            "open-security-data/app/x.py",
            True,
        ),
        (["!a/**", "a/**"], "a/b", True),
        (["a/**", "!a/**"], "a/b", False),
    ],
)
def test_the_filter_reads_patterns_as_github_does(patterns, path, expected):
    assert triggers(patterns, path) is expected


# --- the workflows -----------------------------------------------------------


def filtered_workflows() -> list:
    """(workflow file name, event, patterns, the jobs as text)."""
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
        # PyYAML reads the key `on` as the boolean True.
        events = document.get("on", document.get(True)) or {}
        if not isinstance(events, dict):
            continue
        # The jobs only, re-serialised: no comments, and not the filter
        # itself, whose patterns would read as paths the workflow uses.
        body = yaml.safe_dump(document.get("jobs") or {}, width=10_000)
        for event, settings in events.items():
            patterns = (
                (settings or {}).get("paths") if isinstance(settings, dict) else None
            )
            if patterns:
                found.append((path.name, event, list(patterns), body))
    return found


FILTERED = filtered_workflows()
IDS = [f"{name}:{event}" for name, event, _, _ in FILTERED]


def named_by(body: str) -> set:
    """Tracked files a workflow names, and tracked files under directories it names."""
    named = set()
    for token in re.findall(r"[A-Za-z0-9_.][A-Za-z0-9_./-]*", body):
        if token in TRACKED_SET:
            named.add(token)
        elif "/" in token:
            prefix = token.rstrip("/") + "/"
            named.update(path for path in TRACKED if path.startswith(prefix))
    return named


def test_the_filtered_workflows_are_the_ones_this_was_written_for():
    assert sorted({name for name, _, _, _ in FILTERED}) == [
        "docker-build-validation.yml",
        "documentation-quality.yml",
        "gateway-lint.yml",
        "production-stack.yml",
    ]


@pytest.mark.parametrize("name, event, patterns, body", FILTERED, ids=IDS)
def test_a_workflow_is_triggered_by_itself(name, event, patterns, body):
    assert triggers(patterns, f".github/workflows/{name}")


@pytest.mark.parametrize("name, event, patterns, body", FILTERED, ids=IDS)
def test_a_workflow_is_triggered_by_what_its_steps_name(name, event, patterns, body):
    missing = sorted(path for path in named_by(body) if not triggers(patterns, path))
    assert (
        missing == []
    ), f"{name} ({event}) runs or reads these and is not triggered by them"


# --- Docker Build Validation -------------------------------------------------


def build_validation():
    document = yaml.safe_load(
        (WORKFLOWS / BUILD_VALIDATION).read_text(encoding="utf-8")
    )
    events = document.get("on", document.get(True))
    services = document["jobs"]["build"]["strategy"]["matrix"]["service"]
    return events["pull_request"]["paths"], services


def is_documentation_or_test(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return (
        name.endswith(".md")
        or "tests" in parts[:-1]
        or "test" in parts[:-1]
        or name.startswith("test_")
    )


def test_the_matrix_is_the_ten_images():
    _, services = build_validation()
    assert sorted(services) == sorted(
        [
            "identity",
            "tools",
            "data",
            "guardian",
            "responder",
            "agents",
            "cspm",
            "sensor",
            "gateway",
            "dashboard",
        ]
    )


def test_every_file_of_an_image_triggers_its_build():
    patterns, services = build_validation()
    directories = [f"open-security-{service}/" for service in services]
    directories.append("open-security-shared/")
    untriggered = sorted(
        path
        for path in TRACKED
        if path.startswith(tuple(directories))
        and not is_documentation_or_test(path)
        and not triggers(patterns, path)
    )
    assert untriggered == []


@pytest.mark.parametrize(
    "path",
    [
        "open-security-guardian/apps/core/views.py",
        "open-security-guardian/guardian/settings.py",
        "open-security-dashboard/src/lib/api-client.ts",
        "open-security-dashboard/package-lock.json",
        "open-security-gateway/nginx/lua/auth_handler.lua",
        "open-security-identity/scripts/init.sh",
        "open-security-sensor/sensor/api/local_api.py",
        "open-security-shared/errors.py",
        "docker-compose.yml",
    ],
)
def test_the_changes_that_did_not_build_an_image_now_do(path):
    patterns, _ = build_validation()
    assert path in TRACKED_SET or path == "docker-compose.yml"
    assert triggers(patterns, path)


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "docs/guides/ports.md",
        "open-security-data/README.md",
        "open-security-identity/tests/unit/test_cors_origins.py",
        "tests/integration/test_identity_service.py",
        "scripts/check_prose.py",
    ],
)
def test_documentation_and_tests_alone_build_nothing(path):
    patterns, _ = build_validation()
    assert not triggers(patterns, path)


# --- installs are not masked -------------------------------------------------

INSTALL = re.compile(
    r"\b(pip3? install|npm (ci|install)|uv pip install|apt-get install)\b"
)


def masked_installs() -> list:
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split(" #", 1)[0]
            if code.lstrip().startswith("#"):
                continue
            if INSTALL.search(code) and re.search(r"\|\|\s*(true|:)\s*$", code.strip()):
                found.append(f"{path.name}:{number}: {code.strip()}")
    return found


def test_no_workflow_masks_an_install_that_fails():
    # test.yml installed the shared package with `|| true`: a package that
    # did not install left the unit tests to fail later for another reason,
    # or to pass in a service that imports none of it.
    assert masked_installs() == []
