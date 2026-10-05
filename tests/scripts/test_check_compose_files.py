"""Tests for check_compose_files.py, the guard on Compose files that cannot start.

Three per-service Compose files mounted paths that were never in the
repository or built a stage their Dockerfile does not have (#726), and
`docker compose config` accepted all three. These feed the checker rendered
configurations over a temporary tree, then run it on the repository with the
runner's Docker.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_compose_files.py"
spec = importlib.util.spec_from_file_location("check_compose_files", SCRIPT)
ccf = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ccf
spec.loader.exec_module(ccf)

DOCKERFILE = """\
FROM python:3.11-slim AS builder
RUN true
FROM python:3.11-slim
COPY --from=builder /install /usr/local
COPY --from=shared . /tmp/open-security-shared
COPY --from=docker.io/library/busybox:1.36 /bin/busybox /bin/busybox
COPY . .
"""


def never_ignored(_path: str) -> bool:
    return False


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    (tmp_path / "svc" / "nginx.conf").write_text("events {}\n", encoding="utf-8")
    (tmp_path / "shared").mkdir()
    return tmp_path


def build(tree: Path, **changes) -> dict:
    value = {
        "context": str(tree / "svc"),
        "dockerfile": "Dockerfile",
        "additional_contexts": {"shared": str(tree / "shared")},
    }
    value.update(changes)
    return {key: item for key, item in value.items() if item is not None}


def bind(tree: Path, relative: str, target: str = "/x") -> dict:
    return {"type": "bind", "source": str(tree / relative), "target": target}


def problems(tree: Path, service: dict, ignored=never_ignored) -> list:
    return ccf.service_problems("svc", service, tree, ignored)


def rules(tree: Path, service: dict, ignored=never_ignored) -> list:
    return [rule for rule, _ in problems(tree, service, ignored)]


# --- build -------------------------------------------------------------------


def test_a_build_that_points_at_what_exists_passes(tree):
    assert problems(tree, {"build": build(tree)}) == []
    assert problems(tree, {"build": build(tree, target="builder")}) == []
    assert problems(tree, {"build": build(tree, target="Builder")}) == []


def test_a_stage_the_dockerfile_lacks_is_refused(tree):
    # open-security-sensor/docker-compose.dev.yml as it stood: `target:
    # development` on a Dockerfile with no such stage.
    found = problems(tree, {"build": build(tree, target="development")})
    assert [rule for rule, _ in found] == ["build"]
    assert "the stage 'development'" in found[0][1]
    assert "svc/Dockerfile does not have (stages: builder)" in found[0][1]


def test_a_named_context_the_service_does_not_provide_is_refused(tree):
    # The same file gave no `shared` context to a Dockerfile that copies from it.
    found = problems(tree, {"build": build(tree, additional_contexts=None)})
    assert [rule for rule, _ in found] == ["build"]
    assert "copies --from=shared" in found[0][1]


def test_a_stage_or_an_image_is_not_a_missing_context(tree):
    text = (
        DOCKERFILE
        + "COPY --from=0 /a /a\nRUN --mount=type=bind,from=builder,target=/b true\n"
    )
    assert ccf.dockerfile_contexts(text) == {"shared"}
    mounted = (
        text + "RUN --mount=type=bind,from=wheels,target=/w --mount=from=cache true\n"
    )
    assert ccf.dockerfile_contexts(mounted) == {"shared", "wheels", "cache"}
    assert ccf.dockerfile_stages(text) == {"builder"}
    platform = "FROM --platform=$BUILDPLATFORM node:24 AS Deps\nFROM scratch\nCOPY --from=deps /a /a\n"
    assert ccf.dockerfile_stages(platform) == {"deps"}
    assert ccf.dockerfile_contexts(platform) == set()


def test_a_missing_context_dockerfile_or_additional_context_is_refused(tree):
    found = problems(tree, {"build": build(tree, context=str(tree / "gone"))})
    assert [rule for rule, _ in found] == ["build"]
    assert "build context gone does not exist" in found[0][1]
    found = problems(tree, {"build": build(tree, dockerfile="Dockerfile.dev")})
    assert [rule for rule, _ in found] == ["build"]
    assert "Dockerfile svc/Dockerfile.dev does not exist" in found[0][1]
    missing = {"shared": str(tree / "elsewhere")}
    found = problems(tree, {"build": build(tree, additional_contexts=missing)})
    assert [rule for rule, _ in found] == ["build"]
    assert "additional context 'shared' is elsewhere" in found[0][1]


def test_a_service_with_an_image_has_nothing_to_build(tree):
    assert problems(tree, {"image": "redis:7-alpine"}) == []


# --- mounts ------------------------------------------------------------------


def test_a_mount_of_a_file_that_is_not_there_is_refused(tree):
    # open-security-gateway/docker-compose.dev.yml as it stood.
    service = {
        "volumes": [
            bind(tree, "svc/test/mock-identity.conf", "/etc/nginx/conf.d/default.conf")
        ]
    }
    found = problems(tree, service)
    assert [rule for rule, _ in found] == ["mount"]
    assert (
        "mounts svc/test/mock-identity.conf at /etc/nginx/conf.d/default.conf"
        in found[0][1]
    )


def test_a_mount_of_a_directory_that_is_not_there_is_refused(tree):
    # open-security-data/docker-compose.yml as it stood.
    service = {
        "volumes": [bind(tree, "svc/grafana/dashboards"), bind(tree, "svc/nginx")]
    }
    assert rules(tree, service) == ["mount", "mount"]


def test_a_mount_of_what_exists_passes(tree):
    service = {
        "volumes": [
            bind(tree, "svc/nginx.conf"),
            bind(tree, "svc"),
            bind(tree, "shared"),
        ]
    }
    assert problems(tree, service) == []


def test_a_path_git_ignores_is_created_at_run_time(tree):
    service = {"volumes": [bind(tree, "svc/logs"), bind(tree, "svc/data")]}
    assert rules(tree, service, lambda path: path == "svc/logs") == ["mount"]
    assert rules(tree, service, lambda path: True) == []


def test_a_listed_run_time_path_passes(tree):
    listed = sorted(ccf.CREATED_AT_RUN_TIME)
    assert listed, "the list is what this test reads"
    service = {"volumes": [bind(tree, name) for name in listed]}
    assert problems(tree, service) == []
    for reason in ccf.CREATED_AT_RUN_TIME.values():
        assert len(reason.split()) >= 4, reason


def test_a_path_of_the_host_is_not_checked(tree):
    service = {
        "volumes": [
            {"type": "bind", "source": "/proc/stat", "target": "/host/proc/stat"},
            {"type": "bind", "source": "/nonexistent/on/this/host", "target": "/x"},
            {
                "type": "volume",
                "source": "pgdata",
                "target": "/var/lib/postgresql/data",
            },
        ]
    }
    assert problems(tree, service) == []


def test_a_missing_env_file_is_refused_unless_optional(tree):
    required = {"env_file": [{"path": str(tree / ".env"), "required": True}]}
    assert rules(tree, required) == ["env-file"]
    assert rules(tree, {"env_file": [str(tree / ".env")]}) == ["env-file"]
    optional = {"env_file": [{"path": str(tree / ".env"), "required": False}]}
    assert problems(tree, optional) == []
    (tree / ".env").write_text("A=1\n", encoding="utf-8")
    assert problems(tree, required) == []


def test_every_service_of_a_configuration_is_read(tree):
    config = {
        "services": {
            "b": {"volumes": [bind(tree, "svc/missing")]},
            "a": {"build": build(tree, target="development")},
            "c": {"image": "redis:7-alpine"},
        }
    }
    found = ccf.config_problems(config, tree, never_ignored)
    assert [(service, rule) for service, rule, _ in found] == [
        ("a", "build"),
        ("b", "mount"),
    ]


# --- which files are rendered together ---------------------------------------


def test_an_overlay_is_rendered_with_its_base_and_not_alone():
    files = [
        "docker-compose.yml",
        "docker-compose.prod.yml",
        "docker-compose.dev.yml",
        "open-security-tools/docker-compose.yml",
    ]
    stacks = ccf.stacks_for(files)
    assert ("docker-compose.yml",) in stacks
    assert ("open-security-tools/docker-compose.yml",) in stacks
    assert ("docker-compose.yml", "docker-compose.prod.yml") in stacks
    assert ("docker-compose.prod.yml",) not in stacks
    assert ("docker-compose.dev.yml",) not in stacks
    # A stack with a file that is not there is not rendered ...
    assert all(".github/compose.ci-ports.yml" not in stack for stack in stacks)
    # ... and is reported, so the table cannot name a file that was removed.
    assert ".github/compose.ci-ports.yml" in ccf.unknown_stack_files(files)
    # A tree without the root file has no stack to complete.
    assert ccf.unknown_stack_files(["svc/docker-compose.yml"]) == []
    covered = {name for stack in stacks for name in stack}
    assert covered == set(files)


def test_required_variables_are_found_in_both_spellings():
    text = "a: ${ONE:?needed}\nb: ${TWO?needed}\nc: ${THREE:-x}\nd: ${FOUR}\ne: $${FIVE:?x}\n"
    assert ccf.required_variables([text, "f: ${SIX:?}"]) == {
        "ONE",
        "TWO",
        "SIX",
        "FIVE",
    }


# --- The repository, with Docker ---------------------------------------------


# The `docker` fixture is the one of conftest.py: it skips where Docker is
# missing, and CI turns that skip into a failure (#723).


def run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_repository_passes(docker):
    result = run(REPO)
    assert result.returncode == 0, result.stderr


def test_every_stack_names_tracked_files():
    for stack in ccf.STACKS:
        for name in stack:
            assert (REPO / name).is_file(), name
        assert stack[0] == "docker-compose.yml", stack


def write(root: Path, files: dict) -> None:
    for name, text in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


BROKEN_MOUNT = """\
services:
  mock-identity:
    image: nginx:1.30-alpine
    volumes:
      - ./test/mock-identity.conf:/etc/nginx/conf.d/default.conf:ro
"""
BROKEN_STAGE = """\
services:
  sensor-dev:
    build:
      context: .
      dockerfile: Dockerfile
      target: development
"""
REQUIRES_A_SECRET = """\
services:
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD:?REDIS_PASSWORD is required}
"""


def test_a_file_that_renders_and_cannot_start_fails(docker, tmp_path):
    write(
        tmp_path,
        {
            "gateway/docker-compose.dev.yml": BROKEN_MOUNT,
            "sensor/docker-compose.dev.yml": BROKEN_STAGE,
            "sensor/Dockerfile": "FROM scratch\n",
        },
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert "gateway/docker-compose.dev.yml: mount [mock-identity]" in result.stderr
    assert "sensor/docker-compose.dev.yml: build [sensor-dev]" in result.stderr
    assert "the stage 'development'" in result.stderr


def test_a_required_variable_needs_no_env_file(docker, tmp_path):
    write(tmp_path, {"svc/docker-compose.yml": REQUIRES_A_SECRET})
    result = run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "1 Compose file(s) rendered in 1 stack(s)" in result.stdout


def test_a_file_that_does_not_render_fails(docker, tmp_path):
    write(
        tmp_path,
        {
            "svc/docker-compose.yml": "services:\n  a:\n    networks: [missing]\n    image: x:1\n"
        },
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert "svc/docker-compose.yml: config: does not render" in result.stderr


def test_a_tree_without_compose_files_fails(tmp_path):
    write(tmp_path, {"README.md": "nothing here\n"})
    result = run(tmp_path)
    assert result.returncode == 1
    assert "no Compose file found" in result.stderr


# --- The files #726 named ----------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "open-security-gateway/docker-compose.dev.yml",
        "open-security-data/docker-compose.yml",
        "open-security-sensor/docker-compose.dev.yml",
        "open-security-sensor/docker-compose.scale.yml",
        "open-security-sensor/nginx",
        "open-security-sensor/monitoring",
    ],
)
def test_the_files_that_could_not_start_are_gone(path):
    assert not (REPO / path).exists()


def test_the_sensor_file_starts_the_sensor_and_nothing_else():
    text = (REPO / "open-security-sensor" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    document = ccf.hygiene.load_compose(text)
    assert sorted(document["services"]) == ["sensor"]
    # No network that has to be created by hand before `docker compose up`.
    assert (
        "networks" not in document and "networks" not in document["services"]["sensor"]
    )
    assert "GRAFANA" not in text


def test_validate_docker_compose_runs_the_check():
    text = (REPO / ".github" / "workflows" / "pr-validation.yml").read_text(
        encoding="utf-8"
    )
    assert "python3 scripts/check_compose_files.py" in text
