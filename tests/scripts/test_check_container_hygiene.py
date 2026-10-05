"""Tests for check_container_hygiene.py, the guard on Compose files.

The gateway's development Compose file mounted /var/run/docker.sock into an
unpinned, unmaintained log shipper (#680), and nothing read Compose files
other than the root one. These feed the checker Compose documents as text,
then run it on the repository itself.
"""

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_container_hygiene.py"
spec = importlib.util.spec_from_file_location("check_container_hygiene", SCRIPT)
cch = importlib.util.module_from_spec(spec)
# dataclasses resolves string annotations through sys.modules.
sys.modules[spec.name] = cch
spec.loader.exec_module(cch)


def compose(body: str) -> str:
    return "services:\n" + textwrap.indent(textwrap.dedent(body), "  ")


def findings(body: str, path: str = "docker-compose.yml"):
    return cch.check_compose(path, compose(body))


def rules(body: str) -> list[str]:
    return [finding.rule for finding in findings(body)]


# --- Which files are Compose files ------------------------------------------


def test_a_file_without_services_is_not_compose():
    workflow = "jobs:\n  build:\n    services:\n      db:\n        image: postgres\n"
    assert cch.load_compose(workflow) is None
    assert cch.check_compose("ci.yml", workflow) == []


def test_compose_tags_are_read_not_refused():
    text = compose("""
        db:
          image: postgres:15
          ports: !reset []
          networks: !override
            - data
        """)
    assert cch.check_compose("docker-compose.prod.yml", text) == []


def test_a_python_object_tag_is_not_constructed():
    with pytest.raises(Exception):
        cch.load_compose("services: !!python/object/apply:os.system ['true']\n")


# --- Runtime sockets ---------------------------------------------------------


@pytest.mark.parametrize(
    "volume",
    [
        "/var/run/docker.sock:/var/run/docker.sock",
        "/var/run/docker.sock:/var/run/docker.sock:ro",
        "/run/docker.sock:/tmp/d.sock:ro",
        "/run/podman/podman.sock:/var/run/docker.sock",
        "/run/containerd/containerd.sock:/c.sock",
        "${DOCKER_SOCK:-/var/run/docker.sock}:/var/run/docker.sock:ro",
        "/var/run:/host/run:ro",
        "/:/host:ro",
    ],
)
def test_a_runtime_socket_mount_is_refused(volume):
    found = findings(f"""
        logviewer:
          image: gliderlabs/logspout:v3.2.14
          volumes:
            - "{volume}"
        """)
    assert [f.rule for f in found] == ["socket"]
    assert found[0].subject.startswith("logviewer:")


def test_a_socket_in_long_volume_syntax_is_refused():
    assert rules("""
        agent:
          image: example/agent:1.2.3
          volumes:
            - type: bind
              source: /var/run/docker.sock
              target: /var/run/docker.sock
              read_only: true
        """) == ["socket"]


def test_ordinary_mounts_pass():
    assert rules("""
            sensor:
              image: example/sensor:1.0.0
              volumes:
                - /proc/stat:/host/proc/stat:ro
                - ./config.yaml:/etc/sensor/config.yaml:ro
                - sensor_data:/var/lib/sensor
                - /app/__pycache__
                - type: volume
                  source: logs
                  target: /var/log/sensor
            """) == []


# --- Images ------------------------------------------------------------------


@pytest.mark.parametrize(
    "image",
    [
        "gliderlabs/logspout:latest",
        "gliderlabs/logspout",
        "nginx",
        "nginx:alpine",
        "nginx:stable-alpine",
        "registry.example.com:5000/team/app",
        "registry.example.com:5000/team/app:latest",
        "redis:${REDIS_TAG}",
        "redis:${REDIS_TAG:-latest}",
    ],
)
def test_an_image_without_a_version_is_refused(image):
    assert rules(f"svc:\n  image: {image}\n") == ["image"]


@pytest.mark.parametrize(
    "image",
    [
        "redis:7-alpine",
        "postgres:15",
        "nginx:1.30-alpine",
        "prom/prometheus:v2.55.1",
        "registry.example.com:5000/team/app:1.4.2",
        "redis:${REDIS_TAG:-7-alpine}",
        "nginx@sha256:" + "a" * 64,
        "nginx:alpine@sha256:" + "a" * 64,
    ],
)
def test_an_image_with_a_version_passes(image):
    assert rules(f"svc:\n  image: {image}\n") == []


def test_each_unversioned_image_is_told_why():
    assert "has no tag" in cch.image_problem("gliderlabs/logspout")
    assert cch.image_problem("gliderlabs/logspout:latest") == (
        "floats with upstream; name a version"
    )
    assert "'alpine' names no version" in cch.image_problem("nginx:alpine")


def test_a_tag_from_a_variable_without_default_cannot_be_verified():
    # The digits are in the variable's name, not in a version.
    for image in (
        "redis:${REDIS_7_TAG}",
        "redis:$REDIS_7_TAG",
        "${REGISTRY_2}/redis:7",
    ):
        assert "cannot be verified" in cch.image_problem(image), image
    assert rules("svc:\n  image: redis:${REDIS_7_TAG}\n") == ["image"]


def test_the_name_of_a_built_image_is_not_checked():
    assert rules("svc:\n  build: .\n  image: wildbox/svc\n") == []


# --- Privileges --------------------------------------------------------------


@pytest.mark.parametrize(
    "setting",
    [
        "privileged: true",
        "cap_add: [SYS_PTRACE]",
        "devices: ['/dev/kmsg:/dev/kmsg']",
        "network_mode: host",
        "pid: host",
        "ipc: host",
        "userns_mode: host",
        "cgroup: host",
        "security_opt: ['seccomp:unconfined']",
        "security_opt: ['apparmor=unconfined']",
    ],
)
def test_a_privileged_setting_is_refused(setting):
    assert rules(f"svc:\n  image: example/svc:1.0.0\n  {setting}\n") == ["privilege"]


def test_hardening_settings_pass():
    assert rules("""
            svc:
              image: example/svc:1.0.0
              privileged: false
              cap_drop: [ALL]
              security_opt: ['no-new-privileges:true']
              network_mode: bridge
            """) == []


# --- Ports -------------------------------------------------------------------


@pytest.mark.parametrize(
    "port, subject",
    [
        ('"6379:6379"', "redis:6379"),
        ('"6382:6379"', "redis:6382"),
        ("'3000:3000'", "redis:3000"),
        ('"0.0.0.0:6379:6379"', "redis:6379"),
        ('"6379:6379/tcp"', "redis:6379"),
        ('"6379"', "redis:6379"),
        ("6379", "redis:6379"),
        ('"${REDIS_PORT:-6379}:6379"', "redis:6379"),
        ('"[::]:6379:6379"', "redis:6379"),
    ],
)
def test_a_port_on_every_interface_is_refused(port, subject):
    found = findings(f"redis:\n  image: redis:7-alpine\n  ports:\n    - {port}\n")
    assert [(f.rule, f.subject) for f in found] == [("port", subject)]


def test_a_port_in_long_syntax_on_every_interface_is_refused():
    found = findings("""
        redis:
          image: redis:7-alpine
          ports:
            - target: 6379
              published: 6380
        """)
    assert [(f.rule, f.subject) for f in found] == [("port", "redis:6380")]


@pytest.mark.parametrize(
    "port",
    [
        '"127.0.0.1:6379:6379"',
        '"127.0.0.1:6382:6379/tcp"',
        '"[::1]:6379:6379"',
        '"${BIND:-127.0.0.1}:6379:6379"',
        "{target: 6379, published: 6379, host_ip: 127.0.0.1}",
    ],
)
def test_a_loopback_port_passes(port):
    assert rules(f"redis:\n  image: redis:7-alpine\n  ports:\n    - {port}\n") == []


def test_no_ports_pass():
    assert rules("redis:\n  image: redis:7-alpine\n  ports: []\n") == []


# --- Reporting ---------------------------------------------------------------


def test_a_finding_names_the_line():
    text = compose("""
        gateway:
          build: .
        logviewer:
          image: gliderlabs/logspout:latest
          volumes:
            - /var/run/docker.sock:/var/run/docker.sock:ro
        """)
    found = {f.rule: f for f in cch.check_compose("dev.yml", text)}
    assert text.splitlines()[found["image"].line - 1].strip() == (
        "image: gliderlabs/logspout:latest"
    )
    assert "docker.sock" in text.splitlines()[found["socket"].line - 1]
    assert (
        found["socket"].render().startswith(f"dev.yml:{found['socket'].line}: socket ")
    )


# --- Allow-list --------------------------------------------------------------


def test_an_allowlisted_finding_is_dropped():
    found = findings("gateway:\n  build: .\n  ports:\n    - '443:443'\n")
    allowlist, errors = cch.read_allowlist(
        "port  docker-compose.yml  gateway:443  # the entry point\n"
    )
    assert errors == []
    assert cch.apply_allowlist(found, allowlist) == ([], [])


def test_the_allowlist_matches_rule_file_and_subject():
    found = findings("gateway:\n  build: .\n  ports:\n    - '443:443'\n")
    for entry in (
        "image  docker-compose.yml  gateway:443  # wrong rule",
        "port  other/docker-compose.yml  gateway:443  # wrong file",
        "port  docker-compose.yml  gateway:80  # wrong port",
    ):
        allowlist, _ = cch.read_allowlist(entry + "\n")
        remaining, stale = cch.apply_allowlist(found, allowlist)
        assert remaining == found
        assert len(stale) == 1


def test_an_entry_without_a_reason_is_an_error():
    _, errors = cch.read_allowlist("port  docker-compose.yml  gateway:443\n")
    assert len(errors) == 1 and "no reason" in errors[0]
    _, errors = cch.read_allowlist("port  docker-compose.yml  gateway:443  #  \n")
    assert len(errors) == 1 and "no reason" in errors[0]


def test_a_malformed_entry_is_an_error():
    _, errors = cch.read_allowlist("docker-compose.yml  # two fields short\n")
    assert len(errors) == 1 and "expected" in errors[0]
    _, errors = cch.read_allowlist("anything  docker-compose.yml  x  # unknown rule\n")
    assert len(errors) == 1 and "not a rule" in errors[0]


def test_comments_and_blank_lines_are_skipped():
    assert cch.read_allowlist("# a comment\n\n   \n") == ({}, [])


# --- A whole tree ------------------------------------------------------------


def write_tree(root: Path, files: dict) -> None:
    for name, text in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def run(root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), *extra],
        capture_output=True,
        text=True,
        check=False,
    )


GOOD = compose(
    "redis:\n  image: redis:7-alpine\n  ports:\n    - '127.0.0.1:6379:6379'\n"
)
LOGSPOUT = compose("""
    logviewer:
      image: gliderlabs/logspout:latest
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock:ro
    """)


def test_a_clean_tree_passes(tmp_path):
    write_tree(tmp_path, {"docker-compose.yml": GOOD})
    result = run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "1 Compose file(s) checked" in result.stdout


def test_the_logspout_service_fails_wherever_the_file_is(tmp_path):
    write_tree(
        tmp_path,
        {
            "docker-compose.yml": GOOD,
            "open-security-gateway/docker-compose.dev.yml": LOGSPOUT,
        },
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert "socket [logviewer:/var/run/docker.sock]" in result.stderr
    assert "image [logviewer:gliderlabs/logspout:latest]" in result.stderr


def test_a_compose_file_under_any_name_is_checked(tmp_path):
    write_tree(
        tmp_path,
        {"docker-compose.yml": GOOD, ".github/ci/stack.yaml": LOGSPOUT},
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert ".github/ci/stack.yaml" in result.stderr


def test_an_unreadable_compose_file_fails(tmp_path):
    write_tree(
        tmp_path,
        {"docker-compose.yml": GOOD, "docker-compose.dev.yml": "services:\n  a: [\n"},
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert "docker-compose.dev.yml: cannot be read as YAML" in result.stderr


def test_a_tree_without_compose_files_fails(tmp_path):
    write_tree(tmp_path, {"README.md": "nothing here\n"})
    result = run(tmp_path)
    assert result.returncode == 1
    assert "no Compose file found" in result.stderr


def test_a_stale_allowlist_entry_fails(tmp_path):
    write_tree(
        tmp_path,
        {
            "docker-compose.yml": GOOD,
            "scripts/container_hygiene_allowlist.txt": (
                "port  docker-compose.yml  redis:6379  # was public once\n"
            ),
        },
    )
    result = run(tmp_path)
    assert result.returncode == 1
    assert "matches no finding" in result.stderr


def test_the_allowlist_file_is_honoured(tmp_path):
    write_tree(
        tmp_path,
        {
            "docker-compose.yml": compose(
                "gateway:\n  build: .\n  ports:\n    - '443:443'\n"
            ),
            "scripts/container_hygiene_allowlist.txt": (
                "port  docker-compose.yml  gateway:443  # the entry point\n"
            ),
        },
    )
    result = run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "1 finding(s) allow-listed" in result.stdout


# --- The repository ----------------------------------------------------------


def test_the_repository_passes():
    result = run(REPO)
    assert result.returncode == 0, result.stderr


def test_the_repository_mounts_no_runtime_socket_even_allowlisted():
    allowlist, errors = cch.read_allowlist(
        (REPO / "scripts" / "container_hygiene_allowlist.txt").read_text(
            encoding="utf-8"
        )
    )
    assert errors == []
    assert [key for key in allowlist if key[0] in ("socket", "privilege")] == []


def test_the_gateway_dev_stack_has_no_log_shipper():
    text = (REPO / "open-security-gateway" / "docker-compose.dev.yml").read_text(
        encoding="utf-8"
    )
    services = cch.load_compose(text)["services"]
    assert "logviewer" not in services
    assert cch.check_compose("open-security-gateway/docker-compose.dev.yml", text) == []
