"""Tests for check_container_hygiene.py, the guard on Compose files and Dockerfiles.

The gateway's development Compose file mounted /var/run/docker.sock into an
unpinned, unmaintained log shipper (#680), and nothing read Compose files
other than the root one. Four Dockerfiles upgraded pip from PyPI, unpinned,
before their hash-checked install, and all eight let pip download setuptools
to build the shared package (#657). These feed the checker Compose documents
and Dockerfiles as text, then run it on the repository itself.
"""

import fnmatch
import importlib.util
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

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
          image: postgres:15@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
          image: gliderlabs/logspout:v3.2.14@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          volumes:
            - "{volume}"
        """)
    assert [f.rule for f in found] == ["socket"]
    assert found[0].subject.startswith("logviewer:")


def test_a_socket_in_long_volume_syntax_is_refused():
    assert rules("""
        agent:
          image: example/agent:1.2.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          volumes:
            - type: bind
              source: /var/run/docker.sock
              target: /var/run/docker.sock
              read_only: true
        """) == ["socket"]


def test_ordinary_mounts_pass():
    assert rules("""
            sensor:
              image: example/sensor:1.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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


DIGEST = "@sha256:" + "a" * 64


@pytest.mark.parametrize(
    "image",
    [
        "redis:7-alpine",
        "postgres:15",
        "nginx:1.30-alpine",
        "prom/prometheus:v3.13.4",
        "registry.example.com:5000/team/app:1.4.2",
        "redis:${REDIS_TAG:-7-alpine}",
    ],
)
def test_an_image_with_a_version_and_its_digest_passes(image):
    assert rules(f"svc:\n  image: {image}{DIGEST}\n") == []
    # The tag alone was accepted before #726: it is published again with
    # every rebuild upstream, so the same file ran different code.
    found = findings(f"svc:\n  image: {image}\n")
    assert [f.rule for f in found] == ["image"]
    assert "can be published again" in found[0].message
    assert found[0].subject == f"svc:{image}"


def test_a_default_that_carries_the_digest_passes():
    assert rules("svc:\n  image: ${REDIS_IMAGE:-redis:7-alpine" + DIGEST + "}\n") == []


@pytest.mark.parametrize(
    "image, says",
    [
        ("nginx" + DIGEST, "has a digest and no tag"),
        ("registry.example.com:5000/team/app" + DIGEST, "has a digest and no tag"),
        ("nginx:alpine" + DIGEST, "'alpine' names no version"),
        ("nginx:latest" + DIGEST, "floats with upstream"),
        ("redis:7-alpine@sha256:abc123", "is not a SHA-256 digest"),
        ("redis:7-alpine@sha512:" + "a" * 128, "is not a SHA-256 digest"),
        ("redis:7-alpine@" + "a" * 64, "is not a SHA-256 digest"),
        ("redis:7-alpine@sha256:" + "A" * 64, "is not a SHA-256 digest"),
    ],
)
def test_a_digest_does_not_replace_the_version(image, says):
    found = findings(f"svc:\n  image: {image}\n")
    assert [f.rule for f in found] == ["image"]
    assert says in found[0].message


def test_outside_compose_a_version_is_enough():
    # check_workflow_pins.py uses the same function for `docker://` actions,
    # which the repository pins by tag like every other action.
    assert cch.image_problem("alpine:3.20") is None
    assert cch.image_problem("alpine" + DIGEST) is None
    assert cch.image_problem("alpine:latest") is not None
    assert "can be published again" in cch.image_problem("alpine:3.20", digest=True)
    assert cch.image_problem("alpine:3.20" + DIGEST, digest=True) is None


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
    assert rules(
        f"svc:\n  image: example/svc:1.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  {setting}\n"
    ) == ["privilege"]


def test_hardening_settings_pass():
    assert rules("""
            svc:
              image: example/svc:1.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
    found = findings(
        f"redis:\n  image: redis:7-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  ports:\n    - {port}\n"
    )
    assert [(f.rule, f.subject) for f in found] == [("port", subject)]


def test_a_port_in_long_syntax_on_every_interface_is_refused():
    found = findings("""
        redis:
          image: redis:7-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
    assert (
        rules(
            f"redis:\n  image: redis:7-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  ports:\n    - {port}\n"
        )
        == []
    )


def test_no_ports_pass():
    assert (
        rules(
            "redis:\n  image: redis:7-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  ports: []\n"
        )
        == []
    )


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


# --- Dockerfiles: parsing ------------------------------------------------------

BASE = "python:3.11-slim@sha256:" + "9" * 64
GOOD_DOCKERFILE = f"""\
FROM {BASE}
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements.txt
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-cache-dir --no-index --no-deps --no-build-isolation /tmp/open-security-shared
"""


def dockerfile(body: str) -> str:
    return f"FROM {BASE}\n" + textwrap.dedent(body)


def docker_findings(body: str, path: str = "svc/Dockerfile"):
    return cch.check_dockerfile(path, dockerfile(body))


def docker_rules(body: str) -> list:
    return [finding.rule for finding in docker_findings(body)]


def test_instructions_are_joined_across_continuations_and_comments():
    text = textwrap.dedent("""\
        # syntax=docker/dockerfile:1
        FROM scratch
        RUN pip install --no-cache-dir --upgrade pip \\
            # a comment inside the instruction

            && pip install --require-hashes -r requirements.txt
        CMD ["true"]
        """)
    parsed = cch.parse_dockerfile(text)
    assert [(i.keyword, i.line) for i in parsed] == [
        ("FROM", 2),
        ("RUN", 3),
        ("CMD", 7),
    ]
    assert "a comment" not in parsed[1].value
    assert parsed[1].value.endswith("-r requirements.txt")


def test_a_here_document_belongs_to_its_instruction():
    text = textwrap.dedent("""\
        FROM scratch
        RUN <<EOF
        pip install --upgrade pip
        EOF
        RUN echo done
        """)
    parsed = cch.parse_dockerfile(text)
    assert [i.keyword for i in parsed] == ["FROM", "RUN", "RUN"]
    assert "pip install --upgrade pip" in parsed[1].value
    assert [f.rule for f in cch.check_dockerfile("Dockerfile", text)] == ["pip"]


def test_a_here_string_swallows_nothing():
    text = "FROM scratch\nRUN cat <<<EOF\nRUN pip install --upgrade pip\n"
    assert [f.rule for f in cch.check_dockerfile("Dockerfile", text)] == ["pip"]
    unclosed = "FROM scratch\nRUN cat <<EOF\nRUN pip install --upgrade pip\n"
    assert [f.rule for f in cch.check_dockerfile("Dockerfile", unclosed)] == ["pip"]


def test_shell_commands_are_split_at_operators():
    script = (
        'ARCH=$(dpkg --print-architecture) && if [ "$ARCH" = amd64 ]; '
        'then curl -fsSL "https://x/y z" -o f; fi | cat'
    )
    assert cch.shell_commands(script) == [
        ["dpkg", "--print-architecture"],
        ["[", "$ARCH", "=", "amd64", "]"],
        ["curl", "-fsSL", "https://x/y z", "-o", "f"],
        ["fi"],
        ["cat"],
    ]


# --- Dockerfiles: base images -----------------------------------------------


def test_a_digest_pinned_base_image_passes():
    assert cch.check_dockerfile("Dockerfile", f"FROM {BASE}\n") == []
    platform = f"FROM --platform=linux/amd64 {BASE} AS b\n"
    assert cch.check_dockerfile("Dockerfile", platform) == []
    assert cch.check_dockerfile("Dockerfile", "FROM scratch\n") == []


@pytest.mark.parametrize(
    "reference",
    [
        "python:3.11-slim",
        "python",
        "python:latest",
        "node:24-alpine",
        "python@sha256:abc",
    ],
)
def test_a_base_image_without_a_digest_is_refused(reference):
    found = cch.check_dockerfile("Dockerfile", f"FROM {reference}\n")
    assert [(f.rule, f.subject, f.line) for f in found] == [
        ("base-image", reference, 1)
    ]


def test_a_stage_of_the_same_file_is_not_an_image():
    text = (
        f"FROM {BASE} AS Builder\nFROM builder AS runner\nCOPY --from=builder /a /b\n"
    )
    assert cch.check_dockerfile("Dockerfile", text) == []
    # A name that is no earlier stage is an image.
    found = cch.check_dockerfile("Dockerfile", "FROM builder\n")
    assert [f.rule for f in found] == ["base-image"]


def test_a_base_image_from_a_build_argument():
    pinned = f"ARG BASE={BASE}\nFROM ${{BASE}}\n"
    assert cch.check_dockerfile("Dockerfile", pinned) == []
    floating = "ARG BASE=python:3.11-slim\nFROM $BASE\n"
    assert [f.rule for f in cch.check_dockerfile("Dockerfile", floating)] == [
        "base-image"
    ]
    unknown = cch.check_dockerfile("Dockerfile", "ARG BASE\nFROM ${BASE}\n")
    assert [f.rule for f in unknown] == ["base-image"]
    assert "cannot be verified" in unknown[0].message


def test_copy_from_an_image_needs_a_digest():
    latest = "COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv\n"
    assert docker_rules(latest) == ["base-image"]
    tagged = "COPY --from=ghcr.io/astral-sh/uv:0.9.1 /uv /bin/uv\n"
    assert docker_rules(tagged) == ["base-image"]
    pinned = "COPY --from=ghcr.io/astral-sh/uv@sha256:" + "a" * 64 + " /uv /bin/uv\n"
    assert docker_rules(pinned) == []
    # A named build context or a stage index is not an image reference.
    assert docker_rules("COPY --from=shared . /tmp/shared\nCOPY --from=0 /a /b\n") == []


# --- Dockerfiles: pip -------------------------------------------------------


@pytest.mark.parametrize(
    "run",
    [
        "pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements.txt",
        "pip install --require-hashes --no-build-isolation --prefix=/install -r requirements.txt",
        "pip install --require-hashes --no-build-isolation --prefix /install -r requirements.txt",
        "pip install --require-hashes --only-binary :all: -r requirements.txt",
        "pip install --require-hashes --only-binary=:all: --requirement requirements.txt",
        "pip3 install --require-hashes --no-build-isolation -r a.txt -r b.txt",
        "python -m pip install --require-hashes --no-build-isolation -r requirements.txt",
        "pip install --no-cache-dir --no-index --no-deps --no-build-isolation /tmp/open-security-shared",
        "pip install --no-index --no-deps --no-build-isolation -e .",
        "pip install --no-index --find-links /wheels ./pkg",
        "pip --version",
        "pip check",
        "pip list",
    ],
)
def test_a_verified_pip_install_passes(run):
    assert docker_rules(f"RUN {run}\n") == []


@pytest.mark.parametrize(
    "run, says",
    [
        # The four images of #657, and the same for the other installers.
        ("pip install --no-cache-dir --upgrade pip", "installs pip from PyPI unpinned"),
        ("pip install -U pip setuptools wheel", "installs pip, setuptools, wheel"),
        ("pip install 'setuptools>=64'", "installs setuptools"),
        ("python -m pip install --upgrade pip", "installs pip"),
        ("python3 -m pip install --upgrade pip", "installs pip"),
        ("/usr/local/bin/pip3.11 install --upgrade pip", "installs pip"),
        ("pip --no-cache-dir install --upgrade pip", "installs pip"),
        ("pip --cache-dir /tmp/c install --upgrade pip", "installs pip"),
        ("uv pip install --system --upgrade pip", "installs pip"),
        # Not hash-checked at all.
        ("pip install --no-cache-dir -r requirements.txt", "not hash-checked"),
        ("pip install --no-cache-dir watchdog", "not hash-checked"),
        ("pip install watchdog==6.0.0", "not hash-checked"),
        ("pip install https://example.com/pkg-1.0.tar.gz", "not hash-checked"),
        ("pip download -d /wheels -r requirements.txt", "not hash-checked"),
        ("pip wheel -w /wheels -r requirements.txt", "not hash-checked"),
        # Hash-checked, but something is still fetched without a hash.
        (
            "pip install --require-hashes -r requirements.txt",
            "build dependencies downloaded unhashed",
        ),
        (
            "pip install --require-hashes --only-binary numpy -r requirements.txt",
            "build dependencies downloaded unhashed",
        ),
        (
            "pip install --require-hashes --no-build-isolation -r requirements.txt watchdog",
            "names watchdog next to --require-hashes",
        ),
        (
            "pip install --require-hashes --no-build-isolation -r requirements.txt -e .",
            "names . next to --require-hashes",
        ),
        ("pip install --require-hashes --no-build-isolation", "without -r"),
        # A local path, which is not enough to keep pip off the index.
        ("pip install --no-deps /tmp/open-security-shared", "without --no-index"),
        ("pip install -e .", "without --no-index"),
        ("pip install .", "without --no-index"),
        # --no-index does not stop a direct URL, a remote wheel directory or a file.
        ("pip install --no-index https://example.com/pkg.whl", "although --no-index"),
        (
            "pip install --no-index git+https://example.com/pkg.git",
            "although --no-index",
        ),
        (
            "pip install --no-index -f https://example.com/wheels ./pkg",
            "although --no-index",
        ),
        ("pip install --no-index -r requirements.txt", "-r without --require-hashes"),
        ("pip install --no-index watchdog", "although --no-index"),
    ],
)
def test_an_unverified_pip_install_is_refused(run, says):
    found = docker_findings(f"RUN {run}\n")
    assert [f.rule for f in found] == ["pip"], found
    assert says in found[0].message
    assert found[0].line == 2


def test_the_upgrade_before_the_hashed_install_is_refused():
    # open-security-cspm/Dockerfile:37 as it stood (#657).
    found = docker_findings("""\
        COPY requirements.txt .
        RUN pip install --no-cache-dir --upgrade pip \\
            # --require-hashes: refuse an artefact whose hash does not match the lockfile
            # (WILDBO-DEP-04).
            && pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements.txt
        """)
    assert [(f.rule, f.subject, f.line) for f in found] == [
        ("pip", "pip install --no-cache-dir --upgrade pip", 3)
    ]


@pytest.mark.parametrize(
    "run",
    [
        "apt-get update && pip install --upgrade pip && rm -rf /var/lib/apt/lists/*",
        "set -eux; pip install --upgrade pip; echo done",
        "if [ -f requirements.txt ]; then pip install --upgrade pip; fi",
        "PIP_NO_CACHE_DIR=1 pip install --upgrade pip",
        "sudo pip install --upgrade pip",
        "true || pip install --upgrade pip",
        "(cd /app && pip install --upgrade pip)",
        "--mount=type=cache,target=/root/.cache/pip pip install --upgrade pip",
    ],
)
def test_pip_is_found_wherever_it_stands_in_the_script(run):
    assert docker_rules(f"RUN {run}\n") == ["pip"]


def test_pip_in_onbuild_and_here_documents_is_found():
    assert docker_rules("ONBUILD RUN pip install --upgrade pip\n") == ["pip"]
    assert docker_rules("RUN <<EOF\nset -e\npip install --upgrade pip\nEOF\n") == [
        "pip"
    ]


@pytest.mark.parametrize(
    "run",
    [
        # A script handed to a shell is one quoted word of the outer command.
        'bash -c "pip install --upgrade pip"',
        "/bin/sh -ec 'set -u; pip install --upgrade pip'",
        "eval 'pip install --upgrade pip'",
        # Exec form.
        '["pip", "install", "--upgrade", "pip"]',
        '["/bin/sh", "-c", "pip install --upgrade pip"]',
    ],
)
def test_pip_inside_a_nested_shell_or_exec_form_is_found(run):
    assert docker_rules(f"RUN {run}\n") == ["pip"]


def test_exec_form_of_a_verified_install_passes():
    run = '["pip", "install", "--no-index", "--no-deps", "/tmp/open-security-shared"]'
    assert docker_rules(f"RUN {run}\n") == []
    assert docker_rules('RUN ["echo", "[not json"\n') == []


def test_pip_outside_run_is_not_an_install():
    assert docker_rules('CMD ["pip", "install", "--upgrade", "pip"]\n') == []
    assert docker_rules("ENV HINT='pip install --upgrade pip'\n") == []


# --- Dockerfiles: npm -------------------------------------------------------


@pytest.mark.parametrize(
    "run",
    [
        "npm ci",
        "npm ci --omit=dev",
        "npm run build",
        "npm install -g pnpm@9.12.3",
        "npm i --global npm@10.9.0 corepack@0.31.0",
        "yarn global add serve@14.2.4",
        "yarn install --frozen-lockfile",
        "pnpm install --frozen-lockfile",
        "npm cache clean --force",
    ],
)
def test_a_locked_npm_install_passes(run):
    assert docker_rules(f"RUN {run}\n") == []


@pytest.mark.parametrize(
    "run, says",
    [
        ("npm install -g pnpm", "without an exact version"),
        ("npm i -g pnpm@latest", "without an exact version"),
        ("npm install --global pnpm@9", "without an exact version"),
        ("npm install -g pnpm@^9.1.0", "without an exact version"),
        ("yarn global add serve", "without an exact version"),
        ("pnpm add -g serve", "without an exact version"),
        ("npm install", "resolves versions at build time"),
        ("npm install --omit=dev", "resolves versions at build time"),
        ("yarn install", "resolves versions at build time"),
        ("npm install left-pad", "without an exact version"),
        ("npm install left-pad@1.3.0", "outside the lockfile"),
    ],
)
def test_an_unlocked_npm_install_is_refused(run, says):
    found = docker_findings(f"RUN {run}\n")
    assert [f.rule for f in found] == ["npm"], found
    assert says in found[0].message


# --- Dockerfiles: OS packages -------------------------------------------------

CLEAN = "rm -rf /var/lib/apt/lists/*"


@pytest.mark.parametrize(
    "install, subject",
    [
        ("apt-get install -y gcc curl", "apt-get install -y gcc curl"),
        ("apt install -y gcc", "apt install -y gcc"),
        ("apt-get -y install gcc", "apt-get -y install gcc"),
        ("apt-get -o Acquire::Retries=3 install -y gcc", None),
        ("DEBIAN_FRONTEND=noninteractive apt-get install -y gcc", None),
        ("apt-get install -y --no-install-suggests gcc", None),
        ("apt-get -o APT::Install-Recommends=true install -y gcc", None),
        ("apt-get build-dep -y python3", None),
        ("apt-get dist-upgrade -y", None),
        ('sh -c "apt-get install -y gcc"', "apt-get install -y gcc"),
    ],
)
def test_an_apt_install_with_recommends_is_refused(install, subject):
    found = docker_findings(f"RUN apt-get update && {install} && {CLEAN}\n")
    assert [f.rule for f in found] == ["os-packages"], found
    assert "--no-install-recommends" in found[0].message
    if subject:
        assert found[0].subject == subject


@pytest.mark.parametrize(
    "install",
    [
        "apt-get install -y --no-install-recommends gcc curl",
        "apt-get install --no-install-recommends -y gcc",
        "apt-get -y --no-install-recommends install gcc",
        "apt-get -o APT::Install-Recommends=false install -y gcc",
        "apt-get -o APT::Install-Recommends=0 install -y gcc",
        "apt-get install -y -o 'APT::Install-Recommends=\"no\"' gcc",
    ],
)
def test_an_apt_install_without_recommends_passes(install):
    assert docker_rules(f"RUN apt-get update && {install} && {CLEAN}\n") == []


def test_apt_commands_that_install_nothing_are_not_installs():
    assert docker_rules(f"RUN apt-get update && apt-get clean && {CLEAN}\n") == []
    assert docker_rules("RUN apt-get remove -y gcc && apt-get autoremove -y\n") == []
    assert docker_rules("RUN apt-cache policy install\n") == []


def test_the_installs_issue_726_named():
    # open-security-agents/Dockerfile:21 as it stood, and the same instruction
    # in data, identity, sensor and the tools development image.
    found = docker_findings("""\
        WORKDIR /app
        RUN apt-get update && apt-get install -y \\
            gcc \\
            curl \\
            && rm -rf /var/lib/apt/lists/*
        """)
    assert [(f.rule, f.subject, f.line) for f in found] == [
        ("os-packages", "apt-get install -y gcc curl", 3)
    ]


def test_the_fallback_after_dpkg_is_an_install_too():
    # open-security-sensor/Dockerfile:46 as it stood.
    run = "RUN curl -f http://localhost/o.deb -o o.deb && { dpkg -i o.deb || apt-get install -f -y; }\n"
    found = docker_findings(run)
    assert [(f.rule, f.subject) for f in found] == [
        ("os-packages", "apt-get install -f -y")
    ]


INSTALL = "apt-get install -y --no-install-recommends gcc"


@pytest.mark.parametrize(
    "run",
    [
        f"RUN apt-get update && {INSTALL}\n",
        f"RUN apt-get update && {INSTALL}\nRUN {CLEAN}\n",
        f"RUN {CLEAN} && apt-get update && {INSTALL}\n",
        f"RUN apt-get update && {INSTALL} && apt-get clean\n",
        f"RUN apt-get update && {INSTALL} && rm -rf /var/cache/apt/*\n",
        f"RUN apt-get update && {INSTALL} && rm -f /var/lib/apt/lists/*\n",
        f"RUN apt-get update && {INSTALL} && rm -rf /var/lib/apt/lists/partial\n",
        f"RUN apt-get update && {INSTALL} && {CLEAN} && apt-get update\n",
        "RUN apt update\n",
    ],
)
def test_package_lists_left_in_the_layer_are_refused(run):
    found = docker_findings(run)
    assert [f.rule for f in found] == ["os-packages"], found
    assert "package lists" in found[0].message
    assert found[0].subject in ("apt-get update", "apt update")


@pytest.mark.parametrize(
    "tail",
    [
        "rm -rf /var/lib/apt/lists/*",
        "rm -rf /var/lib/apt/lists",
        "rm -fr /var/lib/apt/lists/",
        "rm --recursive --force /var/lib/apt/lists/*",
        "rm -rf /tmp/build /var/lib/apt/lists/*",
        "apt-get clean && rm -rf /var/lib/apt",
    ],
)
def test_package_lists_removed_in_the_same_run_pass(tail):
    assert docker_rules(f"RUN apt-get update && {INSTALL} && {tail}\n") == []


def test_a_cache_mount_keeps_the_lists_out_of_the_layer():
    mounted = (
        "RUN --mount=type=cache,target=/var/lib/apt/lists,sharing=locked "
        f"apt-get update && {INSTALL}\n"
    )
    assert docker_rules(mounted) == []
    parent = f"RUN --mount=type=cache,target=/var/lib/apt apt-get update && {INSTALL}\n"
    assert docker_rules(parent) == []
    elsewhere = (
        f"RUN --mount=type=cache,target=/root/.cache apt-get update && {INSTALL}\n"
    )
    assert docker_rules(elsewhere) == ["os-packages"]
    bind = (
        f"RUN --mount=type=bind,target=/var/lib/apt/lists apt-get update && {INSTALL}\n"
    )
    assert docker_rules(bind) == ["os-packages"]


@pytest.mark.parametrize(
    "run",
    ["apk add curl", "apk update && apk add --no-cache curl", "apk upgrade"],
)
def test_an_apk_index_left_in_the_layer_is_refused(run):
    found = docker_findings(f"RUN {run}\n")
    assert [f.rule for f in found] == ["os-packages"], found
    assert "--no-cache" in found[0].message


@pytest.mark.parametrize(
    "run",
    [
        "apk add --no-cache curl wget",
        "apk --no-cache add curl",
        "apk add curl && rm -rf /var/cache/apk/*",
        "apk del build-deps",
    ],
)
def test_an_apk_install_without_an_index_passes(run):
    assert docker_rules(f"RUN {run}\n") == []


# --- Dockerfiles: downloads -------------------------------------------------


@pytest.mark.parametrize(
    "run",
    [
        "curl -fsSL https://get.example.com/install.sh | sh",
        "curl -fsSL https://get.example.com/install.sh | sudo bash -s -- -y",
        "wget -qO- https://get.example.com/install.sh | bash",
        "curl -sSL https://install.python-poetry.org | python3 -",
        'sh -c "$(curl -fsSL https://get.example.com/install.sh)"',
        "bash <(curl -s https://get.example.com/install.sh)",
        "VERSION=`curl -s https://api.example.com/latest` && echo $VERSION",
    ],
)
def test_a_download_fed_to_a_shell_is_refused(run):
    assert "pipe-to-shell" in docker_rules(f"RUN {run}\n")


def test_a_pipe_to_something_else_is_not_a_pipe_to_a_shell():
    run = "curl -sfL https://example.com/v1/t.tgz | tar -xz -C /opt"
    assert docker_rules(f"RUN {run}\n") == ["download"]


def test_an_unchecked_download_is_refused():
    found = docker_findings("""\
        ARG TRIVY_VERSION=0.72.0
        RUN curl -sfL "https://example.com/v${TRIVY_VERSION}/trivy.tar.gz" -o /tmp/trivy.tar.gz \\
            && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
        """)
    assert [(f.rule, f.subject, f.line) for f in found] == [
        ("download", "https://example.com/v${TRIVY_VERSION}/trivy.tar.gz", 3)
    ]


def test_each_unchecked_url_is_a_finding():
    found = docker_findings("""\
        RUN wget -O a.lua https://example.com/v1/a.lua \\
            && wget -O b.lua https://example.com/v1/b.lua
        """)
    assert [f.subject for f in found] == [
        "https://example.com/v1/a.lua",
        "https://example.com/v1/b.lua",
    ]


@pytest.mark.parametrize(
    "check",
    [
        'echo "${SHA256}  /tmp/t.tgz" | sha256sum -c -',
        "sha256sum --check sums.txt",
        "sha512sum -c sums.txt",
        "printf '%s  %s\\n' abc /tmp/t.tgz | sha256sum -c -",
        "shasum -a 256 -c sums.txt",
        "gpg --batch --verify t.tgz.asc /tmp/t.tgz",
        "cosign verify-blob --key k.pub --signature t.sig /tmp/t.tgz",
    ],
)
def test_a_checked_download_passes(check):
    run = f"curl -sfL https://example.com/v1/t.tgz -o /tmp/t.tgz && {check} && tar -xzf /tmp/t.tgz"
    assert docker_rules(f"RUN {run}\n") == []


@pytest.mark.parametrize(
    "not_a_check",
    ["sha256sum /tmp/t.tgz", "md5sum -c sums.txt", "sha1sum -c sums.txt"],
)
def test_printing_a_hash_or_checking_a_weak_one_is_not_a_check(not_a_check):
    run = f"curl -sfL https://example.com/v1/t.tgz -o /tmp/t.tgz && {not_a_check}"
    assert docker_rules(f"RUN {run}\n") == ["download"]


def test_a_check_in_another_instruction_does_not_count():
    assert docker_rules(
        "RUN curl -sfL https://example.com/v1/t.tgz -o /tmp/t.tgz\n"
        "RUN echo 'abc  /tmp/t.tgz' | sha256sum -c -\n"
    ) == ["download"]


def test_a_local_request_is_not_a_download():
    assert docker_rules("RUN curl -f http://localhost:8000/health\n") == []
    healthcheck = "HEALTHCHECK CMD curl -f http://example.com/health || exit 1\n"
    assert docker_rules(healthcheck) == []


def test_add_of_a_url_needs_a_checksum():
    assert docker_rules("ADD https://example.com/v1/t.tgz /tmp/\n") == ["download"]
    pinned = (
        "ADD --checksum=sha256:" + "a" * 64 + " https://example.com/v1/t.tgz /tmp/\n"
    )
    assert docker_rules(pinned) == []
    assert docker_rules("ADD ./local.tgz /tmp/\n") == []


# --- Dockerfiles: downloads for one architecture -------------------------------

CHECKED = 'echo "${SHA256}  /tmp/t.tgz" | sha256sum -c -'


def test_the_trivy_download_issue_726_named():
    # open-security-tools/Dockerfile:58 as it stood: verified, and x86-64 on
    # every platform.
    found = docker_findings("""\
        ARG TRIVY_VERSION=0.72.0
        ARG TRIVY_SHA256=bbb64b96
        RUN curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \\
            -o /tmp/trivy.tar.gz \\
            && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \\
            && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
        """)
    assert [(f.rule, f.line) for f in found] == [("architecture", 4)]
    assert "64bit" in found[0].message and "TARGETARCH" in found[0].message


@pytest.mark.parametrize(
    "asset",
    [
        "tool_1.2.3_Linux-64bit.tar.gz",
        "tool_1.2.3_linux_amd64.deb",
        "tool-1.2.3-x86_64-unknown-linux-musl.tar.gz",
        "tool_1.2.3_linux_x64.tar.gz",
        "tool_1.2.3_Linux-ARM64.tar.gz",
        "tool-1.2.3.aarch64.rpm",
        "tool_1.2.3_linux_armv7.tar.gz",
        "tool-1.2.3-linux-s390x.tar.gz",
    ],
)
def test_a_download_for_one_architecture_is_refused(asset):
    run = f"RUN curl -fsSL https://example.com/v1.2.3/{asset} -o /tmp/t.tgz && {CHECKED}\n"
    found = docker_findings(run)
    assert [f.rule for f in found] == ["architecture"], found
    assert found[0].subject == f"https://example.com/v1.2.3/{asset}"


@pytest.mark.parametrize(
    "run",
    [
        # The tools image: the asset chosen from TARGETARCH.
        'case "${TARGETARCH}" in amd64) A=Linux-64bit ;; arm64) A=Linux-ARM64 ;; '
        "*) exit 1 ;; esac && curl -sfL https://example.com/v1/t_${A}.tar.gz -o /tmp/t.tgz",
        # The sensor image: the package named after dpkg's architecture.
        "ARCH=$(dpkg --print-architecture) && "
        'curl -fsSL "https://example.com/deb/tool_1.2.3-1.linux_${ARCH}.deb" -o /tmp/t.tgz',
        'if [ "$(dpkg --print-architecture)" = amd64 ]; then '
        "curl -fsSL https://example.com/v1/tool_linux_amd64.tgz -o /tmp/t.tgz; fi",
        'if [ "$(uname -m)" = x86_64 ]; then '
        "curl -fsSL https://example.com/v1/tool_linux_amd64.tgz -o /tmp/t.tgz; fi",
        # Not a binary: the same file on every machine.
        "curl -fsSL https://example.com/v0.17.2/lib/resty/http.lua -o /tmp/t.tgz",
        "curl -fsSL https://example.com/archive/v1.2.3.tar.gz -o /tmp/t.tgz",
        "curl -fsSL https://example.com/tool-64bits-of-entropy.txt -o /tmp/t.tgz",
    ],
)
def test_a_download_chosen_by_platform_or_for_every_platform_passes(run):
    assert docker_rules(f"ARG TARGETARCH\nRUN {run} && {CHECKED}\n") == []


def test_a_build_argument_nobody_reads_is_not_a_choice():
    # ARG TARGETARCH on its own changes nothing: the RUN must use it.
    run = (
        "ARG TARGETARCH\n"
        f"RUN curl -fsSL https://example.com/v1/tool_linux_amd64.tgz -o /tmp/t.tgz && {CHECKED}\n"
    )
    assert docker_rules(run) == ["architecture"]


def test_an_unverified_download_for_one_architecture_is_two_findings():
    run = "RUN curl -fsSL https://example.com/v1/tool_linux_amd64.tgz -o /tmp/t.tgz\n"
    assert docker_rules(run) == ["download", "architecture"]


def test_add_of_a_url_for_one_architecture_is_refused():
    pinned = "ADD --checksum=sha256:" + "a" * 64
    assert docker_rules(
        f"{pinned} https://example.com/v1/tool_linux_arm64.tgz /tmp/\n"
    ) == ["architecture"]
    assert docker_rules(f"{pinned} https://example.com/v1/tool.tgz /tmp/\n") == []


def test_the_tools_image_installs_trivy_for_its_platform():
    text = (REPO / "open-security-tools" / "Dockerfile").read_text(encoding="utf-8")
    instructions = cch.parse_dockerfile(text)
    arguments = {
        i.value.partition("=")[0]: i.value.partition("=")[2]
        for i in instructions
        if i.keyword == "ARG"
    }
    assert "TARGETARCH" in arguments
    # One recorded checksum per architecture, both full SHA-256 values.
    for name in ("TRIVY_SHA256_AMD64", "TRIVY_SHA256_ARM64"):
        assert len(arguments[name]) == 64 and int(arguments[name], 16), name
    assert arguments["TRIVY_SHA256_AMD64"] != arguments["TRIVY_SHA256_ARM64"]
    runs = [i.value for i in instructions if i.keyword == "RUN" and "trivy" in i.value]
    assert len(runs) == 1
    run = runs[0]
    assert 'case "${TARGETARCH}" in' in run
    assert 'amd64) TRIVY_ASSET=Linux-64bit; TRIVY_SHA256="${TRIVY_SHA256_AMD64}"' in run
    assert 'arm64) TRIVY_ASSET=Linux-ARM64; TRIVY_SHA256="${TRIVY_SHA256_ARM64}"' in run
    # Any other architecture stops the build before anything is downloaded.
    default = run[run.index("*)") : run.index("esac")]
    assert "exit 1" in default
    assert run.index("esac") < run.index("curl")
    # What is downloaded is what the case chose, not a name written out.
    assert "/trivy_${TRIVY_VERSION}_${TRIVY_ASSET}.tar.gz" in run
    assert run.count("Linux-64bit") == 1 and run.count("Linux-ARM64") == 1
    assert run.index("sha256sum -c") < run.index("tar -xzf")


def version_tuple(text: str) -> tuple:
    return tuple(int(part) for part in text.split("."))


def test_the_sensor_image_installs_a_supported_osquery_for_its_platform():
    # #726: 5.10.2 (October 2023) stood here. 5.23.1 is the first release
    # with the fixes of 5.23.0 and 5.23.1 in osquery itself and OpenSSL 3.6.
    text = (REPO / "open-security-sensor" / "Dockerfile").read_text(encoding="utf-8")
    runs = [
        i.value
        for i in cch.parse_dockerfile(text)
        if i.keyword == "RUN" and "osquery.deb" in i.value
    ]
    assert len(runs) == 1
    run = " ".join(runs[0].split())
    versions = re.findall(r"osquery_(\d+\.\d+\.\d+)-1\.linux_\$\{ARCH\}\.deb", run)
    assert len(versions) == 1
    assert version_tuple(versions[0]) >= (5, 23, 1), versions
    # The package of the image's architecture, one checksum each, checked
    # before dpkg runs it; any other architecture stops the build.
    assert "ARCH=$(dpkg --print-architecture)" in run
    checksums = re.findall(
        r'"\$ARCH" = "(\w+)" \]; then OSQUERY_SHA256=([0-9a-f]{64});', run
    )
    assert [arch for arch, _ in checksums] == ["amd64", "arm64"]
    assert checksums[0][1] != checksums[1][1]
    assert re.search(r'else echo "Unsupported architecture: \$ARCH" && exit 1; fi', run)
    assert run.index("sha256sum -c") < run.index("dpkg -i osquery.deb")
    # The README names the version the image installs.
    readme = (REPO / "open-security-sensor" / "README.md").read_text(encoding="utf-8")
    assert f"osquery {versions[0]}," in readme


def test_prometheus_is_a_supported_release():
    # #726: v2.55.1 stood here, the last release of a line that gets no
    # fixes. 3.13 is the long-term support line; 3.13.4 has the fixes of
    # CVE-2026-44903 and CVE-2026-42154.
    text = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    prometheus = cch.load_compose(text)["services"]["prometheus"]
    match = re.match(
        r"^prom/prometheus:v(\d+\.\d+\.\d+)(@sha256:[0-9a-f]{64})?$",
        prometheus["image"],
    )
    assert match, prometheus["image"]
    assert version_tuple(match.group(1)) >= (3, 13, 4)
    # The 3.x image has no console templates: the flags that named their
    # directories are gone with them.
    assert not [arg for arg in prometheus["command"] if "web.console" in arg]
    assert "--config.file=/etc/prometheus/prometheus.yml" in prometheus["command"]
    assert "--storage.tsdb.path=/prometheus" in prometheus["command"]


def test_a_download_can_be_allowlisted_but_pip_cannot():
    found = docker_findings("RUN curl -sfL https://example.com/v1/t.tgz -o /t.tgz\n")
    allowlist, errors = cch.read_allowlist(
        "download  svc/Dockerfile  https://example.com/v1/t.tgz  # verified by the next stage\n"
    )
    assert errors == []
    assert cch.apply_allowlist(found, allowlist) == ([], [])
    for rule in (
        "pip",
        "npm",
        "pipe-to-shell",
        "base-image",
        "os-packages",
        "architecture",
    ):
        _, errors = cch.read_allowlist(f"{rule}  svc/Dockerfile  x  # because\n")
        assert len(errors) == 1 and "not a rule" in errors[0], rule


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
    files = {"svc/Dockerfile": GOOD_DOCKERFILE, **files}
    for name, text in files.items():
        if text is None:
            continue
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
    "redis:\n  image: redis:7-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  ports:\n    - '127.0.0.1:6379:6379'\n"
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
    assert "1 Compose file(s) and 1 Dockerfile(s) checked" in result.stdout


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


def test_a_tree_without_dockerfiles_fails(tmp_path):
    write_tree(tmp_path, {"docker-compose.yml": GOOD, "svc/Dockerfile": None})
    result = run(tmp_path)
    assert result.returncode == 1
    assert "no Dockerfile found" in result.stderr


def test_a_dockerfile_under_any_of_its_names_is_checked(tmp_path):
    bad = GOOD_DOCKERFILE + "RUN pip install --upgrade pip\n"
    for name in ("svc/Dockerfile", "svc/Dockerfile.dev", "docker/api.dockerfile"):
        tree = tmp_path / name.replace("/", "_")
        write_tree(tree, {"docker-compose.yml": GOOD, name: bad})
        result = run(tree)
        assert result.returncode == 1, name
        assert f"{name}:" in result.stderr and "pip [" in result.stderr


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


def python_dockerfiles() -> list:
    found = sorted(REPO.glob("open-security-*/Dockerfile*"))
    return [path for path in found if "pip install" in path.read_text(encoding="utf-8")]


def test_every_python_image_installs_the_same_way():
    # #657: identity, data, agents and sensor used the base image's pip, the
    # other four upgraded it first. All of them, and the tools dev image, now
    # run the same two commands. The shared package is installed offline and,
    # since #722, without --no-deps and with the extras of the modules the
    # service imports, so pip checks its requirements against the lock
    # (tests/scripts/test_check_shared_dependencies.py holds the extras).
    files = python_dockerfiles()
    assert len(files) == 9, [str(path) for path in files]
    hashed = "pip install --no-cache-dir --require-hashes --no-build-isolation"
    shared = (
        "pip install --no-cache-dir --no-index --no-build-isolation "
        "/tmp/open-security-shared"
    )
    for path in files:
        runs = [
            " ".join(command)
            for instruction in cch.parse_dockerfile(path.read_text(encoding="utf-8"))
            if instruction.keyword == "RUN"
            for command in cch.shell_commands(instruction.value)
            if cch.pip_arguments(command) is not None
        ]
        installs = [run for run in runs if run.startswith(shared)]
        assert len(installs) == 1, path
        assert installs[0][len(shared) :] in ("", "[fastapi,metrics]"), path
        lockfile = [run for run in runs if run.startswith(hashed)]
        assert len(lockfile) == 1 and lockfile[0].endswith("-r requirements.txt"), path
        for run in runs:
            assert "--upgrade" not in run and " -U" not in run, (path, run)


def test_every_image_installs_only_the_packages_it_names():
    # #726: agents, data, identity, sensor and the tools development image
    # ran `apt-get install -y` and took every recommended package with it.
    installs = []
    for path in sorted(REPO.glob("open-security-*/Dockerfile*")):
        text = path.read_text(encoding="utf-8")
        name = str(path.relative_to(REPO))
        found = [f for f in cch.check_dockerfile(name, text) if f.rule == "os-packages"]
        assert found == [], [finding.render() for finding in found]
        for instruction in cch.parse_dockerfile(text):
            if instruction.keyword != "RUN":
                continue
            for command in cch.shell_commands(cch.run_script(instruction.value)):
                if command[:2] == ["apt-get", "install"]:
                    installs.append((name, command))
                    assert "--no-install-recommends" in command, (name, command)
                    assert "rm -rf /var/lib/apt/lists/*" in instruction.value, name
                    # The C library headers are a recommendation of gcc: left
                    # out, the compiler is installed and compiles nothing.
                    if "gcc" in command:
                        assert {"libc6-dev", "g++", "build-essential"} & set(command), (
                            name,
                            "gcc without the C library headers",
                        )
    # One per Debian-based image, two in the two-stage cspm image. A count
    # that drops means the loop above stopped seeing them.
    assert len(installs) == 10, [name for name, _ in installs]


def test_no_dockerfile_exception_is_allowlisted():
    allowlist, _ = cch.read_allowlist(
        (REPO / "scripts" / "container_hygiene_allowlist.txt").read_text(
            encoding="utf-8"
        )
    )
    assert [key for key in allowlist if key[0] == "download"] == []


def compose_images() -> dict:
    """{directory: [image, ...]} for the third-party images of tracked Compose files."""
    found: dict = {}
    for name in cch.tracked_files(REPO):
        if not cch.is_yaml(name):
            continue
        try:
            document = cch.load_compose((REPO / name).read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue  # not Compose; check_tree reports a Compose file it cannot read
        if document is None:
            continue
        parent = Path(name).parent.as_posix()
        directory = "/" if parent == "." else "/" + parent
        for service in document["services"].values():
            if (
                isinstance(service, dict)
                and "image" in service
                and "build" not in service
            ):
                found.setdefault(directory, []).append(service["image"])
    return found


def dependabot_entry(ecosystem: str) -> dict:
    document = yaml.safe_load(
        (REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    )
    entries = [e for e in document["updates"] if e["package-ecosystem"] == ecosystem]
    assert len(entries) == 1, ecosystem
    return entries[0]


def test_every_compose_image_is_pinned_by_tag_and_digest():
    # #726: the tags were versions and nothing more, so `redis:7-alpine` was
    # whatever the registry served on the day of the pull.
    images = [image for group in compose_images().values() for image in group]
    assert len(images) >= 20, images
    pinned = re.compile(r"^[\w./-]+:[\w.-]*\d[\w.-]*@sha256:[0-9a-f]{64}$")
    for image in images:
        assert pinned.match(image), image
    # One digest per tag: the same image is the same bytes in every file.
    by_tag: dict = {}
    for image in images:
        tag, _, digest = image.partition("@")
        by_tag.setdefault(tag, set()).add(digest)
    assert {tag: digests for tag, digests in by_tag.items() if len(digests) > 1} == {}
    allowlist, _ = cch.read_allowlist(
        (REPO / "scripts" / "container_hygiene_allowlist.txt").read_text(
            encoding="utf-8"
        )
    )
    assert [key for key in allowlist if key[0] == "image"] == []


def test_dependabot_reads_every_directory_with_a_compose_image():
    # A pin nothing moves is a pin that goes stale: the "docker" ecosystem
    # reads Dockerfiles only, so nothing proposed a new tag or digest for the
    # images the Compose files run.
    entry = dependabot_entry("docker-compose")
    assert entry["schedule"]["interval"] == "weekly"
    patterns = entry["directories"]
    for directory in compose_images():
        assert any(
            fnmatch.fnmatchcase(directory, pattern) for pattern in patterns
        ), directory
    ignored = {
        rule["dependency-name"]: rule["update-types"] for rule in entry["ignore"]
    }
    # Majors are decided by hand: one in a grouped pull request holds the
    # weekly digests back with it.
    assert ignored["*"] == ["version-update:semver-major"]
    assert ignored["prom/prometheus"] == ["version-update:semver-minor"]
    assert entry["groups"]["docker-compose"]["patterns"] == ["*"]


def test_dependabot_reads_every_directory_with_a_dockerfile():
    patterns = dependabot_entry("docker")["directories"]
    directories = {
        "/" + str(Path(name).parent)
        for name in cch.tracked_files(REPO)
        if cch.is_dockerfile(name)
    }
    assert len(directories) >= 9
    for directory in directories:
        assert any(
            fnmatch.fnmatchcase(directory, pattern) for pattern in patterns
        ), directory


def test_no_compose_file_runs_a_log_shipper():
    # #680 took the logspout service out of the gateway's development file;
    # #726 removed the file, which could not start. No Compose file may bring
    # the service back.
    assert not (REPO / "open-security-gateway" / "docker-compose.dev.yml").exists()
    for path in REPO.glob("**/*compose*.y*ml"):
        if "node_modules" in path.parts:
            continue
        document = cch.load_compose(path.read_text(encoding="utf-8"))
        if document is None:
            continue
        for name, service in document["services"].items():
            assert name != "logviewer", path
            assert "logspout" not in str(service.get("image", "")), path
