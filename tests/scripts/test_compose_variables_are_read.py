"""A variable Compose passes to a container is one the container's code reads (#721, #743).

``docker-compose.prod.yml`` set ``WORKERS=4`` for the tools API and
``ENABLE_METRICS=true`` for two services. Nothing read either: an operator
who changed them changed nothing, and believed otherwise. #733 added a test
for the tools containers. This is the same rule for every service that is
built from this repository, read from the Compose files and the sources,
with nothing installed.

A name counts as read when the service's own code, or the shared package,
has it

* as a field of a pydantic ``BaseSettings`` class (the field's name in upper
  case, with the class's ``env_prefix``), or
* as a string of its own in Python: ``os.getenv("X")``, ``os.environ["X"]``,
  ``env("X")``, ``Field(alias="X")``; a mention in a comment or a docstring
  is not a read, or
* in a construct that reads the environment in JavaScript
  (``process.env.X``), Lua (``os.getenv("X")``), nginx (``env X;``), a shell
  script or template (``$X``, ``${X}``) or a Dockerfile (``ARG``, ``ENV``).

Services that run somebody else's image (PostgreSQL, Redis, n8n, Prometheus,
Alertmanager) are not checked: what those images read is in their own
documentation, not in this tree.
"""

import ast
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.dev.yml",
)
SHARED = ROOT / "open-security-shared"

# Read by what runs the code, not by the code: the language runtime, the
# framework or the base image. Each with where it is read.
READ_BY_THE_RUNTIME = {
    "NODE_ENV": "Node.js and Next.js",
    "PORT": "the Next.js standalone server",
    "HOSTNAME": "the Next.js standalone server",
    "NEXT_TELEMETRY_DISABLED": "Next.js",
    "PYTHONUNBUFFERED": "the Python interpreter",
    "PYTHONDONTWRITEBYTECODE": "the Python interpreter",
    "PYTHONPATH": "the Python interpreter",
    "DJANGO_SETTINGS_MODULE": "Django",
    "TZ": "the C library",
}

# Found by this test and not fixed here: variables a Compose file passes that
# the service's code does not read. They are left for the cross-service
# cleanup (#665). An entry that no longer applies fails the test, so the
# list cannot outlive what it lists; a new unread variable fails it too.
KNOWN_UNREAD = {
    "docker-compose.yml": {
        "gateway": {
            "ENVIRONMENT",
            "GATEWAY_LOG_LEVEL",
            "NGINX_ENVSUBST_OUTPUT_DIR",
            "WILDBOX_ENV",
        },
        "dashboard": {
            "ENVIRONMENT",
            "NEXT_PUBLIC_DEBUG",
            "NEXTAUTH_SECRET",
            "NEXTAUTH_URL",
        },
        "guardian": {"LOG_FILE"},
        "sensor": {"LOG_LEVEL"},
    },
    "docker-compose.prod.yml": {
        "gateway": {"ENVIRONMENT", "LOG_LEVEL"},
        # The overlay sets production on every service the base file gives
        # the variable to (#736); the dashboard is one, and reads none.
        "dashboard": {"ENVIRONMENT"},
        # The origins guardian allows are a list written in its settings: the
        # overlay's value changes nothing.
        "guardian": {"CORS_ALLOWED_ORIGINS"},
        "identity": {"LOG_LEVEL", "REDIS_PASSWORD"},
        "responder": {"WORKER_CONCURRENCY"},
        "agents": {"WORKER_CONCURRENCY", "CELERY_WORKER_PREFETCH_MULTIPLIER"},
    },
    "docker-compose.dev.yml": {
        "dashboard": {
            "NEXT_PUBLIC_API_BASE_URL",
            "NEXT_PUBLIC_IDENTITY_API_URL",
            "NEXT_PUBLIC_GUARDIAN_API_URL",
            "NEXT_PUBLIC_RESPONDER_API_URL",
            "NEXT_PUBLIC_AGENTS_API_URL",
            "NEXTAUTH_SECRET",
            "NEXTAUTH_URL",
        },
    },
}

SKIPPED_DIRECTORIES = {
    "node_modules",
    ".next",
    "tests",
    "test",
    "e2e",
    "__pycache__",
    "docs",
    "build",
    "venv",
    ".venv",
    "migrations",
}
ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]*\Z")
OTHER_SOURCES = {
    ".lua",
    ".conf",
    ".sh",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
    ".cjs",
    ".template",
}
# How a name is read outside Python, {name} being the variable.
READS = (
    r"process\.env\.{name}\b",
    r"process\.env\[\s*['\"]{name}['\"]\s*\]",
    r"getenv\(\s*['\"]{name}['\"]",
    r"^\s*env\s+{name}\s*;",
    r"\$\{{?{name}\b",
    r"^\s*(?:ARG|ENV)\s+{name}\b",
)


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose tags such as !override as plain nodes."""


def _untagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def compose(name):
    return yaml.load((ROOT / name).read_text(encoding="utf-8"), Loader=_ComposeLoader)


def build_contexts():
    """{service: directory} for the services built from this repository."""
    contexts = {}
    for service, spec in compose("docker-compose.yml")["services"].items():
        build = spec.get("build")
        context = build.get("context") if isinstance(build, dict) else build
        if isinstance(context, str) and context.startswith("./open-security-"):
            contexts[service] = ROOT / context[2:]
    return contexts


def environment_names(spec):
    environment = (spec or {}).get("environment") or []
    if isinstance(environment, dict):
        return set(environment)
    return {str(entry).split("=", 1)[0] for entry in environment}


def source_files(directory):
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if not path.is_file() or SKIPPED_DIRECTORIES & set(relative.parts[:-1]):
            continue
        if path.name.startswith(("docker-compose", ".env")):
            continue
        yield path


def settings_fields(tree):
    """Environment names of the BaseSettings fields in one module."""
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {getattr(base, "id", getattr(base, "attr", "")) for base in node.bases}
        if not bases & {"BaseSettings", "Settings"}:
            continue
        prefix = ""
        for inner in ast.walk(node):
            if isinstance(inner, ast.keyword) and inner.arg == "env_prefix":
                prefix = getattr(inner.value, "value", "") or ""
            if (
                isinstance(inner, ast.Assign)
                and getattr(inner.targets[0], "id", "") == "env_prefix"
            ):
                prefix = getattr(inner.value, "value", "") or ""
        for inner in node.body:
            target = getattr(inner, "target", None)
            if isinstance(inner, ast.AnnAssign) and isinstance(target, ast.Name):
                names.add((prefix + target.id).upper())
    return names


def names_read_in(directory):
    """Every environment name the sources under ``directory`` read.

    Returns the names read in Python, the text of the other sources, and
    whether the Python code imports the shared package.
    """
    names = set()
    other = []
    uses_shared = False
    for path in source_files(directory):
        if path.suffix == ".py":
            text = path.read_text(encoding="utf-8")
            uses_shared = uses_shared or "open_security_shared" in text
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            names |= settings_fields(tree)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and ENVIRONMENT_NAME.match(node.value)
                ):
                    names.add(node.value)
        elif path.suffix in OTHER_SOURCES or path.name.startswith("Dockerfile"):
            other.append(path.read_text(encoding="utf-8", errors="ignore"))
    return names, "\n".join(other), uses_shared


_READ = {}


def is_read(name, directory):
    if directory not in _READ:
        names, text, uses_shared = names_read_in(directory)
        if uses_shared:
            # What the shared package reads, it reads in this container too.
            names |= names_read_in(SHARED)[0]
        _READ[directory] = (names, text)
    names, text = _READ[directory]
    if name in names:
        return True
    return any(
        re.search(pattern.format(name=re.escape(name)), text, re.M) for pattern in READS
    )


def unread_variables():
    """{file: {service: {names}}} passed by a Compose file and read by nothing."""
    contexts = build_contexts()
    found = {}
    for file in COMPOSE_FILES:
        for service, spec in (compose(file).get("services") or {}).items():
            if service not in contexts:
                continue
            unread = {
                name
                for name in environment_names(spec)
                if name not in READ_BY_THE_RUNTIME
                and not is_read(name, contexts[service])
            }
            if unread:
                found.setdefault(file, {})[service] = unread
    return found


# --- the check works -----------------------------------------------------------


def test_the_services_built_here_are_found():
    contexts = build_contexts()

    assert {
        "identity",
        "api",
        "tools-worker",
        "data",
        "gateway",
        "dashboard",
        "guardian",
        "guardian-worker",
        "responder",
        "agents",
        "cspm",
        "sensor",
    } <= set(contexts)
    # Other people's images are not checked.
    assert not {"postgres", "wildbox-redis", "prometheus", "alertmanager"} & set(
        contexts
    )


@pytest.mark.parametrize(
    "service, name",
    [
        ("api", "REDIS_URL"),  # a settings field
        ("api", "GATEWAY_INTERNAL_SECRET"),  # os.getenv in the shared package
        ("api", "USER_PERMISSIONS_FILE"),  # os.getenv in the service
        ("gateway", "GATEWAY_INTERNAL_SECRET"),  # os.getenv in Lua
        ("guardian", "ALLOWED_HOSTS"),  # Django settings
        ("dashboard", "NEXT_PUBLIC_GATEWAY_URL"),  # process.env
    ],
)
def test_a_variable_the_code_reads_is_seen_as_read(service, name):
    assert is_read(name, build_contexts()[service]), (service, name)


@pytest.mark.parametrize(
    "name", ["WORKERS", "ENABLE_METRICS", "METRICS_PORT", "NO_SUCH_SETTING"]
)
@pytest.mark.parametrize("service", ["api", "identity", "gateway", "dashboard"])
def test_a_variable_nothing_reads_is_seen_as_unread(service, name):
    assert not is_read(name, build_contexts()[service]), (service, name)


def test_a_name_in_a_comment_or_a_docstring_is_not_a_read(tmp_path):
    (tmp_path / "config.py").write_text(
        '"""Reads nothing. WORKERS used to be set."""\n'
        "# WORKERS=4 was read by nothing\n"
        "import os\n"
        'LEVEL = os.getenv("LOG_LEVEL", "INFO")\n',
        encoding="utf-8",
    )

    assert is_read("LOG_LEVEL", tmp_path)
    assert not is_read("WORKERS", tmp_path)


def test_a_settings_field_is_read_under_its_prefix(tmp_path):
    (tmp_path / "config.py").write_text(
        "from pydantic_settings import BaseSettings, SettingsConfigDict\n"
        "class Settings(BaseSettings):\n"
        '    model_config = SettingsConfigDict(env_prefix="APP_")\n'
        "    log_level: str = 'INFO'\n",
        encoding="utf-8",
    )

    assert is_read("APP_LOG_LEVEL", tmp_path)
    assert not is_read("LOG_LEVEL", tmp_path)


# --- the tree -------------------------------------------------------------------------


def test_every_variable_compose_passes_is_read_by_the_code():
    """Exactly the known list is unread: nothing new, and nothing fixed but still listed."""
    assert unread_variables() == KNOWN_UNREAD


def test_the_variables_of_721_and_743_are_gone():
    for file in COMPOSE_FILES:
        for service, spec in (compose(file).get("services") or {}).items():
            names = environment_names(spec)
            assert "WORKERS" not in names, (file, service)
            assert "ENABLE_METRICS" not in names, (file, service)


def test_the_example_env_file_does_not_offer_them():
    assigned = re.findall(
        r"^\s*#?\s*([A-Z][A-Z0-9_]*)=", (ROOT / ".env.example").read_text("utf-8"), re.M
    )

    assert "DATABASE_URL" in assigned  # the file was read
    assert not {"ENABLE_METRICS", "METRICS_PORT", "WORKERS"} & set(assigned)
