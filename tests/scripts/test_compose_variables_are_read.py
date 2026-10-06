"""A variable Compose passes to a container is one the container's code reads (#721, #743).

``docker-compose.prod.yml`` set ``WORKERS=4`` for the tools API and
``ENABLE_METRICS=true`` for two services. Nothing read either: an operator
who changed them changed nothing, and believed otherwise. #733 added a test
for the tools containers. This is the same rule for every service that is
built from this repository, read from the Compose files and the sources,
with nothing installed.

A name counts as read when the service's own code, or a module of the shared
package that this code imports (#665: any module of the package used to
count, so guardian, which imports ``scopes`` only, passed for reading
``ENVIRONMENT`` because ``security_middleware`` does), has it

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
import sys
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

# Variables a Compose file passes that the service's code does not read. None
# is left: the cross-service cleanup removed the ones this test first listed
# (#665), and #756 the gateway's. A new unread variable fails the test; it is
# removed from the Compose file, or the code is made to read it, and nothing
# is added here without the reason beside it.
KNOWN_UNREAD = {}

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


PACKAGE = "open_security_shared"


def python_names(tree):
    """The environment names one parsed Python module reads."""
    names = settings_fields(tree)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and ENVIRONMENT_NAME.match(node.value)
        ):
            names.add(node.value)
    return names


def shared_exports():
    """{name: module} of what ``from open_security_shared import name`` loads."""
    tree = ast.parse((SHARED / "__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and node.targets[0].id == "_EXPORTS":
            return ast.literal_eval(node.value)
    raise AssertionError("open-security-shared/__init__.py has no _EXPORTS")


def shared_modules_imported(tree, exports):
    """The modules of the shared package one parsed Python module imports."""
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            dotted = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            dotted = [node.module]
            if node.module == PACKAGE:
                # A name the package exports lazily, or a module of it.
                modules |= {exports.get(a.name, a.name) for a in node.names}
        else:
            continue
        for name in dotted:
            parts = name.split(".")
            if parts[0] == PACKAGE and len(parts) > 1:
                modules.add(parts[1])
    return modules


def shared_names(modules):
    """What the given modules of the shared package read, and what the
    modules they import from the package read."""
    names, seen, todo = set(), set(), set(modules)
    while todo:
        module = todo.pop()
        path = SHARED / f"{module}.py"
        if module in seen or not path.exists():
            continue
        seen.add(module)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names |= python_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 1:
                if node.module:
                    todo.add(node.module.split(".")[0])
                else:
                    todo |= {alias.name for alias in node.names}
        todo |= shared_modules_imported(tree, {})
    return names


def names_read_in(directory):
    """Every environment name the sources under ``directory`` read.

    Returns the names read in Python, the text of the other sources, and
    the modules of the shared package the Python code imports.
    """
    names = set()
    other = []
    shared = set()
    exports = shared_exports()
    for path in source_files(directory):
        if path.suffix == ".py":
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            names |= python_names(tree)
            shared |= shared_modules_imported(tree, exports)
        elif path.suffix in OTHER_SOURCES or path.name.startswith("Dockerfile"):
            other.append(path.read_text(encoding="utf-8", errors="ignore"))
    return names, "\n".join(other), shared


_READ = {}


def is_read(name, directory):
    if directory not in _READ:
        names, text, shared = names_read_in(directory)
        # What a module of the shared package reads, it reads in the
        # container of a service that imports it.
        names |= shared_names(shared)
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
        # ${...} in the script the entrypoint runs (#756)
        ("gateway", "GATEWAY_RATE_LIMIT_PER_SECOND"),
        ("gateway", "GATEWAY_AUTH_RATE_LIMIT_PER_SECOND"),
        ("gateway", "GATEWAY_STATIC_RATE_LIMIT_PER_SECOND"),
        ("guardian", "ALLOWED_HOSTS"),  # Django settings
        ("dashboard", "NEXT_PUBLIC_GATEWAY_URL"),  # process.env
    ],
)
def test_a_variable_the_code_reads_is_seen_as_read(service, name):
    assert is_read(name, build_contexts()[service]), (service, name)


@pytest.mark.parametrize(
    "name",
    [
        "WORKERS",
        "ENABLE_METRICS",
        "METRICS_PORT",
        "NO_SUCH_SETTING",
        # What Compose passed the gateway until #756, read by nothing in it.
        "WILDBOX_ENV",
        "GATEWAY_LOG_LEVEL",
        "NGINX_ENVSUBST_OUTPUT_DIR",
    ],
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


# --- what the rule above cannot see (#665) ---------------------------------------


def test_a_shared_module_a_service_does_not_import_reads_nothing_for_it(
    tmp_path, monkeypatch
):
    """guardian imported ``open_security_shared.scopes`` and passed for reading
    ``ENVIRONMENT`` because another module of the package, one it does not
    import, reads it. A package of two modules, and a service that imports
    one: the service reads what that module reads, and what the modules it
    imports from the package read, and nothing of the other."""
    module = sys.modules[__name__]
    shared = tmp_path / "open-security-shared"
    shared.mkdir()
    (shared / "__init__.py").write_text(
        '_EXPORTS = {"install": "errors"}\n', encoding="utf-8"
    )
    (shared / "scopes.py").write_text(
        "from .headers import NAME\n"
        "import os\n"
        'SECRET = os.getenv("GATEWAY_INTERNAL_SECRET")\n',
        encoding="utf-8",
    )
    (shared / "headers.py").write_text(
        'import os\nNAME = os.getenv("AUTH_HEADER")\n', encoding="utf-8"
    )
    (shared / "middleware.py").write_text(
        'import os\nMODE = os.getenv("ENVIRONMENT")\n', encoding="utf-8"
    )
    (shared / "errors.py").write_text(
        'import os\nLEVEL = os.getenv("ERROR_DETAIL")\n', encoding="utf-8"
    )
    monkeypatch.setattr(module, "SHARED", shared)
    service = tmp_path / "open-security-example"
    service.mkdir()
    (service / "auth.py").write_text(
        "from open_security_shared.scopes import SECRET\n", encoding="utf-8"
    )

    _, _, imported = names_read_in(service)

    assert imported == {"scopes"}
    assert is_read("GATEWAY_INTERNAL_SECRET", service)
    # Through the module that scopes imports from the package.
    assert is_read("AUTH_HEADER", service)
    # Read by a module of the package this service does not import.
    assert "ENVIRONMENT" in shared_names({"middleware"})
    assert not is_read("ENVIRONMENT", service)
    assert not is_read("ERROR_DETAIL", service)

    # A name the package exports lazily loads the module that defines it.
    lazy = tmp_path / "open-security-lazy"
    lazy.mkdir()
    (lazy / "main.py").write_text(
        "from open_security_shared import install\n", encoding="utf-8"
    )
    assert is_read("ERROR_DETAIL", lazy)
    assert not is_read("ENVIRONMENT", lazy)


def test_guardian_is_not_given_what_only_another_service_reads():
    """The case this was found in, on the tree: guardian's code reads no
    ENVIRONMENT, and no Compose file gives it one."""
    contexts = build_contexts()

    assert not is_read("ENVIRONMENT", contexts["guardian"])
    assert is_read("ENVIRONMENT", contexts["identity"])
    for file in COMPOSE_FILES:
        services = compose(file).get("services") or {}
        for service in ("guardian", "guardian-worker", "guardian-beat"):
            assert "ENVIRONMENT" not in environment_names(services.get(service))


def test_a_lazy_export_of_the_shared_package_names_its_module():
    exports = shared_exports()
    tree = ast.parse("from open_security_shared import install_error_handlers\n")

    assert exports["install_error_handlers"] == "errors"
    assert shared_modules_imported(tree, exports) == {"errors"}


# The variables the postgres image reads, from its documentation. Its
# entrypoint ignores every other one: the production overlay set
# POSTGRES_MAX_CONNECTIONS=200 and POSTGRES_SHARED_BUFFERS=256MB, and the
# server ran with 100 connections and 128MB.
POSTGRES_IMAGE_VARIABLES = {
    "POSTGRES_PASSWORD",
    "POSTGRES_USER",
    "POSTGRES_DB",
    "POSTGRES_INITDB_ARGS",
    "POSTGRES_INITDB_WALDIR",
    "POSTGRES_HOST_AUTH_METHOD",
    "PGDATA",
}


def test_postgres_is_given_only_what_its_image_reads():
    seen = set()
    for file in COMPOSE_FILES:
        spec = (compose(file).get("services") or {}).get("postgres")
        names = environment_names(spec)
        seen |= names
        assert names <= POSTGRES_IMAGE_VARIABLES, (file, names)

    assert "POSTGRES_PASSWORD" in seen  # the service was read


def test_the_sensor_is_given_its_own_variables():
    """``DEBUG`` and ``LOG_LEVEL`` were passed to the sensor, which reads
    ``SENSOR_LOGGING_LEVEL``. ``"DEBUG"`` is a string in its code, one of its
    log levels, so the rule above took the variable for read."""
    for file in COMPOSE_FILES:
        names = environment_names((compose(file).get("services") or {}).get("sensor"))
        assert not {"DEBUG", "LOG_LEVEL"} & names, file

    base = environment_names(compose("docker-compose.yml")["services"]["sensor"])
    assert "SENSOR_LOGGING_LEVEL" in base
