"""Every requirement a service declares is imported by it, or is listed here.

The eight ``requirements.in`` files had grown by accretion: the data service
locked spaCy, scikit-learn, pandas and plotly, guardian the clients of
Tenable, Qualys, Jira and ServiceNow, the sensor an MQTT client, and no line
of their code imported any of them (#665). Each one was built into the image,
scanned for advisories and upgraded for them: ``multidict`` and ``yarl`` were
in the cspm image only because of an ``aiohttp`` nobody imported.

A requirement is in use when a Python file of the service imports it, tests
included. Some are in use without an import: a database driver SQLAlchemy
loads from the URL, an application named in Django's ``INSTALLED_APPS``, a
server started from a command line, a pytest plugin, a floor for a package
another requirement brings in. Those are in ``USED_WITHOUT_IMPORT``, each
with what uses it, and the table must be exact: a requirement that is neither
imported nor listed fails, and so does an entry whose requirement was removed
or is imported now.

The import scan is static (``ast``), over every ``.py`` file of the service's
directory, in functions too. The table says which module a distribution
provides when the two names differ.

The lock made from a ``requirements.in`` is what the service's image installs,
so a test runner or a linter named there is shipped, with everything it
brings: guardian's image held pytest, black, flake8, isort, mypy and
pre-commit with virtualenv and nodeenv, the data service's the same and an
HTTP client only ``TestClient`` used (#777 for the sensor, #788 for the six
others). No lock names one now. The unit-test job installs the test runner on
top of each lock, and for a service whose tests need more, that too; the
second half of this file holds the job to what the tests import.
"""

import ast
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

SERVICES = (
    "agents",
    "cspm",
    "data",
    "guardian",
    "identity",
    "responder",
    "sensor",
    "tools",
)

# The modules a distribution provides, where they are not the distribution's
# own name with underscores.
MODULES = {
    "dj-database-url": ("dj_database_url",),
    "django-celery-beat": ("django_celery_beat",),
    "django-filter": ("django_filters",),
    "djangorestframework": ("rest_framework",),
    "dnspython": ("dns",),
    "drf-spectacular": ("drf_spectacular",),
    "fastapi-users": ("fastapi_users", "fastapi_users_db_sqlalchemy"),
    "python-dateutil": ("dateutil",),
    "python-dotenv": ("dotenv",),
    "python-whois": ("whois",),
    "pyyaml": ("yaml",),
    "sentry-sdk": ("sentry_sdk",),
}

CLI = "started from a command line"
METRICS = (
    "required by the `metrics` extra of open-security-shared, which the image installs"
)
ENV_FILE = "pydantic-settings reads the settings' env_file with it"
DJANGO_SETTING = "named in guardian/settings.py"

# Requirements no file of the service imports, and what uses each.
USED_WITHOUT_IMPORT = {
    "agents": {
        "uvicorn": CLI + " (scripts/entrypoint.sh)",
        "python-dotenv": ENV_FILE,
        "prometheus-client": METRICS,
    },
    "cspm": {
        "python-dotenv": ENV_FILE,
        "prometheus-client": METRICS,
    },
    "data": {
        "psycopg2-binary": "SQLAlchemy's driver for a postgresql:// URL",
        "prometheus-client": METRICS,
    },
    "guardian": {
        "django-cors-headers": DJANGO_SETTING + " (INSTALLED_APPS, MIDDLEWARE)",
        "django-extensions": DJANGO_SETTING + " (INSTALLED_APPS when DEBUG)",
        "django-celery-results": DJANGO_SETTING + " (INSTALLED_APPS)",
        "django-redis": DJANGO_SETTING + " (CACHES)",
        "whitenoise": DJANGO_SETTING + " (MIDDLEWARE, STORAGES)",
        "psycopg2-binary": "Django's driver for PostgreSQL",
        "redis": "Celery's broker transport and django-redis",
        "gunicorn": CLI + " (Dockerfile)",
    },
    "identity": {
        "asyncpg": "SQLAlchemy's driver for postgresql+asyncpg://, and scripts/init.sh",
        "python-multipart": "FastAPI needs it to read the login form of fastapi-users",
        "email-validator": "pydantic's EmailStr, which app/schemas.py uses, needs it",
        "cryptography": "a floor for the package PyJWT verifies signatures with",
        "prometheus-client": METRICS,
    },
    "responder": {
        "python-dotenv": ENV_FILE,
        "prometheus-client": METRICS,
    },
    # Nothing: its lock holds what the sensor imports. Its test runner and
    # linters are the ones the workflows install (#777).
    "sensor": {},
    "tools": {
        "python-dotenv": ENV_FILE,
        "aiodns": "aiohttp resolves names with it when it is installed"
        " (tests/unit/test_dns_resolver.py)",
        "flower": CLI + " (tools-flower in docker-compose.yml)",
    },
}

_SKIPPED_PARTS = frozenset({"node_modules", "venv", ".venv", "__pycache__", "build"})
_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def canonical(name: str) -> str:
    """A distribution's name as PyPI compares it."""
    return re.sub(r"[-_.]+", "-", name).lower()


def declared(text: str) -> set[str]:
    """The distributions a requirements.in names, comments and options aside."""
    names = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _NAME.match(line)
        assert match, f"cannot read the requirement {line!r}"
        names.add(canonical(match.group(1)))
    return names


def imported(source: str) -> set[str]:
    """The top-level modules a source file imports, wherever in the file."""
    modules = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def imported_by(directory: Path) -> set[str]:
    modules = set()
    for path in sorted(directory.rglob("*.py")):
        if _SKIPPED_PARTS & set(path.relative_to(directory).parts):
            continue
        modules |= imported(path.read_text(encoding="utf-8"))
    return modules


def modules_of(distribution: str) -> tuple[str, ...]:
    return MODULES.get(distribution, (distribution.replace("-", "_"),))


def not_imported(requirements: set[str], modules: set[str]) -> set[str]:
    """The requirements none of whose modules is imported."""
    lowered = {module.lower() for module in modules}
    return {
        name
        for name in requirements
        if not any(module.lower() in lowered for module in modules_of(name))
    }


# --- The helpers -------------------------------------------------------------


def test_a_requirement_line_is_read_without_its_version_extras_and_marker():
    text = """
        # a comment
        -r other.txt
        uvicorn[standard]==0.32.1
        PyYAML==6.0.2   # trailing
        pydantic>=2.10.0,<3.0.0
        pywin32==308 ; sys_platform == "win32"
        typing_extensions
        """
    assert declared(text) == {
        "uvicorn",
        "pyyaml",
        "pydantic",
        "pywin32",
        "typing-extensions",
    }


def test_an_import_counts_wherever_it_is():
    source = """
import os.path, yaml
from sqlalchemy.ext.asyncio import AsyncSession
from . import sibling
from .models import Thing

def late():
    try:
        import redis.asyncio as aioredis
    except ImportError:
        aioredis = None
"""
    assert imported(source) == {"os", "yaml", "sqlalchemy", "redis"}


def test_a_requirement_is_matched_by_the_module_it_provides():
    requirements = {"pyyaml", "python-dateutil", "pydantic-settings", "spacy", "django"}
    modules = {"yaml", "pydantic_settings", "django", "os"}
    assert not_imported(requirements, modules) == {"python-dateutil", "spacy"}


# --- The repository ----------------------------------------------------------


@pytest.mark.parametrize("service", SERVICES)
def test_every_requirement_is_imported_or_listed_with_its_use(service):
    directory = REPO / f"open-security-{service}"
    requirements = declared((directory / "requirements.in").read_text(encoding="utf-8"))
    unimported = not_imported(requirements, imported_by(directory))
    listed = set(USED_WITHOUT_IMPORT[service])

    unused = sorted(unimported - listed)
    assert not unused, (
        f"open-security-{service}/requirements.in declares {unused}, which no "
        "file of the service imports. Remove the line and compile the lock "
        "(make lock), or say in USED_WITHOUT_IMPORT what uses it."
    )
    stale = sorted(listed - unimported)
    assert not stale, (
        f"USED_WITHOUT_IMPORT[{service!r}] lists {stale}, which the service "
        "imports now or no longer declares. Remove the entry."
    )


def test_every_service_with_a_lock_is_checked():
    locked = {
        path.parent.name.removeprefix("open-security-")
        for path in REPO.glob("open-security-*/requirements.in")
    }
    assert locked == set(SERVICES)
    assert set(USED_WITHOUT_IMPORT) == set(SERVICES)


def test_the_module_table_names_declared_requirements_only():
    everything = set()
    for service in SERVICES:
        path = REPO / f"open-security-{service}" / "requirements.in"
        everything |= declared(path.read_text(encoding="utf-8"))
    assert set(MODULES) <= everything, sorted(set(MODULES) - everything)


def test_every_listed_use_says_what_it_is():
    for service, entries in USED_WITHOUT_IMPORT.items():
        for name, use in entries.items():
            assert name == canonical(name), (service, name)
            assert len(use) > 10, (service, name)


# --- No test tool in a lock, and what the unit-test job installs (#788) ------
#
# The lock is what the image installs. The unit-test job installs the shared
# package, the lock, the test runner and its plugins, and for a service whose
# tests need more, that too; guardian's suite runs a second time, on
# PostgreSQL, in a job of its own. Every tool is named at the version
# tests/ci-tools/requirements.in gives it.

WORKFLOW = REPO / ".github" / "workflows" / "test.yml"
CI_TOOLS = REPO / "tests" / "ci-tools" / "requirements.in"
UNIT_STEP = "- name: Install dependencies for ${{ matrix.service }}"

# A test runner, a pytest plugin, a linter, a type checker and its stubs.
NOT_FOR_AN_IMAGE = {
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "pytest-django",
    "black",
    "flake8",
    "isort",
    "mypy",
    "pre-commit",
    "django-stubs",
}
# What came with those and with nothing a service runs with. Not click,
# packaging, platformdirs, pygments, filelock or tomli: a lock may hold one
# of those on a requirement's account.
BROUGHT_BY_THEM = {
    "coverage",
    "iniconfig",
    "pluggy",
    "pycodestyle",
    "pyflakes",
    "mccabe",
    "mypy-extensions",
    "pathspec",
    "pytokens",
    "cfgv",
    "identify",
    "nodeenv",
    "virtualenv",
    "distlib",
    "python-discovery",
    "django-stubs-ext",
    "types-pytz",
    "types-pyyaml",
}
# The modules of a distribution that is in a lock without being a declared
# requirement a file of the service imports, which is all MODULES knows.
TEST_MODULES = {
    "django-cors-headers": ("corsheaders",),
    "pyjwt": ("jwt",),
}

_PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][0-9A-Za-z.]*)$")
_PIP_LINE = re.compile(
    r"^\s*(?:(?P<services>[a-z|]+)\)\s+)?pip install (?P<what>.+?)\s*(?:;;)?\s*$"
)
_TEST_CLIENTS = frozenset({"fastapi.testclient", "starlette.testclient"})


def locked(service: str) -> set[str]:
    """The distributions the service's image installs."""
    lock = REPO / f"open-security-{service}" / "requirements.txt"
    return declared(lock.read_text(encoding="utf-8"))


def pip_installs(step: str) -> list[tuple[frozenset, dict[str, str]]]:
    """(services, {tool: version}) for each ``pip install`` of pinned tools.

    The services are those of the ``case`` label the line stands under
    (``data|tools) pip install ...``), and none when the line is for every
    service. A line that installs a path or a requirements file names no
    tool and is left out.
    """
    found = []
    for line in step.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _PIP_LINE.match(line)
        if not match:
            continue
        pins = {}
        for word in match.group("what").split():
            pinned = _PINNED.match(word)
            if pinned:
                pins[canonical(pinned.group(1))] = pinned.group(2)
        if pins:
            services = frozenset((match.group("services") or "").split("|")) - {""}
            found.append((services, pins))
    return found


def tools_for(service: str, installs) -> dict[str, str]:
    """The tools a step installs in the leg of one service."""
    tools: dict[str, str] = {}
    for services, pins in installs:
        if not services or service in services:
            tools.update(pins)
    return tools


def unit_test_step() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    (step,) = text.split(UNIT_STEP)[1:]
    return step.split("- name:")[0]


def guardian_postgresql_step() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    (job,) = text.split("\n  guardian-postgres-tests:\n")[1:]
    job = re.split(r"\n  [a-z0-9-]+:\n", job)[0]
    (step,) = job.split("- name: Install dependencies\n")[1:]
    return step.split("- name:")[0]


def imported_names(source: str) -> set[str]:
    """Every module a source file imports, by its full name."""
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names


def files_of_the_tests(service: str) -> list[Path]:
    directory = REPO / f"open-security-{service}" / "tests"
    return [
        path
        for path in sorted(directory.rglob("*.py"))
        if not _SKIPPED_PARTS & set(path.relative_to(directory).parts)
    ]


def own_modules(service: str) -> set[str]:
    """What an import can name in the service's own directory."""
    directory = REPO / f"open-security-{service}"
    names = set()
    for path in directory.rglob("*.py"):
        parts = path.relative_to(directory).parts
        if not _SKIPPED_PARTS & set(parts):
            names.add(path.stem)
            names.update(parts[:-1])
    return names


def provided_modules(distributions) -> set[str]:
    modules = set()
    for name in distributions:
        modules.update(TEST_MODULES.get(name, modules_of(name)))
    return {module.lower() for module in modules}


def test_a_step_is_read_with_the_services_each_line_is_for():
    step = """
        run: |
          cd open-security-${{ matrix.service }}
          pip install ../open-security-shared
          pip install -r requirements.txt
          # pip install commented==1.0
          pip install pytest==9.1.1 pytest-cov==7.1.0
          case "${{ matrix.service }}" in
            guardian)   pip install pytest-django==4.5.2 ;;
            data|tools) pip install httpx==0.28.1 ;;
          esac
        """
    installs = pip_installs(step)
    assert installs == [
        (frozenset(), {"pytest": "9.1.1", "pytest-cov": "7.1.0"}),
        (frozenset({"guardian"}), {"pytest-django": "4.5.2"}),
        (frozenset({"data", "tools"}), {"httpx": "0.28.1"}),
    ]
    assert tools_for("guardian", installs) == {
        "pytest": "9.1.1",
        "pytest-cov": "7.1.0",
        "pytest-django": "4.5.2",
    }
    assert "httpx" in tools_for("tools", installs)
    assert "httpx" not in tools_for("identity", installs)


def test_a_lock_is_read_as_the_distributions_it_pins():
    lock = """
        # This file was autogenerated by uv
        anyio==4.14.2 \\
            --hash=sha256:0a1b \\
            --hash=sha256:2c3d
            # via starlette
        PyYAML==6.0.2 \\
            --hash=sha256:4e5f
            # via -r requirements.in
        """
    assert declared(lock) == {"anyio", "pyyaml"}


@pytest.mark.parametrize("service", SERVICES)
def test_no_lock_names_a_test_runner_or_a_linter(service):
    directory = REPO / f"open-security-{service}"
    direct = declared((directory / "requirements.in").read_text(encoding="utf-8"))
    in_the_image = locked(service)

    assert direct <= in_the_image, sorted(direct - in_the_image)
    assert len(in_the_image) >= 15, "the lock was not read"
    named = sorted(direct & NOT_FOR_AN_IMAGE)
    assert not named, (
        f"open-security-{service}/requirements.in names {named}: the lock made "
        "from it is what the image installs. The unit-test job installs the "
        "test tools (.github/workflows/test.yml), Code Quality the linters."
    )
    shipped = sorted(in_the_image & (NOT_FOR_AN_IMAGE | BROUGHT_BY_THEM))
    assert not shipped, (
        f"open-security-{service}/requirements.txt pins {shipped}, which only a "
        "test runner or a linter needs."
    )


@pytest.mark.parametrize("service", SERVICES)
def test_the_unit_test_job_installs_what_the_tests_import(service):
    tools = tools_for(service, pip_installs(unit_test_step()))
    assert {"pytest", "pytest-cov", "pytest-asyncio"} <= set(tools)
    # The job installs the shared package beside the lock.
    provided = provided_modules(locked(service) | set(tools))
    provided.add("open_security_shared")

    files = files_of_the_tests(service)
    assert len(files) >= 10, "the tests were not found"
    sources = [path.read_text(encoding="utf-8") for path in files]
    names = set().union(*(imported_names(source) for source in sources))
    needed = {name.split(".")[0] for name in names}
    needed -= set(sys.stdlib_module_names) | own_modules(service)
    missing = sorted(module for module in needed if module.lower() not in provided)
    assert "pytest" in needed
    assert not missing, (
        f"the tests of open-security-{service} import {missing}, which neither "
        "its lock nor the unit-test job provides. A library only the tests "
        "use is installed by the job, for that service, at the version "
        "tests/ci-tools/requirements.in pins; it does not go in the lock."
    )

    # What a test needs without importing it.
    if names & _TEST_CLIENTS:
        assert "httpx" in provided, (
            f"the tests of open-security-{service} use TestClient, which needs "
            "httpx: the unit-test job installs it for the services whose lock "
            "does not hold it"
        )
    ini = REPO / f"open-security-{service}" / "pytest.ini"
    if "DJANGO_SETTINGS_MODULE" in ini.read_text(encoding="utf-8"):
        assert "pytest-django" in tools, "pytest.ini's setting is pytest-django's"
    else:
        assert "pytest-django" not in tools
    if any("mark.asyncio" in source for source in sources):
        assert "pytest-asyncio" in tools


def test_some_suite_needs_each_thing_the_job_adds_for_it():
    # The cases the check above decides by: a service that uses TestClient
    # with no httpx in its lock, one whose pytest.ini is pytest-django's.
    installs = pip_installs(unit_test_step())
    for_some = {
        (service, tool)
        for services, pins in installs
        for service in services
        for tool in pins
    }
    assert for_some == {
        ("guardian", "pytest-django"),
        ("data", "httpx"),
        ("tools", "httpx"),
    }
    for service, tool in sorted(for_some):
        # Not in the image: that is why the job installs it.
        assert tool not in locked(service), (service, tool)
    for service in ("data", "tools"):
        names = set()
        for path in files_of_the_tests(service):
            names |= imported_names(path.read_text(encoding="utf-8"))
        assert names & _TEST_CLIENTS, service


def test_every_tool_of_the_unit_test_jobs_is_at_the_version_of_the_tools_lock():
    # scripts/check_workflow_pins.py compares a tool with the tools lock when
    # the lock names it; a tool it does not name would pass at any version,
    # and no hash of it would be recorded anywhere.
    pins = {}
    for line in CI_TOOLS.read_text(encoding="utf-8").splitlines():
        pinned = _PINNED.match(line.strip())
        if pinned:
            pins[canonical(pinned.group(1))] = pinned.group(2)
    assert {"pytest", "httpx", "pytest-django"} <= set(pins)

    for step in (unit_test_step(), guardian_postgresql_step()):
        for _services, tools in pip_installs(step):
            for tool, version in tools.items():
                assert pins.get(tool) == version, (tool, version)


def test_the_guardian_postgresql_job_installs_the_tools_of_the_unit_test_leg():
    # The same suite on another database: the same test tools, at the same
    # versions. It measures no coverage, so it has no use for pytest-cov.
    unit = tools_for("guardian", pip_installs(unit_test_step()))
    installs = pip_installs(guardian_postgresql_step())
    assert all(not services for services, _pins in installs)
    postgresql = tools_for("guardian", installs)

    del unit["pytest-cov"]
    assert postgresql == unit
    assert "pytest-django" in postgresql
