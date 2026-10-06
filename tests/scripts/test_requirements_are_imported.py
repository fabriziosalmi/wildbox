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
"""

import ast
import re
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
TEST_PLUGIN = "pytest plugin, loaded by pytest when installed"
DEV_TOOL = "developer tool, run from a command line"
METRICS = (
    "required by the `metrics` extra of open-security-shared, which the image installs"
)
ENV_FILE = "pydantic-settings reads the settings' env_file with it"
TEST_CLIENT = "fastapi.testclient.TestClient, which the unit tests use, needs it"
DJANGO_SETTING = "named in guardian/settings.py"

# Requirements no file of the service imports, and what uses each.
USED_WITHOUT_IMPORT = {
    "agents": {
        "uvicorn": CLI + " (scripts/entrypoint.sh)",
        "python-dotenv": ENV_FILE,
        "prometheus-client": METRICS,
        "pytest-asyncio": TEST_PLUGIN,
        "black": DEV_TOOL,
    },
    "cspm": {
        "httpx": TEST_CLIENT,
        "python-dotenv": ENV_FILE,
        "prometheus-client": METRICS,
    },
    "data": {
        "psycopg2-binary": "SQLAlchemy's driver for a postgresql:// URL",
        "httpx": TEST_CLIENT,
        "prometheus-client": METRICS,
        "pytest-asyncio": TEST_PLUGIN,
        "pytest-cov": TEST_PLUGIN,
        "black": DEV_TOOL,
        "flake8": DEV_TOOL,
        "mypy": DEV_TOOL,
        "pre-commit": DEV_TOOL,
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
        "pytest-django": TEST_PLUGIN + "; pytest.ini sets its DJANGO_SETTINGS_MODULE",
        "pytest-cov": TEST_PLUGIN,
        "black": DEV_TOOL,
        "isort": DEV_TOOL,
        "flake8": DEV_TOOL,
        "pre-commit": DEV_TOOL,
        "mypy": DEV_TOOL,
        "django-stubs": "type stubs for mypy",
    },
    "identity": {
        "asyncpg": "SQLAlchemy's driver for postgresql+asyncpg://, and scripts/init.sh",
        "python-multipart": "FastAPI needs it to read the login form of fastapi-users",
        "email-validator": "pydantic's EmailStr, which app/schemas.py uses, needs it",
        "cryptography": "a floor for the package PyJWT verifies signatures with",
        "prometheus-client": METRICS,
        "pytest-asyncio": TEST_PLUGIN,
        "black": DEV_TOOL + " (Makefile)",
        "isort": DEV_TOOL + " (Makefile)",
        "flake8": DEV_TOOL + " (Makefile)",
    },
    "responder": {
        "python-dotenv": ENV_FILE,
        "prometheus-client": METRICS,
        "pytest-asyncio": TEST_PLUGIN,
        "pytest-cov": TEST_PLUGIN + " (Makefile)",
    },
    "sensor": {
        "pytest-cov": TEST_PLUGIN,
        "black": DEV_TOOL,
        "flake8": DEV_TOOL,
        "mypy": DEV_TOOL,
    },
    "tools": {
        "python-dotenv": ENV_FILE,
        "aiodns": "aiohttp resolves names with it when it is installed"
        " (tests/unit/test_dns_resolver.py)",
        "flower": CLI + " (tools-flower in docker-compose.yml)",
        "httpx": TEST_CLIENT,
        "pytest-asyncio": TEST_PLUGIN,
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
