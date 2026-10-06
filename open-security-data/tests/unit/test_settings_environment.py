"""The configuration is what the service reads, each value set by its variable (#665).

``app/config.py`` parsed some sixty variables into nine classes and the
service read sixteen of them. ``RATE_LIMIT_ENABLED``,
``DATA_RETENTION_DAYS``, ``BACKUP_ENABLED``, ``JWT_EXPIRATION``,
``ALLOWED_SOURCES``, ``LOG_FILE_ENABLED``, ``SENTRY_DSN`` and
``METRICS_PORT`` among them changed nothing; ``REDIS_URL`` was parsed by a
service that uses no Redis. Importing the module also created ``data/`` and
``logs/`` directories nothing wrote to.

The values are read when the module is imported, so each case imports it in a
process of its own.
"""

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
CONFIG = SERVICE_ROOT / "app" / "config.py"

BASE = {
    "ENVIRONMENT": "development",
    "SECRET_KEY": "k" * 40,
    "DATABASE_URL": "postgresql://u:p@localhost:5432/data",
}
# variable -> (path of the value in the configuration, value, what it is read as)
VARIABLES = {
    "ENVIRONMENT": ("environment", "staging", "staging"),
    "DEBUG": ("debug", "true", True),
    "DATABASE_URL": ("database.url", "postgresql://u:p@db.internal:5432/d", None),
    "DB_POOL_SIZE": ("database.pool_size", "7", 7),
    "DB_POOL_OVERFLOW": ("database.max_overflow", "3", 3),
    "DB_POOL_TIMEOUT": ("database.pool_timeout", "11", 11),
    "DB_ECHO": ("database.echo", "true", True),
    "API_HOST": ("api.host", "127.0.0.1", None),
    "API_PORT": ("api.port", "9002", 9002),
    "CORS_ENABLED": ("api.cors_enabled", "false", False),
    "CORS_ORIGINS": (
        "api.cors_origins",
        "https://a.example, https://b.example",
        ["https://a.example", "https://b.example"],
    ),
    "MAX_CONCURRENT_COLLECTORS": ("collection.max_concurrent", "2", 2),
    "SECRET_KEY": ("security.secret_key", "s" * 48, None),
    "MAX_BATCH_SIZE": ("security.max_batch_size", "25", 25),
    "LOG_LEVEL": ("logging.level", "WARNING", None),
    "LOG_FORMAT": ("logging.format", "%(message)s", None),
}
REMOVED = (
    "REDIS_URL",
    "REDIS_MAX_CONNECTIONS",
    "API_WORKERS",
    "API_TIMEOUT",
    "RATE_LIMIT_ENABLED",
    "RATE_LIMIT_REQUESTS",
    "COLLECTION_ENABLED",
    "COLLECTION_INTERVAL",
    "COLLECTION_TIMEOUT",
    "EXTERNAL_RATE_LIMIT_REQUESTS",
    "VALIDATE_COLLECTION_DATA",
    "DATA_RETENTION_DAYS",
    "FILE_STORAGE_PATH",
    "BACKUP_ENABLED",
    "JWT_ALGORITHM",
    "JWT_EXPIRATION",
    "MAX_QUERY_SIZE",
    "ALLOWED_SOURCES",
    "BLOCKED_SOURCES",
    "LOG_FILE_ENABLED",
    "LOG_FILE_PATH",
    "SENTRY_DSN",
    "MONITORING_ENABLED",
    "METRICS_PORT",
    "HEALTH_CHECK_PORT",
    "PROMETHEUS_ENABLED",
    "PROMETHEUS_PORT",
)

PROGRAM = """
import dataclasses, json
from app.config import config
print(json.dumps(dataclasses.asdict(config)))
"""


def configuration(cwd=SERVICE_ROOT, **variables):
    """The configuration a process with these variables builds, as a dict."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in VARIABLES and key not in REMOVED
    }
    env.update(BASE)
    env.update(variables)
    env["PYTHONPATH"] = str(SERVICE_ROOT)
    result = subprocess.run(
        [sys.executable, "-c", PROGRAM],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


def at(document, path):
    for key in path.split("."):
        document = document[key]
    return document


def leaves(document, prefix=""):
    for key, value in document.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            yield from leaves(value, f"{path}.")
        else:
            yield path


def variables_read():
    """Every name ``app/config.py`` asks the environment for."""
    tree = ast.parse(CONFIG.read_text(encoding="utf-8"))
    return {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", "") == "getenv"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }


@pytest.fixture(scope="module")
def default():
    return configuration()


def test_every_value_of_the_configuration_is_covered(default):
    """A value added later is added here, with the variable that sets it."""
    assert sorted(leaves(default)) == sorted(path for path, _, _ in VARIABLES.values())


def test_the_module_reads_these_variables_and_no_other():
    assert variables_read() == set(VARIABLES)


@pytest.mark.parametrize("variable", sorted(VARIABLES))
def test_the_variable_sets_the_value(default, variable):
    path, value, expected = VARIABLES[variable]
    extra = {"SECRET_KEY": BASE["SECRET_KEY"]} if variable == "ENVIRONMENT" else {}

    read = at(configuration(**{**extra, variable: value}), path)

    assert read == (value if expected is None else expected)
    assert read != at(default, path), "the value would not show the variable was read"


def test_what_nothing_read_changes_nothing(default):
    """All of them at once, with values the removed parsers refused or read."""
    removed = {variable: "1" for variable in REMOVED}
    removed["REDIS_URL"] = "redis://nowhere.invalid:6379/0"
    removed["FILE_STORAGE_PATH"] = "/nonexistent/files"
    removed["LOG_FILE_PATH"] = "/nonexistent/logs/app.log"

    assert configuration(**removed) == default
    assert not variables_read() & set(REMOVED)


def test_importing_the_configuration_creates_no_directory(tmp_path):
    """It made data/, data/files/ and logs/ beside the code, for nothing."""
    before = sorted(path.name for path in SERVICE_ROOT.iterdir())

    configuration(cwd=tmp_path)

    assert sorted(path.name for path in SERVICE_ROOT.iterdir()) == before
    assert list(tmp_path.iterdir()) == []
