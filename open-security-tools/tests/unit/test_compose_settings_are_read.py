"""Every variable Compose sets for the tools containers is one the service reads (#721).

``docker-compose.prod.yml`` set ``WORKERS=4`` for the API. Nothing read it:
the image starts one uvicorn process, so an operator who raised it changed
nothing. It was removed, not honored, because the API keeps state that is
one per process (see ``test_the_api_is_one_process_by_design``).
``ENABLE_METRICS=true`` beside it was the same kind of line: ``/metrics`` is
always served. And ``docker-compose.dev.yml`` still passed the addresses of
four other services "for health aggregation", a route removed in #646.

The rule these tests keep: a name in the ``environment`` of ``api``,
``tools-worker`` or ``tools-flower``, in any root Compose file, is a field
of ``app.config.Settings`` or a variable the code reads from the
environment itself.
"""

import os
import re
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.config import Settings  # noqa: E402

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
SHARED = REPO_ROOT / "open-security-shared"

# The containers built from open-security-tools in the root Compose files.
TOOLS_SERVICES = ("api", "tools-worker", "tools-flower")

ENVIRONMENT_READ = re.compile(
    r"""os\.(?:getenv\(|environ\.get\(|environ\[)\s*["']([A-Z][A-Z0-9_]*)["']"""
)

pytestmark = pytest.mark.skipif(
    not (REPO_ROOT / "docker-compose.yml").is_file() or not SHARED.is_dir(),
    reason="the root Compose files are not next to this service (not a full checkout)",
)


def compose_environment():
    """{(file, service): {variable names}} for the tools containers."""
    import yaml

    class Loader(yaml.SafeLoader):
        """Reads the compose merge tags (!override, !reset) as plain values."""

    def plain(loader, suffix, node):
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_scalar(node)

    Loader.add_multi_constructor("!", plain)

    found = {}
    for path in sorted(REPO_ROOT.glob("docker-compose*.yml")):
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader) or {}
        for service in TOOLS_SERVICES:
            spec = (document.get("services") or {}).get(service) or {}
            environment = spec.get("environment") or []
            if isinstance(environment, dict):
                names = set(environment)
            else:
                names = {str(entry).split("=", 1)[0] for entry in environment}
            if names:
                found[(path.name, service)] = names
    return found


def variables_the_service_reads():
    """Settings fields, and names read from the environment in the code."""
    names = {name.upper() for name in Settings.model_fields}
    sources = list((SERVICE_ROOT / "app").rglob("*.py")) + list(SHARED.glob("*.py"))
    for source in sources:
        names.update(ENVIRONMENT_READ.findall(source.read_text(encoding="utf-8")))
    return names


def test_the_reader_finds_both_kinds_of_setting():
    read = variables_the_service_reads()

    # Fields of Settings.
    assert {"API_KEY", "REDIS_URL", "CORS_ORIGINS", "LOG_LEVEL", "DEBUG"} <= read
    # Read from the environment by the shared gateway authentication and by
    # the authorization manager.
    assert {"GATEWAY_INTERNAL_SECRET", "USER_PERMISSIONS_FILE"} <= read
    assert "WORKERS" not in read
    assert "ENABLE_METRICS" not in read


def test_the_compose_blocks_were_found():
    found = compose_environment()

    assert ("docker-compose.yml", "api") in found
    assert ("docker-compose.yml", "tools-worker") in found
    assert ("docker-compose.prod.yml", "api") in found
    assert "API_KEY" in found[("docker-compose.yml", "api")]


def test_every_variable_compose_sets_is_read():
    read = variables_the_service_reads()

    unread = {
        f"{file}: {service}: {name}"
        for (file, service), names in compose_environment().items()
        for name in names
        if name not in read
    }

    assert sorted(unread) == [], (
        "set for a tools container and read by nothing: an operator who "
        "changes it changes nothing"
    )


@pytest.mark.parametrize("variable", ["WORKERS", "ENABLE_METRICS"])
def test_the_variables_of_721_are_gone_from_the_tools_containers(variable):
    for (file, service), names in compose_environment().items():
        assert variable not in names, f"{file}: {service}"


def test_the_api_is_one_process_by_design():
    """Why WORKERS was removed and not honored.

    With several uvicorn processes each would have its own execution manager
    (the MAX_CONCURRENT_TOOLS ceiling, the registry of runs to cancel at
    shutdown, ``active_executions`` of /health) and its own Prometheus
    registry, so a scrape would read whichever process answered: counters
    that jump up and down. The image therefore starts one process and takes
    no setting that says otherwise.
    """
    dockerfile = (SERVICE_ROOT / "Dockerfile").read_text(encoding="utf-8")
    (command,) = re.findall(r"^CMD\s+(\[.*\])\s*$", dockerfile, re.M)

    assert '"uvicorn"' in command and '"app.main:app"' in command
    assert "--workers" not in command
    assert "WORKERS" not in dockerfile
    assert "WEB_CONCURRENCY" not in dockerfile

    from app.execution_manager import ToolExecutionManager

    assert "SINGLE INSTANCE BY DESIGN" in ToolExecutionManager.__doc__
