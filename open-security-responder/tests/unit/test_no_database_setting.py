"""The responder is given no database it does not use (#654).

docker-compose.yml passed it ``DATABASE_URL=${RESPONDER_DATABASE_URL:-${DATABASE_URL}}``:
a ``responder`` database that scripts/init-databases.sql never creates, or,
when that variable was unset, identity's own connection string. The
responder opens no SQL connection (its runs and its queue are in Redis),
so the only effect was a PostgreSQL password in a container with no use
for it, and a start that waited for a database it never queried.

These tests keep the variable out of the compose files and the env
template for as long as the service has no code that reads it.
"""

import re
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.prod.yml")
ENV_TEMPLATE = REPO_ROOT / ".env.example"

pytestmark = pytest.mark.skipif(
    not (REPO_ROOT / "docker-compose.yml").is_file(),
    reason="the repository's compose files are not here",
)


class _Loader(yaml.SafeLoader):
    """SafeLoader that accepts Compose's !override and !reset tags."""


def _plain(loader, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


_Loader.add_constructor("!override", _plain)
_Loader.add_constructor("!reset", _plain)


def responder(compose_file):
    # _Loader is a SafeLoader: it builds plain data only.
    text = (REPO_ROOT / compose_file).read_text()
    return yaml.load(text, Loader=_Loader)["services"]["responder"]  # nosec B506


def environment(service):
    """The service's environment as {name: value}, from either YAML form."""
    entries = service.get("environment") or []
    if isinstance(entries, dict):
        return {name: str(value) for name, value in entries.items()}
    return dict(entry.partition("=")[::2] for entry in entries)


def uses_a_sql_database():
    """Whether the responder's code opens a SQL connection."""
    drivers = re.compile(
        r"^\s*(?:import|from)\s+(?:sqlalchemy|psycopg2?|asyncpg|databases|sqlmodel)\b",
        re.MULTILINE,
    )
    setting = re.compile(r"database_url|DATABASE_URL")
    for source in (SERVICE_ROOT / "app").rglob("*.py"):
        text = source.read_text()
        if drivers.search(text) or setting.search(text):
            return True
    return False


def test_the_responder_has_no_sql_state():
    """The premise. If this fails, the service gained a database: give it
    one that scripts/init-databases.sql creates, then drop these tests."""
    assert not uses_a_sql_database()
    requirements = (SERVICE_ROOT / "requirements.in").read_text().lower()
    for driver in ("sqlalchemy", "psycopg", "asyncpg"):
        assert driver not in requirements


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_compose_passes_the_responder_no_database_url(compose_file):
    env = environment(responder(compose_file))
    assert "DATABASE_URL" not in env
    for name, value in env.items():
        assert "DATABASE_URL" not in value, f"{name} is built from a database URL"
        assert "POSTGRES" not in value, f"{name} carries a PostgreSQL setting"


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_the_responder_does_not_wait_for_postgres(compose_file):
    depends_on = responder(compose_file).get("depends_on") or {}
    assert "postgres" not in depends_on


def test_the_responder_still_waits_for_redis():
    """What it does use: removing the wrong dependency would be worse."""
    depends_on = responder("docker-compose.yml")["depends_on"]
    assert depends_on["wildbox-redis"] == {"condition": "service_healthy"}
    assert "REDIS_URL" in environment(responder("docker-compose.yml"))


@pytest.mark.parametrize(
    "path", [*COMPOSE_FILES, ".env.example", "scripts/init-databases.sql"]
)
def test_nothing_names_a_responder_database(path):
    text = (REPO_ROOT / path).read_text()
    assert "RESPONDER_DATABASE_URL" not in text
    assert not re.search(r"5432/responder\b", text)
    assert not re.search(r"CREATE DATABASE responder\b", text, re.IGNORECASE)
