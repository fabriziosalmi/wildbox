"""The agents service is told where the services its tools call are (#652).

``WILDBOX_DATA_URL`` and ``WILDBOX_GUARDIAN_URL`` defaulted to localhost,
which inside the agents container is the agents container (and the data
default named port 8001, identity's), and docker-compose.yml set neither.
The defaults are now the services' addresses in docker-compose.yml, which
also sets them, and these tests keep the two equal. They also keep
``ANALYZE_RATE_LIMIT`` and ``ANALYZE_TEAM_RATE_LIMIT`` passed by the compose
file: UPGRADING told operators to add them in an override of their own.
"""

import re
import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
COMPOSE = REPO_ROOT / "docker-compose.yml"
PROD_OVERLAY = REPO_ROOT / "docker-compose.prod.yml"
sys.path.insert(0, str(SERVICE_ROOT))

from app.config import Settings  # noqa: E402

pytestmark = pytest.mark.skipif(
    not COMPOSE.is_file(), reason="the repository's compose files are not here"
)

# Variable -> the compose service its URL names.
SERVICES = {
    "WILDBOX_API_URL": "api",
    "WILDBOX_DATA_URL": "data",
    "WILDBOX_GUARDIAN_URL": "guardian",
}
URL_VARIABLES = tuple(SERVICES)


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


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())["services"]


@pytest.fixture(scope="module")
def overlay():
    # _Loader is a SafeLoader: it builds plain data only.
    return yaml.load(PROD_OVERLAY.read_text(), Loader=_Loader)["services"]  # nosec B506


def environment(service):
    """A compose service's environment as {name: value}."""
    return dict(
        entry.split("#")[0].strip().partition("=")[::2]
        for entry in service.get("environment") or []
    )


def agents_default(compose, variable):
    """The default docker-compose.yml gives ``variable`` for the agents."""
    env = environment(compose["agents"])
    assert variable in env, f"docker-compose.yml sets no {variable} for the agents"
    match = re.fullmatch(r"\$\{[A-Z_]+:-([^}]*)\}", env[variable])
    assert match, f"{variable} in docker-compose.yml has no default: {env[variable]}"
    return match.group(1)


def names_of(service):
    """The names a compose service answers to on the default network."""
    names = {service.get("container_name")}
    networks = service.get("networks")
    if isinstance(networks, dict):
        for config in networks.values():
            names |= set((config or {}).get("aliases") or [])
    return names - {None}


@pytest.fixture
def no_overrides(monkeypatch):
    for variable in URL_VARIABLES + (
        "WILDBOX_RESPONDER_URL",
        "ANALYZE_RATE_LIMIT",
        "ANALYZE_TEAM_RATE_LIMIT",
    ):
        monkeypatch.delenv(variable, raising=False)


# --- The service URLs --------------------------------------------------------


@pytest.mark.parametrize("variable", ["WILDBOX_DATA_URL", "WILDBOX_GUARDIAN_URL"])
def test_compose_sets_the_url_for_the_agents(compose, variable):
    """The acceptance test of #652: neither was set."""
    assert variable in environment(compose["agents"])


@pytest.mark.parametrize("variable", URL_VARIABLES)
def test_the_default_is_the_compose_address(compose, no_overrides, variable):
    settings = Settings(_env_file=None)
    assert getattr(settings, variable.lower()) == agents_default(compose, variable)


@pytest.mark.parametrize("variable", URL_VARIABLES)
def test_the_compose_address_names_the_service_and_its_port(compose, variable):
    url = agents_default(compose, variable)
    host, port = re.fullmatch(r"http://([a-z-]+):(\d+)", url).groups()
    name = SERVICES[variable]
    service = compose[name]
    # A service is reachable by its compose name, its container name and
    # its network aliases.
    assert host in names_of(service) | {name}, f"{host} is not an address of {name}"
    published = [p.rsplit(":", 1)[-1] for p in service.get("ports", [])]
    assert port in published, f"{name} listens on {published}"


@pytest.mark.parametrize("variable", URL_VARIABLES)
def test_no_default_names_localhost(no_overrides, variable):
    """Inside the container, localhost is the agents service itself."""
    url = getattr(Settings(_env_file=None), variable.lower())
    assert "localhost" not in url and "127.0.0.1" not in url


def test_guardian_is_addressed_by_a_host_it_allows(compose):
    """Django answers 400 to a Host that is not in ALLOWED_HOSTS."""
    host = re.fullmatch(
        r"http://([a-z-]+):\d+", agents_default(compose, "WILDBOX_GUARDIAN_URL")
    ).group(1)
    allowed = environment(compose["guardian"])["ALLOWED_HOSTS"].split(",")
    assert host in allowed


@pytest.mark.parametrize("variable", ["WILDBOX_DATA_URL", "WILDBOX_GUARDIAN_URL"])
def test_the_production_overlay_keeps_the_address_reachable(compose, overlay, variable):
    """The overlay replaces every service's networks: the agents must share
    one with the service, on which the name in the URL still resolves."""
    assert variable not in environment(overlay["agents"]), "the base file sets it"
    host = re.fullmatch(
        r"http://([a-z-]+):\d+", agents_default(compose, variable)
    ).group(1)
    name = SERVICES[variable]
    agents_networks = set(overlay["agents"]["networks"])
    target_networks = overlay[name]["networks"]
    shared = agents_networks & set(target_networks)
    assert shared, f"agents and {name} share no network in production"
    if host == compose[name].get("container_name"):
        return  # a container name resolves on every network it joined
    aliases = {
        alias
        for network in shared
        if isinstance(target_networks, dict)
        for alias in ((target_networks[network] or {}).get("aliases") or [])
    }
    assert host in aliases, f"{host} does not resolve on {sorted(shared)}"


@pytest.mark.parametrize(
    "value",
    [
        "open-security-data:8002",
        "ftp://open-security-data",
        "http://",
        "",
        "http://h/?a=1",
        "http://h/#x",
    ],
)
@pytest.mark.parametrize("variable", URL_VARIABLES)
def test_a_url_that_is_not_one_stops_the_service(monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValidationError, match=variable):
        Settings(_env_file=None)


def test_a_trailing_slash_is_dropped(monkeypatch):
    monkeypatch.setenv("WILDBOX_GUARDIAN_URL", "http://guardian.internal:8013/")
    assert (
        Settings(_env_file=None).wildbox_guardian_url == "http://guardian.internal:8013"
    )


def test_an_env_file_that_still_sets_the_responder_url_loads(tmp_path, no_overrides):
    """The service's own .env.example sets it; no tool calls the responder."""
    env_file = tmp_path / ".env"
    env_file.write_text("WILDBOX_RESPONDER_URL=http://localhost:8018\n")
    assert (
        Settings(_env_file=str(env_file)).wildbox_responder_url
        == "http://localhost:8018"
    )


# --- The analysis rate limits ------------------------------------------------


def test_compose_passes_the_analysis_limits_with_the_services_defaults(
    compose, no_overrides
):
    settings = Settings(_env_file=None)
    env = environment(compose["agents"])
    assert (
        env["ANALYZE_RATE_LIMIT"]
        == "${ANALYZE_RATE_LIMIT:-" + settings.analyze_rate_limit + "}"
    )
    assert env["ANALYZE_TEAM_RATE_LIMIT"] == "${ANALYZE_TEAM_RATE_LIMIT:-}"
    assert settings.analyze_team_rate_limit == ""


def test_the_limits_compose_passes_when_nothing_is_set_are_accepted(
    compose, monkeypatch
):
    """Compose passes ANALYZE_TEAM_RATE_LIMIT as an empty string by default:
    the service must take that as "no ceiling", not refuse to start."""
    monkeypatch.setenv(
        "ANALYZE_RATE_LIMIT", agents_default(compose, "ANALYZE_RATE_LIMIT")
    )
    monkeypatch.setenv(
        "ANALYZE_TEAM_RATE_LIMIT", agents_default(compose, "ANALYZE_TEAM_RATE_LIMIT")
    )
    settings = Settings(_env_file=None)
    assert settings.analyze_rate_limit == "5/minute"
    assert settings.analyze_team_rate_limit == ""


def test_the_overlay_does_not_override_the_limits(overlay):
    env = environment(overlay["agents"])
    assert "ANALYZE_RATE_LIMIT" not in env and "ANALYZE_TEAM_RATE_LIMIT" not in env


def test_the_agents_still_reach_redis_and_wait_for_it(compose):
    """The limiter's counters are in REDIS_URL."""
    assert "REDIS_URL" in environment(compose["agents"])
    assert compose["agents"]["depends_on"]["wildbox-redis"] == {
        "condition": "service_healthy"
    }
