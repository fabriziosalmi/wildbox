"""Compose passes the two settings of #676 where the code reads them.

identity tells guardian when a member leaves a team, at
``GUARDIAN_INTERNAL_URL``, and guardian trusts a membership for
``GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS``. A variable Compose does not pass
is one an operator sets in ``.env`` to no effect, and how it is passed
matters here:

* identity reads an empty ``GUARDIAN_INTERNAL_URL`` as "this deployment has
  no guardian" and sends nothing. Passed as ``${GUARDIAN_INTERNAL_URL:-}``,
  every deployment that does not set it would hand identity an empty string
  and silently switch the notice off. It is passed with ``-``: unset means
  guardian's name on the network, and only an explicit empty value is empty.
* the window is read by guardian (the API) and by guardian-worker (the SLA
  and assignment e-mails). Passed to one of them only, the two would apply
  different rules about who is still a member.
"""

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
URL_VARIABLE = "GUARDIAN_INTERNAL_URL"
WINDOW_VARIABLE = "GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS"
GUARDIAN_CONTAINERS = ("guardian", "guardian-worker", "guardian-beat")


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose tags such as !override as plain nodes."""


def _untagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def _services(compose_file="docker-compose.yml"):
    text = (REPO_ROOT / compose_file).read_text()
    return yaml.load(text, Loader=_ComposeLoader)["services"]  # nosec B506


def _environment(service):
    env = service.get("environment") or []
    if isinstance(env, dict):
        return {key: str(value) for key, value in env.items()}
    return dict(item.split("=", 1) for item in env)


def _constant(path, name):
    """A module-level string constant, read without importing the service."""
    source = (REPO_ROOT / path).read_text()
    match = re.search(rf'^{name} = "([^"]*)"$', source, flags=re.MULTILINE)
    assert match, f"{name} not found in {path}"
    return match.group(1)


def test_identity_is_told_where_guardian_is_unless_switched_off():
    value = _environment(_services()["identity"])[URL_VARIABLE]
    default = _constant(
        "open-security-identity/app/guardian_memberships.py", "DEFAULT_URL"
    )

    # ${VAR-default}: the default when unset, and an empty value kept empty.
    assert value == f"${{{URL_VARIABLE}-{default}}}"
    assert ":-" not in value, "':-' would turn an unset variable into 'no guardian'"


def test_the_default_url_is_guardian_s_route_on_the_compose_network():
    default = _constant(
        "open-security-identity/app/guardian_memberships.py", "DEFAULT_URL"
    )
    guardian = _services()["guardian"]
    route = (REPO_ROOT / "open-security-guardian/guardian/urls.py").read_text()

    host, port, path = re.fullmatch(r"http://([^:/]+):(\d+)(/.*)", default).groups()
    assert host == guardian["container_name"]
    assert any(str(mapping).endswith(f":{port}") for mapping in guardian["ports"])
    # The exact route, trailing slash included: a redirect drops a POST's body.
    assert f"'{path.lstrip('/')}'" in route
    assert path.endswith("/")
    # guardian answers to that name.
    assert host in _environment(guardian)["ALLOWED_HOSTS"].split(",")


def test_identity_and_guardian_share_the_internal_secret():
    services = _services()
    for name in ("identity", "guardian"):
        assert _environment(services[name])["GATEWAY_INTERNAL_SECRET"] == (
            "${GATEWAY_INTERNAL_SECRET}"
        ), name


@pytest.mark.parametrize("container", GUARDIAN_CONTAINERS)
def test_every_guardian_container_gets_the_same_window(container):
    value = _environment(_services()[container]).get(WINDOW_VARIABLE)

    # Empty means the default in guardian/schedule.py, as for the schedules.
    assert value == f"${{{WINDOW_VARIABLE}:-}}", container


def test_identity_reaches_guardian_in_the_production_overlay():
    """They share a network there; the notice does not go through the gateway."""
    services = _services("docker-compose.prod.yml")
    shared = set(services["identity"]["networks"]) & set(
        services["guardian"]["networks"]
    )
    assert shared, "identity cannot reach guardian on any network of the overlay"


def test_the_route_is_not_one_the_gateway_proxies():
    conf = (
        REPO_ROOT / "open-security-gateway/nginx/conf.d/wildbox_gateway.conf"
    ).read_text()
    # The gateway reaches guardian's /api/v1/ and nothing else.
    targets = set(re.findall(r"proxy_pass http://guardian_service(\S*);", conf))
    assert targets == {"/api/v1/"}, targets
    assert "team-memberships" not in conf
