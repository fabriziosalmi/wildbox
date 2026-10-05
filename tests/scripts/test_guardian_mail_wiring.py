"""Compose gives guardian what it needs to send e-mail, and no more (#705).

guardian's e-mails had no address to go to and no mail server to go
through: Compose passed guardian no mail setting, so Django's console
backend printed each message to the worker's log. The worker now sends by
SMTP when a server is configured, and asks identity who may be told about a
team, with a secret of its own.

How that is wired matters as much as the code:

* a variable Compose does not pass is one an operator sets in ``.env`` to no
  effect;
* the secret the worker presents to identity must not be the gateway's. The
  worker scans addresses and fetches URLs outside the stack, and holds no
  ``GATEWAY_INTERNAL_SECRET`` for that reason: that secret lets its holder
  speak as any user to every service. These tests fail if the worker is
  ever given it, or if the contacts secret is handed to a third service;
* the worker has to reach identity and a mail server on the networks of the
  production overlay.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET = "GUARDIAN_CONTACTS_SECRET"
URL = "GUARDIAN_TEAM_CONTACTS_URL"
WORKER = "guardian-worker"

# What guardian/mailconf.py reads, and the name each has in .env.
MAIL_VARIABLES = {
    "EMAIL_HOST": "GUARDIAN_EMAIL_HOST",
    "EMAIL_PORT": "GUARDIAN_EMAIL_PORT",
    "EMAIL_USE_TLS": "GUARDIAN_EMAIL_USE_TLS",
    "EMAIL_USE_SSL": "GUARDIAN_EMAIL_USE_SSL",
    "EMAIL_HOST_USER": "GUARDIAN_EMAIL_HOST_USER",
    "EMAIL_HOST_PASSWORD": "GUARDIAN_EMAIL_HOST_PASSWORD",
    "DEFAULT_FROM_EMAIL": "GUARDIAN_DEFAULT_FROM_EMAIL",
}


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


def _source(path):
    return (REPO_ROOT / path).read_text()


def _constant(path, name):
    match = re.search(rf'^{name} = "([^"]*)"$', _source(path), flags=re.MULTILINE)
    assert match, f"{name} not found in {path}"
    return match.group(1)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# --- the secret: identity and the worker, and nobody else ----------------------------


def test_identity_and_the_worker_get_the_contacts_secret():
    services = _services()

    for name in ("identity", WORKER):
        # Empty when unset: the route answers 503 and guardian asks nothing.
        assert _environment(services[name]).get(SECRET) == f"${{{SECRET}:-}}", name


def test_no_other_service_gets_the_contacts_secret():
    holders = {
        name
        for name, service in _services().items()
        if any(
            SECRET in key or SECRET in value
            for key, value in _environment(service).items()
        )
    }

    assert holders == {"identity", WORKER}


def test_the_worker_is_not_given_the_gateway_s_secret():
    """The reason the contacts secret exists: this must stay true."""
    for compose_file in ("docker-compose.yml", "docker-compose.prod.yml"):
        environment = _environment(_services(compose_file)[WORKER])
        assert "GATEWAY_INTERNAL_SECRET" not in environment, compose_file
        assert not any(
            "GATEWAY_INTERNAL_SECRET" in value for value in environment.values()
        ), compose_file


def test_identity_refuses_the_gateway_s_secret_as_the_contacts_secret():
    """An operator cannot hand it to the worker by reusing the value."""
    config = _source("open-security-identity/app/config.py")

    assert "_contacts_secret_is_its_own" in config
    assert (
        '"gateway_internal_secret", "jwt_secret_key", "api_key_hash_secret"' in config
    )


def test_the_generator_writes_a_contacts_secret_and_the_template_has_room_for_it():
    generator = _source("scripts/generate_secrets.py")
    template = _source(".env.example")

    assert f'"{SECRET}": generate_hex(32)' in generator
    # Present and empty: the generator fills it, and a deployment that does
    # not run the generator has the feature off, not a placeholder identity
    # would refuse to start on.
    assert re.search(rf"^{SECRET}=$", template, flags=re.MULTILINE)


def test_the_validator_refuses_a_contacts_secret_that_is_another_secret():
    validator = _load("scripts/validate_secrets.py", "wildbox_validate_secrets_705")
    shared, own = "5" * 40, "6" * 40

    assert validator.check_contacts_secret({}) == []
    assert validator.check_contacts_secret({SECRET: ""}) == []
    assert (
        validator.check_contacts_secret(
            {SECRET: own, "GATEWAY_INTERNAL_SECRET": shared}
        )
        == []
    )
    for other in ("GATEWAY_INTERNAL_SECRET", "JWT_SECRET_KEY", "API_KEY_HASH_SECRET"):
        (problem,) = validator.check_contacts_secret({SECRET: shared, other: shared})
        assert other in problem and shared not in problem
    assert SECRET in validator.OPTIONAL_SECRETS
    assert SECRET not in validator.REQUIRED_SECRETS


# --- where the worker asks ---------------------------------------------------------------


def test_the_worker_asks_identity_at_its_name_on_the_network():
    default = _constant(
        "open-security-guardian/guardian/mailconf.py", "TEAM_CONTACTS_URL_DEFAULT"
    )
    identity = _services()["identity"]

    host, port, path = re.fullmatch(r"http://([^:/]+):(\d+)(/.*)", default).groups()
    assert host == identity["container_name"]
    assert any(str(mapping).endswith(f":{port}") for mapping in identity["ports"])
    prefix = re.search(
        r'internal_api_prefix: str = "([^"]+)"',
        _source("open-security-identity/app/config.py"),
    ).group(1)
    assert path == f"{prefix}/team-contacts"
    assert '"/team-contacts"' in _source("open-security-identity/app/team_contacts.py")
    # Empty means that default, as for guardian's other optional settings.
    assert _environment(_services()[WORKER])[URL] == f"${{{URL}:-}}"


def test_the_route_is_not_one_the_gateway_proxies():
    conf = _source("open-security-gateway/nginx/conf.d/wildbox_gateway.conf")
    targets = set(re.findall(r"proxy_pass http://identity_service(\S*);", conf))

    assert targets
    assert not any(target.startswith("/internal") for target in targets), targets
    assert "team-contacts" not in conf


def test_the_worker_reaches_identity_and_a_mail_server_in_the_production_overlay():
    services = _services("docker-compose.prod.yml")
    worker = set(services[WORKER]["networks"])

    assert worker & set(
        services["identity"]["networks"]
    ), "guardian-worker cannot reach identity on any network of the overlay"
    assert "egress" in worker, "guardian-worker cannot reach a mail server"
    # It is still off the network the gateway reaches the services on.
    assert "backend" not in worker


# --- the mail server -----------------------------------------------------------------------


@pytest.mark.parametrize("setting,variable", sorted(MAIL_VARIABLES.items()))
def test_the_worker_gets_every_mail_setting(setting, variable):
    environment = _environment(_services()[WORKER])

    # Empty when unset: guardian/mailconf.py reads that as the default.
    assert environment.get(setting) == f"${{{variable}:-}}"


def test_the_mail_settings_compose_passes_are_the_ones_guardian_reads():
    mailconf = _source("open-security-guardian/guardian/mailconf.py")
    read = set(re.findall(r'"((?:EMAIL_|DEFAULT_FROM_)[A-Z_]+)"', mailconf))

    assert read - {"EMAIL_BACKEND", "EMAIL_TIMEOUT"} == set(MAIL_VARIABLES)


def test_nothing_chooses_a_mail_backend():
    """The console backend printed every e-mail to the log and called it sent."""
    for compose_file in ("docker-compose.yml", "docker-compose.prod.yml"):
        for name, service in _services(compose_file).items():
            assert "EMAIL_BACKEND" not in _environment(service), (compose_file, name)
    assert "os.getenv('EMAIL_BACKEND'" not in _source(
        "open-security-guardian/guardian/settings.py"
    )
    for template in (".env.example", "open-security-guardian/.env.example"):
        assert not re.search(r"^EMAIL_BACKEND=", _source(template), flags=re.MULTILINE)


@pytest.mark.parametrize(
    "variable",
    sorted([*MAIL_VARIABLES.values(), SECRET, URL, "GUARDIAN_BASE_URL"]),
)
def test_every_variable_is_in_the_template(variable):
    """Commented out or empty, with what it is for."""
    template = _source(".env.example")

    assert re.search(rf"^(# )?{variable}=", template, flags=re.MULTILINE), variable


def test_the_worker_gets_the_public_address_for_links():
    assert (
        _environment(_services()[WORKER])["GUARDIAN_BASE_URL"]
        == "${GUARDIAN_BASE_URL:-}"
    )
