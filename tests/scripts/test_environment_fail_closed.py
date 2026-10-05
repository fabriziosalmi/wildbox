"""A missing ENVIRONMENT never means development (#736).

``docker-compose.yml`` passed ``ENVIRONMENT=${ENVIRONMENT:-development}`` to
eighteen services. A ``.env`` without the line, written by hand or older than
the variable, started the whole stack as a development one, silently: API
schemas published, none of the start-up checks for secrets. The production
overlay set ``production`` itself on five services and left the other
thirteen to ``.env``.

The form now:

* the base file requires the variable (``${ENVIRONMENT:?...}``): Compose
  refuses to start without it, and says what to write;
* the production overlay sets ``production`` on every service the base file
  passes the variable to, whatever ``.env`` says;
* no tracked Compose file gives it a default;
* ``.env.example`` and ``.env.template`` set ``production``, and
  ``validate_secrets.py`` requires the line, with a value the services know.
"""

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE = "docker-compose.yml"
PRODUCTION = "docker-compose.prod.yml"
DEVELOPMENT = "docker-compose.dev.yml"

REQUIRED = re.compile(r"^\$\{ENVIRONMENT:\?[^}]+\}$")
DEFAULTED = re.compile(r"\$\{ENVIRONMENT:?-")


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose tags such as !override as plain nodes."""


def _untagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def environments(path: str) -> dict:
    """``{service: value of ENVIRONMENT}`` for the services of a Compose file
    that set it."""
    document = yaml.load(  # noqa: S506 - SafeLoader subclass
        (REPO_ROOT / path).read_text(encoding="utf-8"), Loader=_ComposeLoader
    )
    found = {}
    for name, service in (document.get("services") or {}).items():
        environment = (service or {}).get("environment") or []
        if isinstance(environment, dict):
            pairs = environment.items()
        else:
            pairs = (str(entry).partition("=")[::2] for entry in environment)
        for key, value in pairs:
            if key == "ENVIRONMENT":
                found[name] = str(value)
    return found


def tracked_compose_files() -> list:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.yml", "*.yaml"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    )
    paths = [path for path in listed.stdout.decode().split("\0") if path]
    return [path for path in paths if "compose" in Path(path).name.lower()]


def _load(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# --- Compose -----------------------------------------------------------------


def test_the_base_file_requires_the_variable_of_every_service_it_gives_it_to():
    values = environments(BASE)
    assert len(values) == 18, sorted(values)
    for service, value in values.items():
        assert REQUIRED.match(value), (service, value)


def test_the_message_says_what_to_write():
    message = next(iter(environments(BASE).values()))
    assert "production" in message and "development" in message
    assert ".env" in message


def test_the_production_overlay_sets_production_on_every_one_of_them():
    base, overlay = environments(BASE), environments(PRODUCTION)
    assert set(overlay) == set(base)
    assert set(overlay.values()) == {"production"}


def test_the_development_overlay_says_development_where_it_turns_debug_on():
    # The overlay turns DEBUG on for data and its scheduler, whose
    # configuration refuses DEBUG anywhere but in development: without the
    # line the generated .env (production) left them crash-looping under
    # `make start`. The rest take the value of .env.
    assert environments(DEVELOPMENT) == {
        "data": "development",
        "data-scheduler": "development",
    }


def test_the_standalone_identity_stack_says_it_is_a_development_one():
    # It passes an optional API_KEY_HASH_SECRET, and only a development
    # environment starts without one.
    path = "open-security-identity/docker-compose.yml"
    text = (REPO_ROOT / path).read_text(encoding="utf-8")
    assert "API_KEY_HASH_SECRET=${API_KEY_HASH_SECRET:-}" in text
    assert environments(path) == {"identity": "development"}


def test_no_compose_file_gives_the_variable_a_default():
    files = tracked_compose_files()
    assert BASE in files and len(files) >= 15, files
    for path in files:
        lines = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()
        settings = [line for line in lines if not line.lstrip().startswith("#")]
        assert not DEFAULTED.search("\n".join(settings)), path


@pytest.mark.parametrize("template", [".env.example", ".env.template"])
def test_the_templates_set_production(template):
    lines = (REPO_ROOT / template).read_text(encoding="utf-8").splitlines()
    assert [line for line in lines if line.startswith("ENVIRONMENT=")] == [
        "ENVIRONMENT=production"
    ]


def compose_config(tmp_path, environment_line: str, *overlays: str, quiet=True):
    """``docker compose config`` on the base file, and overlays if any.

    The env file gives every variable the file requires a placeholder, so that
    ENVIRONMENT is the only one that can be missing. A test that calls this
    asks for the ``docker`` fixture of conftest.py, which decides what a
    machine without Docker means.
    """
    files = (BASE, *overlays)
    text = "".join((REPO_ROOT / name).read_text(encoding="utf-8") for name in files)
    names = sorted(set(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", text)) - {"ENVIRONMENT"})
    lines = [f"{name}=placeholder" for name in names]
    if environment_line:
        lines.append(environment_line)
    env_file = tmp_path / "stack.env"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "ENVIRONMENT" and key not in names
    }
    # Every profile: a service behind one is part of the stack too.
    command = ["docker", "compose", "--profile", "*", "--env-file", str(env_file)]
    for name in files:
        command += ["-f", name]
    command += ["config", "--quiet"] if quiet else ["config", "--format", "json"]
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_compose_refuses_an_env_file_without_the_variable(docker, tmp_path):
    result = compose_config(tmp_path, "")
    assert result.returncode != 0
    assert "ENVIRONMENT" in result.stderr
    assert "set it in .env to production" in result.stderr


def test_compose_refuses_an_empty_variable(docker, tmp_path):
    # ${VAR:?} is for unset and for empty alike: ENVIRONMENT= is not a choice.
    result = compose_config(tmp_path, "ENVIRONMENT=")
    assert result.returncode != 0
    assert "set it in .env to production" in result.stderr


@pytest.mark.parametrize("value", ["production", "development"])
def test_compose_accepts_a_declared_environment(docker, tmp_path, value):
    result = compose_config(tmp_path, f"ENVIRONMENT={value}")
    assert result.returncode == 0, result.stderr


def test_the_rendered_production_stack_is_production_whatever_the_env_file_says(
    docker,
    tmp_path,
):
    import json

    result = compose_config(
        tmp_path, "ENVIRONMENT=development", PRODUCTION, quiet=False
    )
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    rendered = {
        name: service.get("environment", {}).get("ENVIRONMENT")
        for name, service in services.items()
        if "ENVIRONMENT" in (service.get("environment") or {})
    }
    assert len(rendered) == 18, sorted(rendered)
    assert set(rendered.values()) == {"production"}, rendered


# --- validate_secrets.py -----------------------------------------------------


@pytest.fixture(scope="module")
def validator():
    return _load("scripts/validate_secrets.py", "wildbox_validate_secrets_736")


@pytest.mark.parametrize("value", ["production", "staging", "development"])
def test_the_validator_accepts_the_environments_the_services_know(validator, value):
    assert validator.check_environment({"ENVIRONMENT": value}) == []


@pytest.mark.parametrize("env", [{}, {"ENVIRONMENT": ""}, {"ENVIRONMENT": "  "}])
def test_the_validator_requires_the_variable(validator, env):
    (problem,) = validator.check_environment(env)
    assert problem.startswith("ENVIRONMENT is not set")
    assert "ENVIRONMENT=production" in problem


@pytest.mark.parametrize("value", ["prod", "Production", "dev", "test"])
def test_the_validator_refuses_a_name_the_services_do_not_know(validator, value):
    # data compares with the exact word; tools refuses to start on another.
    (problem,) = validator.check_environment({"ENVIRONMENT": value})
    assert repr(value) in problem and "production, staging, development" in problem


def test_the_validator_runs_the_check():
    source = (REPO_ROOT / "scripts" / "validate_secrets.py").read_text(encoding="utf-8")
    assert "for problem in check_environment(env_vars):" in source
