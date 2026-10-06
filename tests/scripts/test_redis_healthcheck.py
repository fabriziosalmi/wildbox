"""The Redis health check authenticates and requires PONG (#740).

Every compose file checked Redis with `redis-cli -a <password> ping`, or with
`redis-cli ping` and no password at all. Two things were wrong with it:

- the password was an argument of a process that runs every 30 seconds, so
  it showed in the container's process list;
- `redis-cli` exits 0 when the server answers with an error, so the check
  passed on NOAUTH and WRONGPASS: a Redis whose password no longer matched
  stayed `healthy`.

The check is now `redis-cli ping | grep -qx PONG`, with the password in the
container's environment as REDISCLI_AUTH. Two kinds of test:

- every tracked compose file is read: each Redis health check has that
  form, and each Redis that requires a password gives the check the same
  variable it gives the server;
- the check of docker-compose.yml, taken from the file, runs against
  throwaway redis:7-alpine containers under this test's own Compose project
  name: one whose server password matches the check's, and one whose
  password differs.

Every password here is made up.
"""

import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK = ["CMD-SHELL", "redis-cli ping | grep -qx PONG"]
REQUIREPASS = re.compile(r"--requirepass \$\{([A-Z0-9_]+)[:}]")


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose tags such as !override as plain nodes."""


def _untagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def _environment(service):
    environment = service.get("environment") or []
    if isinstance(environment, dict):
        return {key: str(value) for key, value in environment.items()}
    return dict(str(item).partition("=")[::2] for item in environment)


def _redis_services():
    """(file, name, service) for every Redis service in a tracked compose file."""
    tracked = subprocess.run(
        ["git", "ls-files", "*.yml", "*.yaml"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    found = []
    for name in tracked:
        if name.startswith(".github/"):
            continue
        try:
            document = yaml.load(  # nosec B506 - a SafeLoader subclass
                (REPO_ROOT / name).read_text(), Loader=_ComposeLoader
            )
        except yaml.YAMLError:
            continue
        services = document.get("services") if isinstance(document, dict) else None
        for service_name, service in (services or {}).items():
            if isinstance(service, dict) and re.match(
                r"redis(:|$)", str(service.get("image", ""))
            ):
                found.append((name, service_name, service))
    return found


def _checked():
    return [entry for entry in _redis_services() if entry[2].get("healthcheck")]


def test_every_redis_health_check_requires_pong_and_names_no_password():
    checked = _checked()
    # The stack's own, and the six per-service files that have one (three
    # more had one: #726 removed data's file, which could not start, and the
    # Redis of the sensor's, which nothing connected to; #756 removed the
    # gateway's file, which could not start and whose Redis the gateway
    # never used).
    assert len(checked) >= 7, [name for name, _, _ in checked]
    assert "docker-compose.yml" in [name for name, _, _ in checked]
    for name, service_name, service in checked:
        test = service["healthcheck"]["test"]
        where = f"{name}: {service_name}"
        assert test == CHECK, where
        assert "REDIS_PASSWORD" not in json.dumps(service["healthcheck"]), where


def test_a_redis_that_requires_a_password_gives_its_check_the_same_one():
    protected = 0
    for name, service_name, service in _checked():
        where = f"{name}: {service_name}"
        required = REQUIREPASS.search(str(service.get("command", "")))
        given = _environment(service).get("REDISCLI_AUTH")
        if not required:
            # Nothing to authenticate with, and nothing to leave lying around.
            assert given is None, where
            continue
        protected += 1
        assert given is not None, f"{where}: the check cannot authenticate"
        # The variable the server takes, and no default that could differ.
        assert re.fullmatch(r"\$\{" + required.group(1) + r":\?[^}]*\}", given), where
    # Six until #756 removed the gateway's own Compose file.
    assert protected >= 5


def test_no_compose_file_passes_a_redis_password_on_a_command_line():
    """Not in a health check, and not anywhere else a process is started."""
    for name, service_name, service in _redis_services():
        check = json.dumps(service.get("healthcheck") or {})
        assert not re.search(r'"-a"|--pass|-u"', check), f"{name}: {service_name}"
        assert "$$" not in check, f"{name}: {service_name}"


# --- the check itself, against real servers -----------------------------------


def _stack_redis():
    compose = yaml.load(  # nosec B506 - a SafeLoader subclass
        (REPO_ROOT / "docker-compose.yml").read_text(), Loader=_ComposeLoader
    )
    return compose["services"]["wildbox-redis"]


def _service(password, healthcheck_test, environment):
    """A Redis with a server password, checked the way the argument says."""
    return {
        "image": "redis:7-alpine",
        "command": ["redis-server"] + (["--requirepass", password] if password else []),
        "environment": environment,
        "healthcheck": {
            "test": healthcheck_test,
            "interval": "1s",
            "timeout": "5s",
            "retries": 3,
        },
        "stop_grace_period": "1s",
    }


@pytest.fixture(scope="module")
def health(docker, tmp_path_factory):
    """{service: health status} once every container has settled."""
    root = tmp_path_factory.mktemp("stack740")
    stack = _stack_redis()
    # The health check and the environment of docker-compose.yml, verbatim.
    # REDIS_PASSWORD is what they interpolate; the server's password is set
    # apart from it, so the two can differ.
    check, environment = stack["healthcheck"]["test"], stack.get("environment", [])
    matching, different = f"same-{uuid.uuid4().hex}", f"other-{uuid.uuid4().hex}"
    services = {
        "matching": _service(matching, check, environment),
        "mismatched": _service(different, check, environment),
        "open": _service("", CHECK, []),
        "open-check-on-a-protected-server": _service(different, CHECK, []),
        # What the files had before: healthy whatever the password.
        "old-check": _service(
            different, ["CMD", "redis-cli", "-a", matching, "ping"], []
        ),
    }
    compose_file = root / "compose.yml"
    compose_file.write_text(yaml.safe_dump({"services": services}))
    env_file = root / "stack.env"
    env_file.write_text(f"REDIS_PASSWORD={matching}\n")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", str(root)),
        "COMPOSE_FILE": str(compose_file),
        "COMPOSE_PROJECT_NAME": f"wbtest740-{uuid.uuid4().hex[:8]}",
    }
    for name in ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"):
        if name in os.environ:
            env[name] = os.environ[name]

    def compose(*args):
        return subprocess.run(
            ["docker", "compose", "--env-file", str(env_file), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )

    try:
        started = compose("up", "-d")
        assert started.returncode == 0, started.stdout + started.stderr
        statuses, deadline = {}, time.time() + 120
        while time.time() < deadline:
            for service in services:
                container = compose("ps", "-q", service).stdout.strip()
                statuses[service] = subprocess.run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Health.Status}}",
                        container,
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                ).stdout.strip()
            if "starting" not in statuses.values() and "" not in statuses.values():
                break
            time.sleep(1)
        yield statuses
    finally:
        compose("down", "-v", "--remove-orphans")


def test_real_check_is_healthy_when_the_password_matches(health):
    assert health["matching"] == "healthy"
    assert health["open"] == "healthy"


def test_real_check_is_unhealthy_when_the_password_differs(health):
    """The container whose password differs from the check's (#740)."""
    assert health["mismatched"] == "unhealthy"
    # And a check without a password does not pass on NOAUTH.
    assert health["open-check-on-a-protected-server"] == "unhealthy"


def test_real_old_check_was_healthy_with_the_wrong_password(health):
    """Why the reply is compared: redis-cli exits 0 on an error reply."""
    assert health["old-check"] == "healthy"
