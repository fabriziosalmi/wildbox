"""Rotating REDIS_PASSWORD against a real Redis (#723).

test_rotate_secrets.py covers the rotation with a stub `docker`. These tests
run scripts/rotate_secrets.sh against a throwaway redis:7-alpine started the
way the stack starts its own (`--appendonly yes --requirepass ...` on the
command line, a data volume), under this test's own Compose project name,
with containers that stand for the services:

- `client` holds a Redis URL that .env overrides, as identity can;
- `worker` holds one Compose builds from REDIS_PASSWORD, as the workers do;
- `bystander` holds neither, and `backup` sits behind a profile.

What they establish is what the script and the guide say: the server refuses
the old password and accepts the new one at once, from another container;
the running clients still hold the old URL; a restart of the Redis container
before it is recreated brings the old password back; the command the script
prints recreates Redis on its data, with the new password for good; and a
failed step leaves the old password in both places.

No test reads a real .env, and every password here is made up.
"""

import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ROTATE = REPO_ROOT / "scripts" / "rotate_secrets.sh"

COMPOSE = """\
services:
  wildbox-redis:
    image: redis:7-alpine
    # As docker-compose.yml starts it: the password is an argument of the
    # server, the health check authenticates with the same value from the
    # container's environment and requires PONG, and the data is in a named
    # volume.
    command: >-
      redis-server --appendonly yes --maxmemory-policy noeviction
      --databases 16 --requirepass ${REDIS_PASSWORD:?required}
    environment:
      - REDISCLI_AUTH=${REDIS_PASSWORD:?required}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep -qx PONG"]
      interval: 1s
      timeout: 5s
      retries: 5
  client:
    image: redis:7-alpine
    environment:
      - REDIS_URL=${IDENTITY_REDIS_URL:-redis://:${REDIS_PASSWORD}@wildbox-redis:6379/0}
    command: sleep infinity
    stop_grace_period: 1s
    depends_on:
      wildbox-redis:
        condition: service_healthy
  worker:
    image: redis:7-alpine
    environment:
      - REDIS_URL=redis://:${REDIS_PASSWORD}@wildbox-redis:6379/1
    command: sleep infinity
    stop_grace_period: 1s
    depends_on:
      wildbox-redis:
        condition: service_healthy
  bystander:
    image: redis:7-alpine
    environment:
      - UNRELATED=${UNRELATED}
    command: sleep infinity
    stop_grace_period: 1s
  backup:
    image: redis:7-alpine
    profiles: ["backup"]
    environment:
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    command: sleep infinity
    stop_grace_period: 1s
volumes:
  redis_data:
"""

# Reads the password on stdin into REDISCLI_AUTH, so that it is in no
# argument list here either, and runs redis-cli against the server over the
# Compose network. Commands, if any, follow on stdin.
AUTHENTICATED = (
    "IFS= read -r REDISCLI_AUTH; export REDISCLI_AUTH; "
    'exec redis-cli -h wildbox-redis "$@"'
)
# MONITOR for a minute at most, authenticated the same way.
MONITOR = (
    "IFS= read -r REDISCLI_AUTH; export REDISCLI_AUTH; "
    "exec timeout 60 redis-cli monitor"
)
# The same with the password of the URL the container was started with.
WITH_OWN_URL = (
    "password=${REDIS_URL#redis://:}; export REDISCLI_AUTH=${password%%@*}; "
    'exec redis-cli -h wildbox-redis "$@"'
)


def _parse(text):
    return dict(
        line.split("=", 1)
        for line in text.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    )


class Stack:
    def __init__(self, root):
        self.root = root
        self.project = f"wbtest723-{uuid.uuid4().hex[:8]}"
        self.compose_file = root / "compose.yml"
        self.compose_file.write_text(COMPOSE)
        self.env_file = root / "stack.env"
        first = f"old-{uuid.uuid4().hex}"
        self.env_file.write_text(
            f"REDIS_PASSWORD={first}\n"
            f"IDENTITY_REDIS_URL=redis://:{first}@wildbox-redis:6379/0\n"
            "CACHE_REDIS_URL=redis://:elsewhere-pw@cache.example.com:6379/0\n"
            "DATABASE_URL=postgresql://postgres:a-db-password@postgres:5432/identity\n"
            "UNRELATED=unrelated\n"
        )
        self.env_file.chmod(0o600)

    def env(self):
        env = {
            "PATH": os.environ["PATH"],
            "HOME": os.environ.get("HOME", str(self.root)),
            "COMPOSE_FILE": str(self.compose_file),
            "COMPOSE_PROJECT_NAME": self.project,
            "ENV_FILE": str(self.env_file),
        }
        for name in ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"):
            if name in os.environ:
                env[name] = os.environ[name]
        return env

    def compose(self, *args, stdin=None, check=True):
        result = subprocess.run(
            ["docker", "compose", "--env-file", str(self.env_file), *args],
            env=self.env(),
            input=stdin,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if check:
            assert result.returncode == 0, f"{args[:3]}: {result.stdout}{result.stderr}"
        return result

    def rotate(self, path_prefix=None, **extra):
        env = self.env()
        env.update(extra)
        if path_prefix:
            env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
            env["REAL_DOCKER"] = shutil.which("docker")
        return subprocess.run(
            ["bash", str(ROTATE), "--secret", "REDIS_PASSWORD"],
            env=env,
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def values(self):
        return _parse(self.env_file.read_text())

    def password(self):
        return self.values()["REDIS_PASSWORD"]

    def accepts(self, password):
        """From the client container, over the network, as a service would.

        True for PONG, False for WRONGPASS. Any other answer is a server
        that is still starting or loading its data, and is asked again.
        """
        deadline = time.time() + 60
        while True:
            result = self.compose(
                *("exec", "-T", "client", "sh", "-c", AUTHENTICATED, "sh", "ping"),
                stdin=password + "\n",
                check=False,
            )
            answer = result.stdout + result.stderr
            if result.stdout.strip() == "PONG":
                return True
            if "WRONGPASS" in answer:
                return False
            assert time.time() < deadline, answer
            time.sleep(0.5)

    def own_url_logs_in(self, service):
        """With the URL the container was started with."""
        result = self.compose(
            *("exec", "-T", service, "sh", "-c", WITH_OWN_URL, "sh", "ping")
        )
        return result.stdout.strip() == "PONG"

    def redis(self, *commands):
        """Commands on stdin, authenticated with the password .env holds."""
        return self.compose(
            *("exec", "-T", "client", "sh", "-c", AUTHENTICATED, "sh"),
            stdin="\n".join([self.password(), *commands]) + "\n",
        ).stdout.split()

    def container_id(self, service):
        """The service's container, running or not; empty when there is none."""
        listed = subprocess.run(
            ["docker", "ps", "-aq"]
            + ["--filter", f"label=com.docker.compose.project={self.project}"]
            + ["--filter", f"label=com.docker.compose.service={service}"],
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert listed.returncode == 0, listed.stderr
        return listed.stdout.strip()

    def health(self, wanted):
        """Wait for the Redis container's health status to become `wanted`."""
        deadline = time.time() + 90
        while True:
            status = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}"]
                + [self.container_id("wildbox-redis")],
                env=self.env(),
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout.strip()
            if status == wanted:
                return status
            assert time.time() < deadline, f"{status}, not {wanted}"
            time.sleep(0.5)

    def settle(self):
        """Every container as .env describes it, and the server accepting it."""
        self.compose("up", "-d", "--wait")
        assert self.accepts(self.password())


@pytest.fixture(scope="module")
def stack(docker, tmp_path_factory):
    s = Stack(tmp_path_factory.mktemp("stack723"))
    try:
        s.compose("up", "-d", "--wait")
        # The kinds of state the stack keeps in Redis, in several databases.
        assert s.redis(
            "SET cspm:scan:1 done",
            "RPUSH celery task-1 task-2 task-3",
            "SELECT 1",
            "HSET run:7 state running owner worker-2",
            "SELECT 4",
            "SET revoked:token:abc 1",
        ) == ["OK", "3", "OK", "2", "OK", "OK"]
        yield s
    finally:
        s.compose("down", "-v", "--remove-orphans", check=False)


def _state(stack):
    return stack.redis(
        "GET cspm:scan:1",
        "LRANGE celery 0 -1",
        "SELECT 1",
        "HGET run:7 owner",
        "SELECT 4",
        "GET revoked:token:abc",
    )


STATE = ["done", "task-1", "task-2", "task-3", "OK", "worker-2", "OK", "1"]


def _printed_command(result):
    command = re.search(
        r"^    (docker compose up -d --no-deps .+)$", result.stdout, re.M
    )
    assert command, result.stdout
    return command.group(1)


def test_real_rotation_old_password_refused_new_accepted_and_the_state_survives(
    stack, tmp_path
):
    old = stack.password()
    assert stack.accepts(old) and not stack.accepts("not-the-password")
    assert stack.own_url_logs_in("client") and stack.own_url_logs_in("worker")
    assert _state(stack) == STATE
    redis_before = stack.container_id("wildbox-redis")
    bystander_before = stack.container_id("bystander")

    # Everything the server would show an observer while the script runs:
    # MONITOR, and a slow log that records every command.
    assert stack.redis("CONFIG SET slowlog-log-slower-than 0") == ["OK"]
    watched = tmp_path / "monitor.log"
    with watched.open("w") as sink:
        monitor = subprocess.Popen(
            ["docker", "compose", "--env-file", str(stack.env_file)]
            + ["exec", "-T", "wildbox-redis", "sh", "-c", MONITOR],
            env=stack.env(),
            stdin=subprocess.PIPE,
            stdout=sink,
            stderr=subprocess.STDOUT,
            text=True,
        )
        monitor.stdin.write(old + "\n")
        monitor.stdin.flush()
        deadline = time.time() + 30
        while "OK" not in watched.read_text():
            assert time.time() < deadline, watched.read_text()
            time.sleep(0.1)

        result = stack.rotate()

        time.sleep(0.5)
        monitor.kill()
        monitor.wait()
    assert result.returncode == 0, result.stdout + result.stderr

    values = stack.values()
    new = values["REDIS_PASSWORD"]
    assert new != old
    for text in (result.stdout, result.stderr):
        assert old not in text and new not in text

    # The server: old refused, new accepted, right away, from another
    # container.
    assert not stack.accepts(old)
    assert stack.accepts(new)

    # The observer saw the script's connections, and no password.
    seen = watched.read_text()
    assert '"AUTH" "(redacted)"' in seen and '"PING"' in seen.upper()
    assert "requirepass" not in seen.lower()
    slowlog = "\n".join(stack.redis("SLOWLOG GET 200"))
    assert "requirepass" in slowlog and "(redacted)" in slowlog
    logs = stack.compose("logs", "wildbox-redis").stdout
    for text in (seen, slowlog, logs):
        assert old not in text and new not in text

    # .env: the variable and the URL that points at the stack's Redis; the
    # URL of another Redis and the PostgreSQL connection string are left.
    assert values["IDENTITY_REDIS_URL"] == f"redis://:{new}@wildbox-redis:6379/0"
    assert values["CACHE_REDIS_URL"].endswith(":elsewhere-pw@cache.example.com:6379/0")
    assert values["DATABASE_URL"].endswith(":a-db-password@postgres:5432/identity")
    assert "CACHE_REDIS_URL: host 'cache.example.com'" in result.stdout
    assert stat.S_IMODE(stack.env_file.stat().st_mode) == 0o600

    # The running clients still hold the old URL, which is why the script
    # names them, with Redis first; the bystander is not named, and neither
    # is the profile's service, which the command would start.
    assert not stack.own_url_logs_in("client")
    assert not stack.own_url_logs_in("worker")
    command = _printed_command(result)
    assert command == "docker compose up -d --no-deps wildbox-redis client worker"
    assert re.search(r"not active here.*\n.*\n.*\n\n    backup\n", result.stdout)

    # The Redis container says so itself: its health check authenticates
    # with the password the container was created with, and requires PONG
    # (#740). It used to stay healthy with a password the server refused.
    assert stack.health("unhealthy")

    # State written after the rotation and before the recreation counts too.
    assert stack.redis("SET written:after:rotation yes") == ["OK"]

    # The command the script printed, as printed. It works on a Redis that
    # is unhealthy: that container is the first thing it replaces.
    stack.compose(*command.split()[2:])
    assert stack.container_id("wildbox-redis") != redis_before
    assert stack.health("healthy")
    assert stack.container_id("bystander") == bystander_before
    assert stack.container_id("backup") == ""
    assert stack.own_url_logs_in("client") and stack.own_url_logs_in("worker")
    assert stack.accepts(new) and not stack.accepts(old)
    # Redis was recreated on its data.
    assert _state(stack) == STATE
    assert stack.redis("GET written:after:rotation") == ["yes"]

    # The new password is now the one the container starts with.
    stack.compose("restart", "wildbox-redis")
    stack.compose("up", "-d", "--wait", "wildbox-redis")
    assert stack.accepts(new) and not stack.accepts(old)
    assert _state(stack) == STATE


def test_real_restart_before_the_recreation_brings_the_old_password_back(stack):
    """Why the script tells the operator to recreate Redis as well.

    The running server was changed; the container's command line was not.
    """
    stack.settle()
    old = stack.password()
    result = stack.rotate()
    assert result.returncode == 0, result.stdout + result.stderr
    new = stack.password()
    assert stack.accepts(new) and not stack.accepts(old)
    assert "comes back with the old password" in result.stdout

    stack.compose("restart", "wildbox-redis")
    assert stack.accepts(old)
    assert not stack.accepts(new)

    # The script refuses to rotate on top of that, and says what to do.
    original = stack.env_file.read_bytes()
    again = stack.rotate()
    assert again.returncode == 1
    assert "the running Redis refuses the REDIS_PASSWORD" in again.stderr
    assert "docker compose up -d --no-deps wildbox-redis" in again.stderr
    assert stack.env_file.read_bytes() == original

    # The command the first run printed puts it right, data included.
    stack.compose(*_printed_command(result).split()[2:])
    assert stack.accepts(new) and not stack.accepts(old)
    assert stack.own_url_logs_in("client") and stack.own_url_logs_in("worker")
    assert _state(stack) == STATE


def test_real_rotation_is_refused_when_redis_is_stopped(stack):
    stack.settle()
    stack.compose("stop", "wildbox-redis")
    try:
        original = stack.env_file.read_bytes()
        result = stack.rotate()
        assert result.returncode == 1
        assert "REFUSING to rotate REDIS_PASSWORD" in result.stderr
        assert "'wildbox-redis' service is not running" in result.stderr
        assert stack.env_file.read_bytes() == original
    finally:
        stack.compose("up", "-d", "--wait", "wildbox-redis")
    assert stack.accepts(stack.password())
    assert _state(stack) == STATE


def test_real_rotation_is_refused_when_redis_does_not_persist(stack):
    """Recreating a Redis without its append-only file would lose the state."""
    stack.settle()
    assert stack.redis("CONFIG SET appendonly no") == ["OK"]
    try:
        original = stack.env_file.read_bytes()
        result = stack.rotate()
        assert result.returncode == 1
        assert "not writing its append-only file" in result.stderr
        assert stack.env_file.read_bytes() == original
        assert stack.accepts(stack.password())
    finally:
        assert stack.redis("CONFIG SET appendonly yes") == ["OK"]
        deadline = time.time() + 60
        while not {"aof_enabled:1", "aof_rewrite_in_progress:0"} <= set(
            stack.redis("INFO persistence")
        ):
            assert time.time() < deadline
            time.sleep(0.2)


# The real docker, except for one call to redis-cli, chosen by what is on its
# stdin: MODE=drop answers the first CONFIG SET with OK without sending it,
# a change that did not take; MODE=blind lets it through and then fails the
# next question to the server, a change that took and cannot be confirmed.
SHIM = r"""#!/usr/bin/env python3
import os
import subprocess
import sys

real = os.environ["REAL_DOCKER"]
if "exec" not in sys.argv:
    os.execv(real, [real, *sys.argv[1:]])
data = sys.stdin.buffer.read()
marker = os.environ["SHIM_MARKER"]
changes = b"CONFIG SET requirepass" in data
if os.environ["SHIM_MODE"] == "drop" and changes and not os.path.exists(marker):
    open(marker, "w").close()
    print("OK")
    sys.exit(0)
if os.environ["SHIM_MODE"] == "blind":
    if changes and not os.path.exists(marker):
        open(marker, "w").close()
    elif os.path.exists(marker) and not os.path.exists(marker + ".done"):
        open(marker + ".done", "w").close()
        print("Could not connect to Redis: Connection refused")
        sys.exit(1)
sys.exit(subprocess.run([real, *sys.argv[1:]], input=data).returncode)
"""


@pytest.mark.parametrize("mode", ["drop", "blind"])
def test_real_failed_change_leaves_the_old_password_in_both_places(
    stack, tmp_path, mode
):
    """The script asks the server; a failed step puts both places back."""
    stack.settle()
    shim = tmp_path / "bin"
    shim.mkdir()
    docker = shim / "docker"
    docker.write_text(SHIM)
    docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
    marker = tmp_path / "seen"

    current = stack.password()
    original = stack.env_file.read_bytes()
    result = stack.rotate(path_prefix=shim, SHIM_MARKER=str(marker), SHIM_MODE=mode)

    assert marker.exists(), "the shim never saw the CONFIG SET"
    assert result.returncode == 1, result.stdout + result.stderr
    assert "does not accept the new password" in result.stderr
    assert "The running Redis accepts the previous password." in result.stderr
    assert "nothing was rotated" in result.stderr
    assert current not in result.stdout + result.stderr
    assert stack.env_file.read_bytes() == original
    # In `blind` the server really held the new password for a moment; the
    # backup of .env is the only place the script kept nothing of it.
    assert stack.accepts(current)
    assert stack.own_url_logs_in("client") and stack.own_url_logs_in("worker")
    assert _state(stack) == STATE
