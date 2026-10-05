"""No Redis password in the argument list of a `docker` command (#740).

`docker compose exec -e REDISCLI_AUTH=<password> ...` hands the password to
redis-cli through its environment, and puts it in the argument list of the
`docker` process on the host on the way, where every local user reads it
with `ps`. scripts/check_redis_config.py did that, under a comment that said
the opposite, and three pages of the documentation told operators to.

`-e REDISCLI_AUTH`, the name alone, makes docker take the value from its own
environment. Three kinds of test:

- with a stub `docker` on PATH: what `check_redis_config.py runtime` puts in
  its arguments and what it puts in its environment;
- every tracked script and document is read: none writes the value after
  the name;
- against a real throwaway Redis whose container does not hold the password,
  under this test's own Compose project name: the name alone is enough for
  redis-cli to authenticate.

Every password here is made up.
"""

import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_redis_config.py"
PASSWORD = "made-up-redis-password-for-argv-tests"

FAKE_DOCKER = r'''#!/usr/bin/env python3
"""Stub `docker`: logs its arguments, and answers like a Redis that takes
the password from REDISCLI_AUTH in the environment it was started with."""
import os
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(" ".join(args) + "\n")
if args[0] == "inspect":
    print(4 * 1024**3)
    sys.exit(0)
assert args[0] == "compose", args
if "ps" in args:
    print("0123456789ab")
    sys.exit(0)
exec_at = args.index("exec")
passed = [args[i + 1] for i in range(exec_at, len(args) - 1) if args[i] == "-e"]
# Docker resolves a bare name from its own environment.
given = dict(
    item.split("=", 1) if "=" in item else (item, os.environ.get(item, ""))
    for item in passed
)
command = args[args.index("redis-cli") + 1 :]
if given.get("REDISCLI_AUTH") != os.environ["FAKE_SERVER_PASSWORD"]:
    print("NOAUTH Authentication required.")
    sys.exit(0)
if command[:2] == ["CONFIG", "GET"]:
    values = {"maxmemory-policy": "noeviction", "maxmemory": "1073741824", "appendonly": "yes"}
    print(command[2])
    print(values[command[2]])
elif command == ["INFO", "memory"]:
    print("used_memory_human:1.00M")
'''


@pytest.fixture
def stub(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
    env_file = tmp_path / "stack.env"
    env_file.write_text(f"REDIS_PASSWORD={PASSWORD}\n")
    log = tmp_path / "docker.log"

    def run(**overrides):
        env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(tmp_path),
            "FAKE_LOG": str(log),
            "FAKE_SERVER_PASSWORD": PASSWORD,
        }
        env.update(overrides)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "runtime", "--env-file", str(env_file)],
            env=env,
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result, log.read_text() if log.exists() else ""

    return run


def test_the_runtime_check_names_the_variable_and_never_its_value(stub):
    result, log = stub()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "noeviction" in result.stdout
    # The password reached redis-cli, or the stub would have said NOAUTH...
    executions = [line for line in log.splitlines() if " exec " in line]
    assert len(executions) == 4
    for line in executions:
        # ...by name: the value is in no argument of any docker command.
        assert " -e REDISCLI_AUTH wildbox-redis redis-cli " in line, line
    assert PASSWORD not in log
    assert PASSWORD not in result.stdout + result.stderr


def test_the_runtime_check_fails_on_a_password_redis_refuses(stub):
    result, log = stub(FAKE_SERVER_PASSWORD="what-the-server-really-holds")
    assert result.returncode != 0
    assert "wrong REDIS_PASSWORD?" in result.stderr
    assert PASSWORD not in log + result.stdout + result.stderr


# `-e NAME=`, `--env NAME=` or an f-string that builds one, for the variables
# redis-cli and psql read a password from.
VALUE_IN_ARGV = re.compile(
    r"""(-e|--env)[\s"',]+(REDISCLI_AUTH|PGPASSWORD)=|["'](REDISCLI_AUTH|PGPASSWORD)=\{"""
)
READ = ("*.md", "*.sh", "*.py", "*.yml", "*.yaml", "Makefile", "*/Makefile")
# Release notes describe the defect in its own words.
NOT_READ = ("CHANGELOG.md", "UPGRADING.md")


def test_no_script_and_no_document_puts_a_password_after_the_variable_name():
    tracked = subprocess.run(
        ["git", "ls-files", *READ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\n")
    offenders = []
    for name in filter(None, tracked):
        path = REPO_ROOT / name
        if name in NOT_READ or path == Path(__file__) or not path.is_file():
            continue
        for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            if VALUE_IN_ARGV.search(line):
                offenders.append(f"{name}:{number}")
    assert offenders == []


def test_the_pattern_recognizes_the_forms_that_were_in_the_tree():
    for line in (
        "  -e REDISCLI_AUTH=\"$(sed -n 's/^REDIS_PASSWORD=//p' .env)\" wildbox-redis \\",
        '  -e REDISCLI_AUTH="$REDIS_PASSWORD" wildbox-redis \\',
        '                f"REDISCLI_AUTH={password}",',
        '["exec", "-e", "PGPASSWORD=secret"]',
    ):
        assert VALUE_IN_ARGV.search(line), line
    for line in (
        "  docker compose exec -e REDISCLI_AUTH wildbox-redis redis-cli ping",
        "REDISCLI_AUTH=\"$(sed -n 's/^REDIS_PASSWORD=//p' .env)\" \\",
        "      - REDISCLI_AUTH=${REDIS_PASSWORD:?REDIS_PASSWORD is required}",
        '    REDISCLI_AUTH="$password" redis-cli \\',
    ):
        assert not VALUE_IN_ARGV.search(line), line


# --- a real Redis --------------------------------------------------------------

REAL_COMPOSE = """\
services:
  wildbox-redis:
    image: redis:7-alpine
    # No REDISCLI_AUTH in this container: the only way redis-cli gets the
    # password is the variable the caller names.
    command: >-
      redis-server --appendonly yes --maxmemory 64mb
      --maxmemory-policy noeviction --requirepass ${REDIS_PASSWORD:?required}
    mem_limit: 256m
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep -q -e PONG -e NOAUTH"]
      interval: 1s
      timeout: 5s
      retries: 60
    stop_grace_period: 1s
"""


@pytest.fixture(scope="module")
def stack(docker, tmp_path_factory):
    root = tmp_path_factory.mktemp("stack740argv")
    compose_file = root / "compose.yml"
    compose_file.write_text(REAL_COMPOSE)
    password = f"redis-{uuid.uuid4().hex}"
    env_file = root / "stack.env"
    env_file.write_text(f"REDIS_PASSWORD={password}\n")
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", str(root)),
        "COMPOSE_FILE": str(compose_file),
        "COMPOSE_PROJECT_NAME": f"wbtest740-{uuid.uuid4().hex[:8]}",
    }
    for name in ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"):
        if name in os.environ:
            env[name] = os.environ[name]

    def compose(*args, **extra):
        return subprocess.run(
            ["docker", "compose", "--env-file", str(env_file), *args],
            env={**env, **extra},
            capture_output=True,
            text=True,
            timeout=300,
        )

    try:
        started = compose("up", "-d", "--wait")
        assert started.returncode == 0, started.stdout + started.stderr
        yield {
            "env": env,
            "env_file": env_file,
            "password": password,
            "compose": compose,
            "root": root,
        }
    finally:
        compose("down", "-v", "--remove-orphans")


def test_real_redis_cli_authenticates_with_a_variable_passed_by_name(stack):
    """The form the documentation now gives."""
    named = stack["compose"](
        "exec", "-T", "-e", "REDISCLI_AUTH", "wildbox-redis", "redis-cli", "ping",
        REDISCLI_AUTH=stack["password"],
    )  # fmt: skip
    assert named.stdout.strip() == "PONG", named.stdout + named.stderr
    # Without it this container has nothing to authenticate with.
    bare = stack["compose"]("exec", "-T", "wildbox-redis", "redis-cli", "ping")
    assert "NOAUTH" in bare.stdout


def test_real_runtime_check_reads_the_running_redis(stack):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "runtime", "--env-file", str(stack["env_file"])],
        env=stack["env"],
        cwd=stack["root"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(r"maxmemory-policy\s+noeviction", result.stdout)
    assert re.search(r"maxmemory\s+67108864", result.stdout)
    assert stack["password"] not in result.stdout + result.stderr

    refused = subprocess.run(
        [sys.executable, str(SCRIPT), "runtime", "--env-file", str(stack["env_file"])],
        env={**stack["env"], "REDIS_PASSWORD": "not-the-password"},
        cwd=stack["root"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert refused.returncode != 0
    assert "wrong REDIS_PASSWORD?" in refused.stderr
