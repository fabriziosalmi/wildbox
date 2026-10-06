"""Rotating POSTGRES_PASSWORD or REDIS_PASSWORD changes the server and every
URL that embeds the password, or neither (#649, #723), and each secret's next
step names what really reads it.

rotate_secrets.sh rewrote only the POSTGRES_PASSWORD= line of .env. The
services do not read that variable: they connect with DATABASE_URL-style
strings that embed the password, and the password itself lives in the running
server. Following the script left every service on the old password in .env
and the server on whatever it had, and the script reported success. Redis
had the same defect: the Redis URLs a deployment overrides in .env kept the
old password, and the running server was never told the new one.

Three kinds of test:

- with a stub `docker` on PATH and a temporary env file built from
  .env.example: what is rewritten, what is sent to the server and how, what
  happens when a step fails, and what the operator is told;
- against the repository's real compose files rendered by `docker compose
  config` (no container is started): which services each secret reaches;
- against a real throwaway PostgreSQL, started under this test's own Compose
  project name: the old password is refused and the new one accepted, from
  another container, before and after it is recreated. The same tests for a
  real Redis are in test_rotate_redis_real.py, so that one stack runs at a
  time.

No test reads a real .env, and every password here is made up.
"""

import ast
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ROTATE = REPO_ROOT / "scripts" / "rotate_secrets.sh"
GENERATOR = REPO_ROOT / "scripts" / "generate_secrets.py"
VALIDATOR = REPO_ROOT / "scripts" / "validate_secrets.py"

# Made up for these tests. Never real secrets.
OLD = "old-made-up-db-password-0000"
OLD_VERIFIER = "SCRAM-SHA-256$4096:b2xkLXNhbHQ=$b2xkLXN0b3JlZA==:b2xkLXNlcnZlcg=="
OLD_REDIS = "old-made-up-redis-password-0000"

DSN_KEYS = (
    "DATABASE_URL",
    "GUARDIAN_DATABASE_URL",
    "DATA_DATABASE_URL",
)
ROTATABLE = (
    "JWT_SECRET_KEY",
    "GATEWAY_INTERNAL_SECRET",
    "API_KEY",
    "API_KEY_HASH_SECRET",
    "CSPM_CREDENTIAL_KEY",
    "REDIS_PASSWORD",
    "POSTGRES_PASSWORD",
)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _env_from_example():
    """The template, with the database password a deployment would have."""
    text = (REPO_ROOT / ".env.example").read_text()
    text = text.replace("YOUR_DB_PASSWORD", OLD)
    text = re.sub(r"(?m)^REDIS_PASSWORD=.*$", f"REDIS_PASSWORD={OLD_REDIS}", text)
    return re.sub(r"(?m)^POSTGRES_PASSWORD=.*$", f"POSTGRES_PASSWORD={OLD}", text)


def _parse(text):
    return dict(
        line.split("=", 1)
        for line in text.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    )


def _scram_matches(verifier, password):
    """True when `verifier` is the SCRAM-SHA-256 verifier of `password`."""
    match = re.fullmatch(r"SCRAM-SHA-256\$(\d+):([^$]+)\$([^:]+):(.+)", verifier)
    if not match:
        return False
    rounds, salt, stored, server = match.groups()
    salted = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), base64.b64decode(salt), int(rounds)
    )
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    return (
        base64.b64decode(stored) == hashlib.sha256(client_key).digest()
        and base64.b64decode(server) == server_key
    )


# --- stub docker ------------------------------------------------------------

FAKE_DOCKER = r'''#!/usr/bin/env python3
"""Stub for `docker compose ...` as rotate_secrets.sh calls it."""
import json
import os
import re
import sys
import time

state = os.environ["FAKE_STATE"]
with open(os.path.join(state, "docker.log"), "a") as log:
    log.write(" ".join(sys.argv[1:]).replace("\n", " ") + "\n")

args = sys.argv[1:]
assert args[:2] == ["compose", "--env-file"], args
env_file, args = args[2], args[3:]
profiles = []
if args[0] == "--profile":
    profiles, args = [args[1]], args[2:]
command, args = args[0], args[1:]

if command == "config" and os.environ.get("FAKE_REAL_DOCKER"):
    # The repository's compose files, rendered by the real docker.
    real = os.environ["FAKE_REAL_DOCKER"]
    os.execv(real, [real, *sys.argv[1:]])


def counted(name):
    path = os.path.join(state, "calls_" + name)
    count = int(open(path).read()) + 1 if os.path.exists(path) else 1
    open(path, "w").write(str(count))
    return count


def word(variable, n, default):
    """The n-th space-separated word of a variable; the last repeats."""
    values = os.environ.get(variable, default).split()
    return values[min(n, len(values)) - 1]


def nth(variable, n):
    """The same, for a variable that holds exit statuses."""
    return int(word(variable, n, "0"))


def redis(data):
    """A Redis with one password, as redis-cli shows it on a pipe.

    The first line of stdin is the password the client presents; the rest
    is its commands. FAKE_REDIS_SET, FAKE_REDIS_PING and FAKE_REDIS_INFO say
    how the n-th call of each kind goes: honest, or
      down   the server cannot be reached
      error  (set) Redis answers with an error and changes nothing
      drop   (set) Redis answers OK and changes nothing
      lost   (set) the password changes and the reply never arrives
      slow   (set) the call takes a few seconds
    """
    lines = data.split("\n")
    auth, commands = lines[0], [line for line in lines[1:] if line]
    with open(os.path.join(state, "redis.log"), "a") as log:
        log.write(json.dumps({"auth": auth, "commands": commands}) + "\n")
    held = os.path.join(state, "redis_password")
    current = (
        open(held).read() if os.path.exists(held) else os.environ["FAKE_REDIS_PASSWORD"]
    )
    kind = (
        "SET"
        if any(c.startswith("CONFIG SET") for c in commands)
        else "PING" if commands == ["PING"] else "INFO"
    )
    behavior = word("FAKE_REDIS_" + kind, counted("redis_" + kind), "honest")
    if behavior == "down":
        print("Could not connect to Redis at 172.18.0.2:6379: Connection refused")
        sys.exit(1)
    if behavior == "slow":
        open(os.path.join(state, "redis_slow"), "w").close()
        time.sleep(3)
    if auth not in {current, *os.environ.get("FAKE_REDIS_ALSO_ACCEPTS", "").split()}:
        print("AUTH failed: WRONGPASS invalid username-password pair or user is disabled.")
        for _ in commands:
            print("NOAUTH Authentication required.")
        print()
        sys.exit(0)
    for line in commands:
        if line == "PING":
            print("PONG")
        elif line == "INFO persistence":
            fields = os.environ.get(
                "FAKE_REDIS_PERSISTENCE", "aof_enabled:1 aof_last_write_status:ok"
            )
            sys.stdout.write("# Persistence\r\nloading:0\r\n")
            sys.stdout.write("".join(field + "\r\n" for field in fields.split()))
        else:
            match = re.fullmatch(
                r'CONFIG SET requirepass "((?:\\x[0-9a-f]{2})+)"', line
            )
            assert match, line
            if behavior == "error":
                print("ERR CONFIG SET failed (possibly related to argument 'requirepass')")
                continue
            if behavior != "drop":
                password = bytes.fromhex(match.group(1).replace("\\x", "")).decode()
                open(held, "w").write(password)
            if behavior == "lost":
                sys.exit(1)
            print("OK")
    sys.exit(0)


if command == "ps":
    if args[-1] in os.environ.get("FAKE_RUNNING", "").split():
        print("0123456789ab")
elif command == "config":
    if os.environ.get("FAKE_CONFIG_RC", "0") != "0":
        sys.exit(int(os.environ["FAKE_CONFIG_RC"]))
    # The compose file, rendered with the env file the script named:
    # ${NAME} and ${NAME:-default}, innermost first.
    values = dict(
        line.split("=", 1)
        for line in open(env_file).read().splitlines()
        if "=" in line and not line.startswith("#")
    )

    def quoted(name):
        """A value as it sits inside a JSON string."""
        return json.dumps(values.get(name, ""))[1:-1]

    rendered, template = None, open(os.environ["FAKE_COMPOSE_TEMPLATE"]).read()
    while rendered != template:
        rendered = template
        template = re.sub(
            r"\$\{([A-Z0-9_]+)\}", lambda m: quoted(m.group(1)), template
        )
        template = re.sub(
            r"\$\{([A-Z0-9_]+):-([^${}]*)\}",
            lambda m: quoted(m.group(1)) or m.group(2),
            template,
        )
    document = json.loads(rendered)
    # A service behind a profile is rendered only when the profile is active.
    document["services"] = {
        name: service
        for name, service in document["services"].items()
        if not service.get("profiles")
        or "*" in profiles
        or set(service["profiles"]) & set(profiles)
    }
    json.dump(document, sys.stdout)
elif command == "exec":
    assert args[0] == "-T" and args[2:4] == ["sh", "-c"], args
    script, data = args[4], sys.stdin.read()
    if "redis-cli" in script:
        redis(data)
    if "hostname -i" in script:
        # The password check: the candidate arrives on stdin.
        open(os.path.join(state, "checked_password"), "w").write(data.rstrip("\n"))
        status = nth("FAKE_CHECK_RC", counted("check"))
        if status == 0:
            print(1)
        sys.exit(status)
    if "pg_authid" in data:
        role = os.environ.get("FAKE_ROLE_ROW", "role:" + os.environ["FAKE_OLD_VERIFIER"])
        if role:
            print(role)
    elif data.startswith("ALTER ROLE"):
        with open(os.path.join(state, "alter.log"), "a") as log:
            log.write(data)
        sys.exit(nth("FAKE_ALTER_RC", counted("alter")))
sys.exit(0)
'''

# The services that matter here, shaped like `docker compose config` output.
COMPOSE_TEMPLATE = {
    "services": {
        "postgres": {"environment": {"POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}"}},
        "identity": {
            "environment": {
                "DATABASE_URL": "${DATABASE_URL}",
                "REDIS_URL": "${IDENTITY_REDIS_URL:-redis://:${REDIS_PASSWORD}@wildbox-redis:6379/0}",
            }
        },
        "data": {"environment": {"DATABASE_URL": "${DATA_DATABASE_URL}"}},
        "guardian": {
            "environment": {
                "DATABASE_URL": "${GUARDIAN_DATABASE_URL}",
                "CELERY_BROKER_URL": "redis://:${REDIS_PASSWORD}@wildbox-redis:6379/1",
            }
        },
        "dashboard": {"environment": {}},
        "api": {"environment": {"API_KEY": "${API_KEY}"}},
        "gateway": {"environment": {}},
        # As the stack starts it: the password is an argument of the server,
        # and in the environment for the health check.
        "wildbox-redis": {
            "command": ["redis-server", "--appendonly", "yes", "--requirepass", "${REDIS_PASSWORD}"],
            "environment": {"REDISCLI_AUTH": "${REDIS_PASSWORD}"},
            "healthcheck": {"test": ["CMD-SHELL", "redis-cli ping | grep -qx PONG"]},
        },
        # Holds both passwords, and runs only for an operator who asked for it.
        "backup": {
            "profiles": ["backup"],
            "environment": {
                "POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}",
                "REDIS_PASSWORD": "${REDIS_PASSWORD}",
            },
        },
    }
}


class Harness:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.state = tmp_path / "state"
        self.bin.mkdir()
        self.state.mkdir()
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
        self.template = tmp_path / "compose.json"
        self.template.write_text(json.dumps(COMPOSE_TEMPLATE))
        self.env_file = tmp_path / "stack.env"
        self.env_file.write_text(_env_from_example())
        self.env_file.chmod(0o600)

    def env(self, path=None, **overrides):
        env = {
            "PATH": path or f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "ENV_FILE": str(self.env_file),
            "FAKE_STATE": str(self.state),
            "FAKE_COMPOSE_TEMPLATE": str(self.template),
            "FAKE_RUNNING": "postgres wildbox-redis",
            "FAKE_OLD_VERIFIER": OLD_VERIFIER,
            "FAKE_REDIS_PASSWORD": OLD_REDIS,
        }
        env.update(overrides)
        return env

    def run(self, *args, path=None, **overrides):
        return subprocess.run(
            ["bash", str(ROTATE), *args],
            env=self.env(path=path, **overrides),
            cwd=self.tmp,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def rotate_postgres(self, **overrides):
        return self.run("--secret", "POSTGRES_PASSWORD", **overrides)

    def rotate_redis(self, **overrides):
        return self.run("--secret", "REDIS_PASSWORD", **overrides)

    def redis_calls(self):
        """What reached redis-cli on stdin, one dict per call."""
        return [json.loads(line) for line in self.log("redis.log").splitlines()]

    def redis_password(self):
        """The password the stub server holds now."""
        return self.log("redis_password") or OLD_REDIS

    def add_to_env(self, text):
        with self.env_file.open("a") as handle:
            handle.write(text)

    def no_redis_secret_in(self, result, new):
        escaped = "".join(f"\\x{byte:02x}" for byte in new.encode())
        for text in (result.stdout, result.stderr, self.log()):
            assert OLD_REDIS not in text
            assert new not in text
            assert escaped not in text

    def values(self):
        return _parse(self.env_file.read_text())

    def log(self, name="docker.log"):
        path = self.state / name
        return path.read_text() if path.exists() else ""

    def backups(self):
        return sorted(self.tmp.glob("stack.env.bak.*"))

    def no_secret_in(self, result, *more):
        new = self.values()["POSTGRES_PASSWORD"]
        for text in (result.stdout, result.stderr, self.log(), *more):
            assert OLD not in text
            assert new not in text
            assert OLD_VERIFIER not in text


@pytest.fixture
def harness(tmp_path):
    return Harness(tmp_path)


def test_every_connection_string_gets_the_new_password_and_nothing_else_changes(
    harness,
):
    """The acceptance test of #649."""
    before = harness.values()
    result = harness.rotate_postgres()
    assert result.returncode == 0, result.stdout + result.stderr

    after = harness.values()
    new = after["POSTGRES_PASSWORD"]
    assert new != OLD
    for key in DSN_KEYS:
        assert OLD in before[key]
        assert after[key] == before[key].replace(OLD, new), key
    # Nothing else in the file moved.
    assert {k: v for k, v in after.items() if v != before[k]}.keys() == {
        "POSTGRES_PASSWORD",
        *DSN_KEYS,
    }
    # The validator `make start` runs agrees.
    validator = _load(VALIDATOR, "validate_secrets")
    assert validator.check_database_urls(after) == []
    assert validator.validate_secret("POSTGRES_PASSWORD", new)[0]


def test_the_server_gets_the_same_password_as_a_scram_verifier_on_stdin(harness):
    result = harness.rotate_postgres()
    assert result.returncode == 0, result.stderr
    new = harness.values()["POSTGRES_PASSWORD"]

    statements = harness.log("alter.log").splitlines()
    assert len(statements) == 1
    match = re.fullmatch(r"ALTER ROLE \"postgres\" PASSWORD '([^']+)';", statements[0])
    assert match, "the statement is not ALTER ROLE ... PASSWORD '<verifier>'"
    # A verifier of the value .env now holds: the two cannot diverge, and the
    # plaintext is in no statement the server could log.
    assert _scram_matches(match.group(1), new)
    assert new not in statements[0]
    # The script then asked the server whether it accepts that password.
    assert harness.log("checked_password") == new


def test_no_password_or_verifier_reaches_an_argument_list_or_the_output(harness):
    result = harness.rotate_postgres()
    assert result.returncode == 0, result.stderr
    harness.no_secret_in(result)
    statement = harness.log("alter.log")
    verifier = re.search(r"'([^']+)'", statement).group(1)
    for text in (result.stdout, result.stderr, harness.log()):
        assert verifier not in text


def test_the_operator_is_told_what_changed_and_what_to_recreate(harness):
    result = harness.rotate_postgres()
    assert result.returncode == 0, result.stderr
    out = result.stdout
    for key in ("POSTGRES_PASSWORD", *DSN_KEYS):
        assert re.search(rf"^    {key}$", out, re.M), key
    # Exactly the services whose rendered configuration carries the new
    # password, without postgres itself, which reads it only at first init.
    assert (
        "    docker compose up -d --no-deps identity data guardian\n" in out
    )
    assert "keeps running" in out
    backup = harness.backups()[0]
    assert f"Then delete {backup}" in out
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert stat.S_IMODE(harness.env_file.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"FAKE_RUNNING": ""}, "service is not running"),
        ({"FAKE_ROLE_ROW": ""}, "does not exist in the server"),
    ],
    ids=["stack-down", "no-such-role"],
)
def test_the_rotation_is_refused_rather_than_half_done(harness, overrides, reason):
    original = harness.env_file.read_bytes()
    result = harness.rotate_postgres(**overrides)
    assert result.returncode == 1
    assert "REFUSING to rotate POSTGRES_PASSWORD" in result.stderr
    assert reason in result.stderr
    assert "Nothing was changed" in result.stderr
    assert harness.env_file.read_bytes() == original
    assert harness.backups() == []
    assert harness.log("alter.log") == ""
    assert "Rotated" not in result.stdout


def test_the_rotation_is_refused_without_docker(harness, tmp_path):
    # A PATH of its own: a CI runner has a real docker in /usr/bin.
    tools = tmp_path / "tools"
    tools.mkdir()
    for tool in "bash cat dirname grep sed tr".split():
        (tools / tool).symlink_to(shutil.which(tool))
    original = harness.env_file.read_bytes()
    result = harness.rotate_postgres(path=str(tools))
    assert result.returncode == 1
    assert "docker is not available" in result.stderr
    assert harness.env_file.read_bytes() == original
    assert harness.backups() == []


def test_a_failed_password_change_restores_the_env_file(harness):
    original = harness.env_file.read_bytes()
    # The ALTER fails; putting the old verifier back then succeeds.
    result = harness.rotate_postgres(FAKE_ALTER_RC="1 0")
    assert result.returncode == 1
    assert "ROTATION FAILED: PostgreSQL did not accept" in result.stderr
    assert "nothing was rotated" in result.stderr
    assert harness.env_file.read_bytes() == original
    assert "Rotated" not in result.stdout
    # The server was given its previous verifier back, as it was.
    statements = harness.log("alter.log").splitlines()
    assert statements[-1] == f"ALTER ROLE \"postgres\" PASSWORD '{OLD_VERIFIER}';"
    assert OLD_VERIFIER not in result.stdout + result.stderr + harness.log()


def test_a_password_the_server_does_not_accept_is_rolled_back(harness):
    original = harness.env_file.read_bytes()
    result = harness.rotate_postgres(FAKE_CHECK_RC="1")
    assert result.returncode == 1
    assert "does not accept the new password" in result.stderr
    assert "Restored the previous password" in result.stderr
    assert harness.env_file.read_bytes() == original
    statements = harness.log("alter.log").splitlines()
    assert len(statements) == 2
    assert statements[1] == f"ALTER ROLE \"postgres\" PASSWORD '{OLD_VERIFIER}';"


def test_an_unreachable_server_during_rollback_is_reported_as_inconsistent(harness):
    original = harness.env_file.read_bytes()
    result = harness.rotate_postgres(FAKE_ALTER_RC="1 1")
    assert result.returncode == 3
    assert "INCONSISTENT" in result.stderr
    assert "\\password postgres" in result.stderr
    # .env is back regardless.
    assert harness.env_file.read_bytes() == original
    assert "nothing was rotated" not in result.stderr


def test_a_role_without_a_password_is_rolled_back_to_no_password(harness):
    result = harness.rotate_postgres(FAKE_ROLE_ROW="role:", FAKE_CHECK_RC="1")
    assert result.returncode == 1
    assert harness.log("alter.log").splitlines()[1] == (
        'ALTER ROLE "postgres" PASSWORD NULL;'
    )


def test_connection_strings_for_another_server_or_user_are_left_and_named(harness):
    text = harness.env_file.read_text()
    text += (
        "REPORTING_DATABASE_URL=postgresql://postgres:elsewhere-pw@db.example.com:5432/r\n"
        "OTHER_USER_DATABASE_URL=postgresql://reader:reader-pw@postgres:5432/data\n"
        f'QUOTED_DATABASE_URL="postgresql+asyncpg://postgres:{OLD}@wildbox-postgres/identity"\n'
        "NOT_A_URL=postgres\n"
    )
    harness.env_file.write_text(text)
    result = harness.rotate_postgres()
    assert result.returncode == 0, result.stderr

    after = harness.values()
    new = after["POSTGRES_PASSWORD"]
    assert after["REPORTING_DATABASE_URL"].endswith(
        "postgres:elsewhere-pw@db.example.com:5432/r"
    )
    assert after["OTHER_USER_DATABASE_URL"].endswith(
        "reader:reader-pw@postgres:5432/data"
    )
    assert after["QUOTED_DATABASE_URL"] == (
        f'"postgresql+asyncpg://postgres:{new}@wildbox-postgres/identity"'
    )
    assert after["NOT_A_URL"] == "postgres"
    assert "NOT changed" in result.stdout
    assert "REPORTING_DATABASE_URL: host 'db.example.com'" in result.stdout
    assert "OTHER_USER_DATABASE_URL: it connects as another user" in result.stdout
    assert "elsewhere-pw" not in result.stdout and "reader-pw" not in result.stdout


def test_a_custom_postgres_user_is_the_role_that_is_changed(harness):
    text = harness.env_file.read_text().replace("://postgres:", "://wbadmin:")
    text = re.sub(r"(?m)^POSTGRES_USER=.*$", "POSTGRES_USER=wbadmin", text)
    harness.env_file.write_text(text)
    result = harness.rotate_postgres()
    assert result.returncode == 0, result.stderr
    assert harness.log("alter.log").startswith('ALTER ROLE "wbadmin" PASSWORD ')
    new = harness.values()["POSTGRES_PASSWORD"]
    assert (
        f"://wbadmin:{new}@postgres:5432/identity" in harness.values()["DATABASE_URL"]
    )


def test_a_role_name_that_is_not_plain_is_refused(harness):
    text = re.sub(
        r"(?m)^POSTGRES_USER=.*$",
        'POSTGRES_USER=postgres"; DROP ROLE x; --',
        harness.env_file.read_text(),
    )
    harness.env_file.write_text(text)
    result = harness.rotate_postgres()
    assert result.returncode == 1
    assert "not a plain role name" in result.stderr
    assert harness.log("alter.log") == ""


def _database_url_sources(compose_file):
    """{service: variables} for every DATABASE_URL a compose file builds."""
    text = (REPO_ROOT / compose_file).read_text()
    compose = yaml.load(text, Loader=_ComposeLoader)  # nosec B506
    sources = {}
    for name, service in (compose.get("services") or {}).items():
        environment = service.get("environment") or []
        if isinstance(environment, dict):
            environment = [f"{k}={v}" for k, v in environment.items()]
        for item in environment:
            key, _, value = str(item).partition("=")
            if key.endswith("DATABASE_URL"):
                sources[name] = set(re.findall(r"\$\{([A-Z0-9_]+)", value))
    return sources


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose tags such as !override as plain nodes."""


def _untagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def test_every_connection_string_the_compose_files_use_is_one_the_rotation_rewrites():
    """A service given a new DSN variable must not be left behind again."""
    used = set()
    for compose_file in (
        "docker-compose.yml",
        "docker-compose.prod.yml",
        "docker-compose.dev.yml",
    ):
        for variables in _database_url_sources(compose_file).values():
            used |= variables
    assert used == set(DSN_KEYS)
    # Each is in the template as a connection string to the stack's
    # PostgreSQL, which is what the acceptance test above rotates.
    template = _parse(_env_from_example())
    for key in DSN_KEYS:
        assert re.match(
            r"postgresql(\+asyncpg)?://postgres:[^@]+@postgres:5432/", template[key]
        )


def test_the_documented_list_of_services_to_recreate_matches_the_compose_file():
    services = list(_database_url_sources("docker-compose.yml"))
    documented = (REPO_ROOT / "docs" / "SECURITY_SECRETS_ROTATION.md").read_text()
    assert f"docker compose up -d --no-deps {' '.join(services)}\n" in documented


# --- Redis: the same procedure (#723) ---------------------------------------

COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.dev.yml",
)
# A Redis URL as the compose files build one: the default user, the password
# from REDIS_PASSWORD, the stack's Redis, optionally behind an override.
COMPOSE_REDIS_URL = re.compile(
    r"(?:\$\{([A-Z0-9_]+):-)?rediss?://:\$\{REDIS_PASSWORD\}@wildbox-redis:6379/(\d+)"
)


def _compose_redis_urls():
    """[(override variable or '', database)] for every Redis URL in compose."""
    found = []
    for compose_file in COMPOSE_FILES:
        for line in (REPO_ROOT / compose_file).read_text().splitlines():
            if line.lstrip().startswith("#") or "redis://" not in line:
                continue
            line = re.sub(r"\$\{REDIS_PASSWORD:\?[^}]*\}", "${REDIS_PASSWORD}", line)
            urls = COMPOSE_REDIS_URL.findall(line)
            # A URL of another shape would be one the rotation does not know.
            assert len(urls) == line.count("redis://"), f"{compose_file}: {line}"
            found += urls
    return found


def _redis_overrides():
    return sorted({variable for variable, _ in _compose_redis_urls() if variable})


def test_every_redis_url_the_compose_files_build_is_one_the_rotation_reaches():
    """Each is built from REDIS_PASSWORD or from a variable .env can set."""
    urls = _compose_redis_urls()
    assert len(urls) > 10
    overrides = _redis_overrides()
    assert "IDENTITY_REDIS_URL" in overrides and "CSPM_CELERY_BROKER_URL" in overrides
    # The server itself takes the variable as an argument, which is what the
    # script checks before it promises the password survives a restart.
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())
    assert "--requirepass ${REDIS_PASSWORD:?" in compose["services"]["wildbox-redis"][
        "command"
    ]


def test_every_redis_url_gets_the_new_password_and_nothing_else_changes(harness):
    """The acceptance test of #723: every URL an operator can override."""
    overrides = _redis_overrides()
    harness.add_to_env(
        "".join(
            f"{variable}=redis://:{OLD_REDIS}@wildbox-redis:6379/{index}\n"
            for index, variable in enumerate(overrides)
        )
    )
    before = harness.values()
    result = harness.rotate_redis()
    assert result.returncode == 0, result.stdout + result.stderr

    after = harness.values()
    new = after["REDIS_PASSWORD"]
    assert new != OLD_REDIS
    for variable in overrides:
        assert after[variable] == before[variable].replace(OLD_REDIS, new), variable
    # Nothing else in the file moved: no PostgreSQL connection string either.
    assert {k for k, v in after.items() if v != before[k]} == {
        "REDIS_PASSWORD",
        *overrides,
    }
    assert OLD_REDIS not in harness.env_file.read_text()
    validator = _load(VALIDATOR, "validate_secrets")
    assert validator.validate_secret("REDIS_PASSWORD", new)[0]
    for variable in ("REDIS_PASSWORD", *overrides):
        assert re.search(rf"^    {variable}$", result.stdout, re.M), variable


def test_the_running_redis_gets_the_same_password_and_is_asked_about_both(harness):
    result = harness.rotate_redis()
    assert result.returncode == 0, result.stderr
    new = harness.values()["REDIS_PASSWORD"]
    # The server holds what .env holds: the two cannot diverge.
    assert harness.redis_password() == new

    calls = harness.redis_calls()
    sets = [c for c in calls if c["commands"][0].startswith("CONFIG SET")]
    assert len(sets) == 1
    # Authenticated with the old password, one command, the value escaped
    # byte by byte so that nothing in it can end the argument.
    assert sets[0]["auth"] == OLD_REDIS
    escaped = "".join(f"\\x{byte:02x}" for byte in new.encode())
    assert sets[0]["commands"] == [f'CONFIG SET requirepass "{escaped}"']
    # Then it asked the server about the new password and about the old one.
    after = calls[calls.index(sets[0]) + 1 :]
    assert [(c["auth"], c["commands"]) for c in after] == [
        (new, ["PING"]),
        (OLD_REDIS, ["PING"]),
    ]
    assert "accepted the new one and refused the old one" in result.stdout


def test_redis_is_asked_over_the_network_and_no_password_reaches_argv(harness):
    result = harness.rotate_redis()
    assert result.returncode == 0, result.stderr
    harness.no_redis_secret_in(result, harness.values()["REDIS_PASSWORD"])
    executions = [line for line in harness.log().splitlines() if " exec " in line]
    assert len(executions) == 5
    for line in executions:
        # The container's own address, not the loopback, and the password
        # from stdin into REDISCLI_AUTH: no -a, no -u, no AUTH argument.
        assert "exec -T wildbox-redis sh -c" in line
        assert 'redis-cli -h "$(hostname -i' in line
        assert "IFS= read -r REDISCLI_AUTH" in line
        assert not re.search(r"redis-cli.* (-a|-u|--pass|--user)\b", line)
        assert "requirepass" not in line


def test_the_operator_is_told_to_recreate_redis_too_and_why(harness):
    harness.add_to_env(f"IDENTITY_REDIS_URL=redis://:{OLD_REDIS}@wildbox-redis:6379/0\n")
    result = harness.rotate_redis()
    assert result.returncode == 0, result.stderr
    out = result.stdout
    # Redis first, then exactly the services whose rendered configuration
    # carries the new password: identity through the URL .env overrides,
    # guardian through the one Compose builds.
    assert "    docker compose up -d --no-deps wildbox-redis identity guardian\n" in out
    assert "OLD password on its" in out and "comes back with the old password" in out
    assert "keeps its data volume" in out
    # A profile's service holds it too, and is named apart from the command:
    # `docker compose up` would start it for an operator who never ran it.
    command = re.search(r"^    docker compose up .*$", out, re.M).group(0)
    assert "backup" not in command
    assert re.search(r"Compose profile that is not active.*\n.*\n.*\n\n    backup\n", out)
    backup = harness.backups()[0]
    assert f"Then delete {backup}" in out
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert stat.S_IMODE(harness.env_file.stat().st_mode) == 0o600


def test_a_profile_service_is_not_named_in_the_postgres_command_either(harness):
    result = harness.rotate_postgres()
    assert result.returncode == 0, result.stderr
    assert "    docker compose up -d --no-deps identity data guardian\n" in result.stdout
    assert re.search(r"not active.*\n.*\n.*\n\n    backup\n", result.stdout)


def test_an_active_profile_puts_its_service_in_the_command(harness):
    template = json.loads(harness.template.read_text())
    del template["services"]["backup"]["profiles"]
    harness.template.write_text(json.dumps(template))
    result = harness.rotate_redis()
    assert result.returncode == 0, result.stderr
    assert (
        "    docker compose up -d --no-deps wildbox-redis identity guardian backup\n"
        in result.stdout
    )
    assert "not active here" not in result.stdout


def _refused(harness, result, reason):
    assert result.returncode == 1, result.stdout + result.stderr
    assert "REFUSING to rotate REDIS_PASSWORD" in result.stderr
    assert reason in result.stderr
    assert "Nothing was changed" in result.stderr
    assert harness.backups() == []
    assert "Rotated" not in result.stdout
    assert not any(
        call["commands"][0].startswith("CONFIG SET") for call in harness.redis_calls()
    )
    assert harness.redis_password() == OLD_REDIS
    assert OLD_REDIS not in result.stdout + result.stderr + harness.log()


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"FAKE_RUNNING": "postgres"}, "'wildbox-redis' service is not running"),
        (
            {"FAKE_REDIS_PASSWORD": "what-the-server-really-holds"},
            "the running Redis refuses the REDIS_PASSWORD",
        ),
        ({"FAKE_REDIS_PING": "down"}, "could not ask Redis"),
        ({"FAKE_CONFIG_RC": "1"}, "does not pass the REDIS_PASSWORD"),
        (
            {"FAKE_REDIS_PERSISTENCE": "aof_enabled:0 aof_last_write_status:ok"},
            "not writing its append-only file",
        ),
        (
            {"FAKE_REDIS_PERSISTENCE": "aof_enabled:1 aof_last_write_status:err"},
            "not writing its append-only file",
        ),
        ({"FAKE_REDIS_INFO": "down"}, "not writing its append-only file"),
    ],
    ids=[
        "redis-stopped",
        "env-and-server-disagree",
        "unreachable",
        "compose-unreadable",
        "aof-off",
        "aof-write-failed",
        "persistence-unknown",
    ],
)
def test_the_redis_rotation_is_refused_rather_than_half_done(harness, overrides, reason):
    original = harness.env_file.read_bytes()
    _refused(harness, harness.rotate_redis(**overrides), reason)
    assert harness.env_file.read_bytes() == original


def test_the_redis_rotation_is_refused_without_a_current_password(harness):
    text = re.sub(r"(?m)^REDIS_PASSWORD=.*\n", "", harness.env_file.read_text())
    harness.env_file.write_text(text)
    _refused(harness, harness.rotate_redis(), "REDIS_PASSWORD is not set")
    assert harness.env_file.read_text() == text
    assert harness.redis_calls() == []


def test_the_redis_rotation_is_refused_when_compose_does_not_pass_the_password(
    harness,
):
    """Then a recreated Redis would not start with the rotated password."""
    template = json.loads(harness.template.read_text())
    template["services"]["wildbox-redis"] = {
        "command": ["redis-server", "--requirepass", "set-somewhere-else"]
    }
    harness.template.write_text(json.dumps(template))
    original = harness.env_file.read_bytes()
    _refused(harness, harness.rotate_redis(), "does not pass the REDIS_PASSWORD")
    assert harness.env_file.read_bytes() == original
    assert harness.redis_calls() == []


def test_the_redis_rotation_is_refused_without_docker(harness, tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    for tool in "bash cat dirname grep sed tr tail".split():
        (tools / tool).symlink_to(shutil.which(tool))
    original = harness.env_file.read_bytes()
    result = harness.rotate_redis(path=str(tools))
    assert result.returncode == 1
    assert "docker is not available" in result.stderr
    assert harness.env_file.read_bytes() == original
    assert harness.backups() == []


def _rolled_back(harness, result, original, reason):
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"ROTATION FAILED: {reason}" in result.stderr
    assert "nothing was rotated" in result.stderr
    assert "INCONSISTENT" not in result.stderr
    assert "Rotated" not in result.stdout
    # Both places hold the old password again.
    assert harness.env_file.read_bytes() == original
    assert harness.redis_password() == OLD_REDIS
    assert "The running Redis accepts the previous password." in result.stderr
    # The last thing the script did was ask the server about the old one.
    last = harness.redis_calls()[-1]
    assert (last["auth"], last["commands"]) == (OLD_REDIS, ["PING"])
    assert OLD_REDIS not in result.stdout + result.stderr + harness.log()


@pytest.mark.parametrize(
    "overrides, reason, took",
    [
        ({"FAKE_REDIS_SET": "error honest"}, "Redis did not accept", False),
        ({"FAKE_REDIS_SET": "down honest"}, "Redis did not accept", False),
        # The change took and its reply was lost: the server holds the new
        # password, and the rollback has to put the old one back.
        ({"FAKE_REDIS_SET": "lost honest"}, "Redis did not accept", True),
        # Redis said OK and nothing changed.
        (
            {"FAKE_REDIS_SET": "drop honest"},
            "the server does not accept the new password",
            False,
        ),
        # The change took, and then the server could not be asked.
        (
            {"FAKE_REDIS_PING": "honest down honest"},
            "the server does not accept the new password",
            True,
        ),
        (
            {"FAKE_REDIS_PING": "honest honest down honest"},
            "the server does not refuse the old password",
            True,
        ),
        # A server that still takes the old password next to the new one.
        (
            {"FAKE_REDIS_ALSO_ACCEPTS": OLD_REDIS},
            "the server does not refuse the old password",
            True,
        ),
    ],
    ids=[
        "set-refused",
        "set-unreachable",
        "set-reply-lost",
        "set-did-not-take",
        "new-cannot-be-checked",
        "old-cannot-be-checked",
        "old-still-accepted",
    ],
)
def test_a_failed_redis_step_restores_the_env_file_and_the_server(
    harness, overrides, reason, took
):
    harness.add_to_env(f"IDENTITY_REDIS_URL=redis://:{OLD_REDIS}@wildbox-redis:6379/0\n")
    original = harness.env_file.read_bytes()
    result = harness.rotate_redis(**overrides)
    _rolled_back(harness, result, original, reason)
    # When the server held the new password, the old one was set back by a
    # client that authenticated with the new one.
    restores = [
        call
        for call in harness.redis_calls()
        if call["commands"][0].startswith("CONFIG SET") and call["auth"] != OLD_REDIS
    ]
    assert len(restores) == 1
    escaped = "".join(f"\\x{byte:02x}" for byte in OLD_REDIS.encode())
    assert restores[0]["commands"] == [f'CONFIG SET requirepass "{escaped}"']
    assert (harness.state / "redis_password").exists() == took


@pytest.mark.parametrize(
    "overrides",
    [
        # The change took, and Redis is gone when the script tries to undo it.
        {"FAKE_REDIS_SET": "lost down", "FAKE_REDIS_PING": "honest down"},
        # It answers again, and holds the new password after all.
        {"FAKE_REDIS_SET": "lost down"},
    ],
    ids=["unreachable", "still-the-new-password"],
)
def test_a_redis_that_cannot_be_put_back_is_reported_as_inconsistent(
    harness, overrides
):
    original = harness.env_file.read_bytes()
    result = harness.rotate_redis(**overrides)
    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONSISTENT" in result.stderr
    assert "nothing was rotated" not in result.stderr
    assert "accepts the previous password" not in result.stderr
    # .env is back regardless, and the way out is the one that always works:
    # Redis starts with the password on its command line.
    assert harness.env_file.read_bytes() == original
    assert (
        "    docker compose up -d --no-deps --force-recreate wildbox-redis\n"
        in result.stderr
    )
    assert OLD_REDIS not in result.stdout + result.stderr + harness.log()


def test_an_interrupted_redis_rotation_is_rolled_back(harness):
    """SIGTERM while the server is being changed: both places are put back."""
    original = harness.env_file.read_bytes()
    process = subprocess.Popen(
        ["bash", str(ROTATE), "--secret", "REDIS_PASSWORD"],
        env=harness.env(FAKE_REDIS_SET="slow honest"),
        cwd=harness.tmp,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.time() + 60
    while not (harness.state / "redis_slow").exists():
        assert process.poll() is None and time.time() < deadline, process.communicate()
        time.sleep(0.05)
    # .env already holds the new password at this point.
    assert harness.env_file.read_bytes() != original
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=60)
    assert process.returncode == 1, stdout + stderr
    assert "ROTATION FAILED: interrupted." in stderr
    assert "nothing was rotated" in stderr
    assert harness.env_file.read_bytes() == original
    assert harness.redis_password() == OLD_REDIS
    assert "Rotated" not in stdout


def test_redis_urls_for_another_server_or_user_are_left_and_named(harness):
    harness.add_to_env(
        f"IDENTITY_REDIS_URL=redis://:{OLD_REDIS}@wildbox-redis:6379/0\n"
        f"NAMED_DEFAULT_REDIS_URL=rediss://default:{OLD_REDIS}@wildbox-redis/3\n"
        f"QUOTED_REDIS_URL='redis://:{OLD_REDIS}@wildbox-redis:6379/4?health_check_interval=30'\n"
        "CACHE_REDIS_URL=redis://:elsewhere-pw@cache.example.com:6379/0\n"
        "ACL_USER_REDIS_URL=redis://reporting:reporting-pw@wildbox-redis:6379/5\n"
        "NO_PASSWORD_REDIS_URL=redis://wildbox-redis:6379/6\n"
        "USER_ONLY_REDIS_URL=redis://someone@wildbox-redis:6379/7\n"
        "OTHER_PLAIN_REDIS_URL=redis://cache.example.com:6379/0\n"
        "NOT_A_URL=wildbox-redis\n"
    )
    before = harness.values()
    result = harness.rotate_redis()
    assert result.returncode == 0, result.stderr

    after = harness.values()
    new = after["REDIS_PASSWORD"]
    assert after["IDENTITY_REDIS_URL"] == f"redis://:{new}@wildbox-redis:6379/0"
    assert after["NAMED_DEFAULT_REDIS_URL"] == f"rediss://default:{new}@wildbox-redis/3"
    assert after["QUOTED_REDIS_URL"] == (
        f"'redis://:{new}@wildbox-redis:6379/4?health_check_interval=30'"
    )
    left = (
        "CACHE_REDIS_URL",
        "ACL_USER_REDIS_URL",
        "NO_PASSWORD_REDIS_URL",
        "USER_ONLY_REDIS_URL",
        "OTHER_PLAIN_REDIS_URL",
        "NOT_A_URL",
    )
    for key in (*left, *DSN_KEYS, "POSTGRES_PASSWORD"):
        assert after[key] == before[key], key

    out = result.stdout
    assert "NOT changed" in out
    assert "CACHE_REDIS_URL: host 'cache.example.com' is not this stack's Redis" in out
    assert "ACL_USER_REDIS_URL: it connects as another user" in out
    assert "NO_PASSWORD_REDIS_URL: it carries no password" in out
    assert "USER_ONLY_REDIS_URL: it carries no password" in out
    # A Redis that is not the stack's and holds no password is nobody's concern.
    assert "OTHER_PLAIN_REDIS_URL" not in out and "NOT_A_URL" not in out
    assert "elsewhere-pw" not in out and "reporting-pw" not in out


def test_a_postgres_rotation_leaves_the_redis_urls_alone(harness):
    harness.add_to_env(f"IDENTITY_REDIS_URL=redis://:{OLD_REDIS}@wildbox-redis:6379/0\n")
    result = harness.rotate_postgres()
    assert result.returncode == 0, result.stderr
    assert harness.values()["IDENTITY_REDIS_URL"] == (
        f"redis://:{OLD_REDIS}@wildbox-redis:6379/0"
    )
    assert harness.values()["REDIS_PASSWORD"] == OLD_REDIS
    assert harness.redis_calls() == []


def test_a_redis_under_another_service_name_is_the_one_that_is_changed(harness):
    template = json.loads(harness.template.read_text())
    template["services"]["cache"] = template["services"].pop("wildbox-redis")
    harness.template.write_text(
        json.dumps(template).replace("@wildbox-redis:", "@cache:")
    )
    harness.add_to_env(f"IDENTITY_REDIS_URL=redis://:{OLD_REDIS}@cache:6379/0\n")
    result = harness.rotate_redis(REDIS_SERVICE="cache", FAKE_RUNNING="cache")
    assert result.returncode == 0, result.stdout + result.stderr
    new = harness.values()["REDIS_PASSWORD"]
    assert harness.values()["IDENTITY_REDIS_URL"] == f"redis://:{new}@cache:6379/0"
    assert "exec -T cache sh -c" in harness.log()
    assert "    docker compose up -d --no-deps cache identity guardian\n" in result.stdout


def test_a_redis_password_with_awkward_characters_is_still_the_one_presented(harness):
    """An operator's own password: it is read from .env, never interpreted."""
    awkward = "p@ss w0rd\\with\"quotes'and#hash"
    text = re.sub(
        r"(?m)^REDIS_PASSWORD=.*$",
        lambda _: f"REDIS_PASSWORD={awkward}",
        harness.env_file.read_text(),
    )
    harness.env_file.write_text(text)
    result = harness.rotate_redis(
        FAKE_REDIS_PASSWORD=awkward, FAKE_REDIS_SET="lost honest"
    )
    # The change took and its reply was lost, so the script put the old
    # password back: it authenticated with it, byte for byte, and sent it
    # back escaped so that the quotes and the backslash end nothing.
    assert result.returncode == 1, result.stdout + result.stderr
    assert "nothing was rotated" in result.stderr
    calls = harness.redis_calls()
    assert calls[0] == {"auth": awkward, "commands": ["PING"]}
    assert calls[-1] == {"auth": awkward, "commands": ["PING"]}
    assert harness.log("redis_password") == awkward
    assert awkward not in result.stdout + result.stderr + harness.log()


def test_the_list_says_redis_is_changed_in_the_server_and_the_urls():
    result = subprocess.run(
        ["bash", str(ROTATE), "--list"], capture_output=True, text=True, timeout=30
    )
    redis = result.stdout.split("REDIS_PASSWORD", 1)[1].split("POSTGRES_PASSWORD")[0]
    assert "running Redis" in redis and "every Redis" in redis and "URL" in redis
    assert "is not rewritten" not in result.stdout


def test_the_help_text_ends_where_the_header_ends():
    result = subprocess.run(
        ["bash", str(ROTATE), "--help"], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0
    lines = result.stdout.splitlines()
    assert lines[-1] == "# argument list."
    assert "--secret REDIS_PASSWORD" in result.stdout
    assert "set -euo pipefail" not in result.stdout


# --- every secret: a value the stack accepts, and an accurate next step ------


def _generator_calls():
    """generate_secrets.py's secrets_map, as source text per name."""
    tree = ast.parse(GENERATOR.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "secrets_map" for t in node.targets
        ):
            return {
                ast.literal_eval(k): ast.unparse(v)
                for k, v in zip(node.value.keys, node.value.values)
            }
    raise AssertionError("secrets_map not found in generate_secrets.py")


def test_a_rotated_secret_is_drawn_the_way_a_fresh_install_draws_it():
    """One shape per secret, in both scripts: validators check the shape."""
    fresh = _generator_calls()
    script = ROTATE.read_text()
    for name in ROTATABLE:
        call = re.search(rf'"{name}": lambda: gen\.(.+),', script)
        assert call, f"{name} has no generator in rotate_secrets.sh"
        assert call.group(1).replace("'", '"') == fresh[name].replace("'", '"'), name


IN_A_SERVER = ("POSTGRES_PASSWORD", "REDIS_PASSWORD")


@pytest.mark.parametrize("name", [n for n in ROTATABLE if n not in IN_A_SERVER])
def test_a_rotated_value_passes_the_validator_make_start_runs(harness, name):
    """API_KEY was rotated to a value `make validate-secrets` rejects."""
    validator = _load(VALIDATOR, "validate_secrets")
    before = harness.values()
    result = harness.run("--secret", name, FAKE_RUNNING="")
    if name == "JWT_SECRET_KEY":
        # Its own guard, covered by test_api_key_hash_secret.py.
        assert result.returncode == 1
        return
    assert result.returncode == 0, result.stderr
    after = harness.values()
    assert after[name] != before.get(name)
    ok, errors = validator.validate_secret(name, after[name])
    assert ok, errors
    assert after[name] not in result.stdout + result.stderr + harness.log()
    # Only that line changed.
    assert {k for k in after if after[k] != before.get(k)} == {name}


def test_the_api_key_message_says_what_reads_it(harness):
    result = harness.run("--secret", "API_KEY")
    assert result.returncode == 0, result.stderr
    assert re.fullmatch(r"wsk_[a-z0-9]+\.[a-f0-9]{64}", harness.values()["API_KEY"])
    assert "not accepted as a credential" in result.stdout
    assert "    docker compose up -d --no-deps api\n" in result.stdout
    assert "GATEWAY_INTERNAL_SECRET" not in result.stdout


def test_nextauth_secret_is_not_a_secret_any_more(harness):
    """Nothing read it (#665): the dashboard has no NextAuth. It was passed
    to the dashboard container, generated, validated and rotatable."""
    before = harness.values()
    result = harness.run("--secret", "NEXTAUTH_SECRET")

    assert result.returncode == 2
    assert "'NEXTAUTH_SECRET' is not a rotatable secret" in result.stderr
    assert harness.values() == before


def test_the_list_describes_each_secret_by_what_reads_it():
    result = subprocess.run(
        ["bash", str(ROTATE), "--list"], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0
    listing = result.stdout
    for name in ROTATABLE:
        assert re.search(rf"^  {name}\s", listing, re.M), name
    assert "NEXTAUTH_SECRET" not in listing
    assert "sessions are invalidated" not in listing
    postgres = listing.split("POSTGRES_PASSWORD", 1)[1]
    assert "every" in postgres and "connection string" in postgres
    assert "Must be changed in Postgres first" not in listing


def test_nothing_in_the_dashboard_reads_nextauth_secret():
    """Why the secret is gone. If this fails, the dashboard needs it back."""
    source = REPO_ROOT / "open-security-dashboard"
    readers = [
        str(path.relative_to(REPO_ROOT))
        for pattern in ("*.ts", "*.tsx", "*.js", "*.mjs")
        for path in source.rglob(pattern)
        if "node_modules" not in path.parts
        and ".next" not in path.parts
        and "NEXTAUTH_SECRET" in path.read_text(errors="ignore")
    ]
    assert readers == []
    package = json.loads((source / "package.json").read_text())
    dependencies = {
        **package.get("dependencies", {}),
        **package.get("devDependencies", {}),
    }
    assert "next-auth" not in dependencies


def test_the_tools_service_only_requires_api_key_at_start():
    """What the API_KEY message claims: read by the settings, not by auth."""
    app = REPO_ROOT / "open-security-tools" / "app"
    readers = sorted(
        str(path.relative_to(app))
        for path in app.rglob("*.py")
        if "settings.get_api_key()" in path.read_text(errors="ignore")
    )
    assert readers == ["main.py"]


# --- the real compose files --------------------------------------------------


def _services_reading(variable):
    """Services whose compose environment interpolates ${variable...}."""
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())
    pattern = re.compile(r"\$\{" + variable + r"[:}?-]")
    return {
        name
        for name, service in compose["services"].items()
        if "profiles" not in service
        and pattern.search(
            json.dumps([service.get("environment"), service.get("command")])
        )
    }


def _renderable_env():
    """The template, with every variable the compose file requires.

    .env.example leaves some variables to the generator; each one the compose
    file requires (${NAME:?...}) gets a made-up value so that it renders.
    """
    text = _env_from_example()
    compose_text = (REPO_ROOT / "docker-compose.yml").read_text()
    for variable in sorted(set(re.findall(r"\$\{([A-Z0-9_]+):\?", compose_text))):
        if not re.search(rf"(?m)^{variable}=.+", text):
            text += f"{variable}=made-up-{uuid.uuid4().hex}\n"
    return text


@pytest.mark.parametrize("name", ["API_KEY", "CSPM_CREDENTIAL_KEY"])
def test_the_services_to_recreate_come_from_the_real_compose_file(
    docker, tmp_path, name
):
    """The script renders the repository's compose file; nothing is started."""
    env_file = tmp_path / "stack.env"
    env_file.write_text(_renderable_env())
    result = subprocess.run(
        ["bash", str(ROTATE), "--secret", name],
        env={
            "PATH": os.environ["PATH"],
            "HOME": os.environ.get("HOME", str(tmp_path)),
            "ENV_FILE": str(env_file),
            "COMPOSE_FILE": str(REPO_ROOT / "docker-compose.yml"),
            "COMPOSE_PROJECT_NAME": f"wbtest649-{uuid.uuid4().hex[:8]}",
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    command = re.search(
        r"^    docker compose up -d --no-deps (.+)$", result.stdout, re.M
    )
    assert command, result.stdout
    listed = set(command.group(1).split())
    expected = _services_reading(name)
    assert expected, f"no service reads {name}?"
    # Exactly the default services that read it, which is also what --list
    # and the next-step text say about each of these.
    assert listed == expected
    exactly = {
        "API_KEY": {"api", "tools-worker", "tools-flower"},
        "CSPM_CREDENTIAL_KEY": {"cspm", "cspm-worker"},
    }
    assert listed == exactly[name]
    assert _parse(env_file.read_text())[name] not in result.stdout + result.stderr


def test_the_redis_services_to_recreate_come_from_the_real_compose_file(
    docker, harness
):
    """The repository's compose file, rendered by the real docker.

    The Redis server is the stub, so no container is started: `config` goes
    to the real docker, `ps` and `exec` do not.
    """
    harness.env_file.write_text(_renderable_env())
    overrides = {
        "FAKE_REAL_DOCKER": shutil.which("docker"),
        "COMPOSE_FILE": str(REPO_ROOT / "docker-compose.yml"),
        "COMPOSE_PROJECT_NAME": f"wbtest723-{uuid.uuid4().hex[:8]}",
        "HOME": os.environ.get("HOME", str(harness.tmp)),
    }
    for name in ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"):
        if name in os.environ:
            overrides[name] = os.environ[name]
    result = harness.rotate_redis(**overrides)
    assert result.returncode == 0, result.stdout + result.stderr
    new = harness.values()["REDIS_PASSWORD"]
    assert harness.redis_password() == new
    harness.no_redis_secret_in(result, new)

    command = re.search(
        r"^    (docker compose up -d --no-deps (.+))$", result.stdout, re.M
    )
    assert command, result.stdout
    listed = command.group(2).split()
    # Redis itself, first, then every default service that reads the
    # variable. The backup profile's service reads it too and is named apart.
    assert listed[0] == "wildbox-redis"
    assert set(listed) == _services_reading("REDIS_PASSWORD")
    assert {"identity", "guardian", "cspm", "agents", "api"} <= set(listed)
    assert "backup" not in listed
    assert re.search(r"not active here.*\n.*\n.*\n\n    backup\n", result.stdout)
    # The guide shows the same command.
    documented = (REPO_ROOT / "docs" / "SECURITY_SECRETS_ROTATION.md").read_text()
    assert f"{command.group(1)}\n" in documented


# --- a real PostgreSQL -------------------------------------------------------

REAL_COMPOSE = """\
services:
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?required}
      - POSTGRES_DB=identity
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      # Over TCP: the image's first-run server listens on the socket only.
      test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U $${POSTGRES_USER} -d identity"]
      interval: 1s
      timeout: 5s
      retries: 60
  # Stands for a service: it holds a connection string in its environment
  # and connects to PostgreSQL over the network, as identity does.
  client:
    image: postgres:15
    environment:
      - DATABASE_URL=${DATABASE_URL}
    command: sleep infinity
    stop_grace_period: 1s
  bystander:
    image: postgres:15
    environment:
      - UNRELATED=${UNRELATED}
    command: sleep infinity
    stop_grace_period: 1s
volumes:
  pgdata:
"""


class Stack:
    def __init__(self, root):
        self.root = root
        self.project = f"wbtest649-{uuid.uuid4().hex[:8]}"
        self.compose_file = root / "compose.yml"
        self.compose_file.write_text(REAL_COMPOSE)
        self.old = f"old-{uuid.uuid4().hex}"
        self.env_file = root / "stack.env"
        self.env_file.write_text(
            "POSTGRES_USER=wbadmin\n"
            f"POSTGRES_PASSWORD={self.old}\n"
            f"DATABASE_URL=postgresql+asyncpg://wbadmin:{self.old}@postgres:5432/identity\n"
            f"GUARDIAN_DATABASE_URL=postgresql://wbadmin:{self.old}@postgres:5432/guardian\n"
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
            ["bash", str(ROTATE), "--secret", "POSTGRES_PASSWORD"],
            env=env,
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def values(self):
        return _parse(self.env_file.read_text())

    def client_can_log_in(self, password):
        """From the client container, over the network, as a service would.

        The password goes over stdin and into PGPASSWORD inside the
        container; it is in no argument list here either.
        """
        result = self.compose(
            "exec",
            "-T",
            "client",
            "sh",
            "-c",
            "IFS= read -r PGPASSWORD; export PGPASSWORD; "
            'exec psql -h postgres -U wbadmin -d identity -w -X -q -tA -c "SELECT 1"',
            stdin=password + "\n",
            check=False,
        )
        if result.returncode == 0:
            assert result.stdout.strip() == "1"
            return True
        assert "password authentication failed" in result.stderr, result.stderr
        return False

    def client_dsn_logs_in(self):
        """With the connection string the client container was started with."""
        result = self.compose(
            "exec",
            "-T",
            "client",
            "sh",
            "-c",
            # psql does not know the +asyncpg driver suffix.
            'exec psql "$(echo "$DATABASE_URL" | sed "s/+asyncpg//")" -w -X -q -tA -c "SELECT 1"',
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "1"

    def container_id(self, service):
        return self.compose("ps", "-q", service).stdout.strip()


@pytest.fixture(scope="module")
def stack(docker, tmp_path_factory):
    s = Stack(tmp_path_factory.mktemp("stack649"))
    try:
        s.compose("up", "-d", "--wait")
        yield s
    finally:
        s.compose("down", "-v", "--remove-orphans", check=False)


def test_real_rotation_old_password_refused_new_accepted(stack):
    assert stack.client_can_log_in(stack.old)
    assert not stack.client_can_log_in("not-the-password")
    assert stack.client_dsn_logs_in()
    postgres_before = stack.container_id("postgres")
    bystander_before = stack.container_id("bystander")

    result = stack.rotate()
    assert result.returncode == 0, result.stdout + result.stderr

    values = stack.values()
    new = values["POSTGRES_PASSWORD"]
    assert new != stack.old
    assert stack.old not in result.stdout + result.stderr
    assert new not in result.stdout + result.stderr

    # The server: old refused, new accepted, right away.
    assert not stack.client_can_log_in(stack.old)
    assert stack.client_can_log_in(new)

    # .env: both connection strings carry it.
    assert values["DATABASE_URL"] == (
        f"postgresql+asyncpg://wbadmin:{new}@postgres:5432/identity"
    )
    assert values["GUARDIAN_DATABASE_URL"] == (
        f"postgresql://wbadmin:{new}@postgres:5432/guardian"
    )

    # The running client still holds the old connection string, which is
    # why the script names it; the bystander and postgres are not named.
    assert not stack.client_dsn_logs_in()
    command = re.search(
        r"^    (docker compose up -d --no-deps .+)$", result.stdout, re.M
    )
    assert command and command.group(1) == "docker compose up -d --no-deps client"

    # The command the script printed, as printed.
    stack.compose(*command.group(1).split()[2:])
    assert stack.client_dsn_logs_in()
    assert stack.container_id("postgres") == postgres_before
    assert stack.container_id("bystander") == bystander_before

    # The password lives in the server, not in the container's variable:
    # recreating postgres on its data volume changes nothing.
    stack.compose("up", "-d", "--wait", "--force-recreate", "postgres")
    assert stack.client_can_log_in(new)
    assert not stack.client_can_log_in(stack.old)


def test_real_rotation_is_refused_when_postgres_is_stopped(stack):
    stack.compose("stop", "postgres")
    try:
        original = stack.env_file.read_bytes()
        result = stack.rotate()
        assert result.returncode == 1
        assert "REFUSING to rotate POSTGRES_PASSWORD" in result.stderr
        assert stack.env_file.read_bytes() == original
    finally:
        stack.compose("up", "-d", "--wait", "postgres")
    current = stack.values()["POSTGRES_PASSWORD"]
    assert stack.client_can_log_in(current)


# The real docker, except that the first new-password ALTER ROLE never
# reaches the server and reports success: a change that did not take.
DROPPING_DOCKER = r"""#!/usr/bin/env python3
import os
import subprocess
import sys

real = os.environ["REAL_DOCKER"]
if "exec" not in sys.argv:
    os.execv(real, [real, *sys.argv[1:]])
data = sys.stdin.buffer.read()
marker = os.environ["DROPPED_MARKER"]
if data.startswith(b"ALTER ROLE") and not os.path.exists(marker):
    open(marker, "w").close()
    sys.exit(0)
sys.exit(subprocess.run([real, *sys.argv[1:]], input=data).returncode)
"""


def test_real_change_that_did_not_take_is_detected_and_rolled_back(stack, tmp_path):
    """The script asks the server, over the network path a service uses."""
    shim = tmp_path / "bin"
    shim.mkdir()
    docker = shim / "docker"
    docker.write_text(DROPPING_DOCKER)
    docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
    marker = tmp_path / "dropped"

    current = stack.values()["POSTGRES_PASSWORD"]
    original = stack.env_file.read_bytes()
    result = stack.rotate(path_prefix=shim, DROPPED_MARKER=str(marker))

    assert marker.exists(), "the shim never saw the ALTER ROLE"
    assert result.returncode == 1, result.stdout + result.stderr
    assert "does not accept the new password" in result.stderr
    assert "nothing was rotated" in result.stderr
    assert stack.env_file.read_bytes() == original
    assert stack.client_can_log_in(current)
