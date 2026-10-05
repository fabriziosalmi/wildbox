"""Rotating POSTGRES_PASSWORD changes the server and every connection string,
or neither (#649), and each secret's next step names what really reads it.

rotate_secrets.sh rewrote only the POSTGRES_PASSWORD= line of .env. The
services do not read that variable: they connect with DATABASE_URL-style
strings that embed the password, and the password itself lives in the running
server. Following the script left every service on the old password in .env
and the server on whatever it had, and the script reported success.

Three kinds of test:

- with a stub `docker` on PATH and a temporary env file built from
  .env.example: what is rewritten, what is sent to the server and how, what
  happens when a step fails, and what the operator is told;
- against the repository's real compose files rendered by `docker compose
  config` (no container is started): which services each secret reaches;
- against a real throwaway PostgreSQL, started under this test's own Compose
  project name: the old password is refused and the new one accepted, from
  another container, before and after it is recreated.

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
import stat
import subprocess
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

DSN_KEYS = (
    "DATABASE_URL",
    "GUARDIAN_DATABASE_URL",
    "DATA_DATABASE_URL",
    "RESPONDER_DATABASE_URL",
)
ROTATABLE = (
    "JWT_SECRET_KEY",
    "GATEWAY_INTERNAL_SECRET",
    "API_KEY",
    "API_KEY_HASH_SECRET",
    "CSPM_CREDENTIAL_KEY",
    "REDIS_PASSWORD",
    "POSTGRES_PASSWORD",
    "NEXTAUTH_SECRET",
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

state = os.environ["FAKE_STATE"]
with open(os.path.join(state, "docker.log"), "a") as log:
    log.write(" ".join(sys.argv[1:]).replace("\n", " ") + "\n")

args = sys.argv[1:]
assert args[:2] == ["compose", "--env-file"], args
env_file, args = args[2], args[3:]
if args[0] == "--profile":
    args = args[2:]
command, args = args[0], args[1:]


def counted(name):
    path = os.path.join(state, "calls_" + name)
    count = int(open(path).read()) + 1 if os.path.exists(path) else 1
    open(path, "w").write(str(count))
    return count


def nth(variable, n):
    """The n-th space-separated exit status in a variable; the last repeats."""
    values = os.environ.get(variable, "0").split()
    return int(values[min(n, len(values)) - 1])


if command == "ps":
    if args[-1] in os.environ.get("FAKE_RUNNING", "").split():
        print("0123456789ab")
elif command == "config":
    # The compose file, rendered with the env file the script named.
    values = dict(
        line.split("=", 1)
        for line in open(env_file).read().splitlines()
        if "=" in line and not line.startswith("#")
    )
    template = open(os.environ["FAKE_COMPOSE_TEMPLATE"]).read()
    sys.stdout.write(
        re.sub(r"\$\{([A-Z_]+)\}", lambda m: values.get(m.group(1), ""), template)
    )
elif command == "exec":
    assert args[0] == "-T" and args[2:4] == ["sh", "-c"], args
    script, data = args[4], sys.stdin.read()
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
        "identity": {"environment": {"DATABASE_URL": "${DATABASE_URL}"}},
        "data": {"environment": {"DATABASE_URL": "${DATA_DATABASE_URL}"}},
        "guardian": {"environment": {"DATABASE_URL": "${GUARDIAN_DATABASE_URL}"}},
        "responder": {"environment": {"DATABASE_URL": "${RESPONDER_DATABASE_URL}"}},
        "dashboard": {"environment": {"NEXTAUTH_SECRET": "${NEXTAUTH_SECRET}"}},
        "api": {"environment": {"API_KEY": "${API_KEY}"}},
        "gateway": {"environment": {}},
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

    def run(self, *args, path=None, **overrides):
        env = {
            "PATH": path or f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "ENV_FILE": str(self.env_file),
            "FAKE_STATE": str(self.state),
            "FAKE_COMPOSE_TEMPLATE": str(self.template),
            "FAKE_RUNNING": "postgres",
            "FAKE_OLD_VERIFIER": OLD_VERIFIER,
        }
        env.update(overrides)
        return subprocess.run(
            ["bash", str(ROTATE), *args],
            env=env,
            cwd=self.tmp,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def rotate_postgres(self, **overrides):
        return self.run("--secret", "POSTGRES_PASSWORD", **overrides)

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
        "    docker compose up -d --no-deps identity data guardian responder\n" in out
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


def test_the_rotation_is_refused_without_docker(harness):
    original = harness.env_file.read_bytes()
    result = harness.rotate_postgres(path="/usr/bin:/bin")
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


@pytest.mark.parametrize("name", [n for n in ROTATABLE if n != "POSTGRES_PASSWORD"])
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


def test_the_nextauth_message_says_nothing_reads_it(harness):
    result = harness.run("--secret", "NEXTAUTH_SECRET")
    assert result.returncode == 0, result.stderr
    assert "no code reads it" in result.stdout
    assert "sessions" not in result.stdout
    assert "    docker compose up -d --no-deps dashboard\n" in result.stdout


def test_the_list_describes_each_secret_by_what_reads_it():
    result = subprocess.run(
        ["bash", str(ROTATE), "--list"], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0
    listing = result.stdout
    for name in ROTATABLE:
        assert re.search(rf"^  {name}\s", listing, re.M), name
    nextauth = listing.split("NEXTAUTH_SECRET", 1)[1]
    assert "nothing reads" in nextauth
    assert "sessions are invalidated" not in listing
    postgres = listing.split("POSTGRES_PASSWORD", 1)[1].split("NEXTAUTH_SECRET")[0]
    assert "every" in postgres and "connection string" in postgres
    assert "Must be changed in Postgres first" not in listing


def test_nothing_in_the_dashboard_reads_nextauth_secret():
    """What the message claims. If this fails, the message is wrong again."""
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


def _docker_available():
    if not shutil.which("docker"):
        return False
    for probe in (["docker", "compose", "version"], ["docker", "info"]):
        if subprocess.run(probe, capture_output=True, timeout=30).returncode != 0:
            return False
    return True


@pytest.fixture(scope="module")
def docker():
    if not _docker_available():
        if os.environ.get("WILDBOX_REQUIRE_DOCKER_TESTS") == "1":
            pytest.fail("docker is required for these tests and is not available")
        pytest.skip("docker is not available")


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


@pytest.mark.parametrize(
    "name", ["API_KEY", "NEXTAUTH_SECRET", "CSPM_CREDENTIAL_KEY", "REDIS_PASSWORD"]
)
def test_the_services_to_recreate_come_from_the_real_compose_file(
    docker, tmp_path, name
):
    """The script renders the repository's compose file; nothing is started."""
    env_file = tmp_path / "stack.env"
    text = _env_from_example()
    # .env.example leaves some variables to the generator; give every one
    # the compose file requires (${NAME:?...}) a made-up value so it renders.
    compose_text = (REPO_ROOT / "docker-compose.yml").read_text()
    for variable in sorted(set(re.findall(r"\$\{([A-Z0-9_]+):\?", compose_text))):
        if not re.search(rf"(?m)^{variable}=.+", text):
            text += f"{variable}=made-up-{uuid.uuid4().hex}\n"
    env_file.write_text(text)
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
    # Every default service that reads it is listed; anything more is a
    # profile service (backup, monitoring) that reads it too.
    assert expected <= listed
    # What --list and the next-step text say about each of these.
    exactly = {
        "API_KEY": {"api", "tools-worker", "tools-flower"},
        "NEXTAUTH_SECRET": {"dashboard"},
        "CSPM_CREDENTIAL_KEY": {"cspm", "cspm-worker"},
    }
    if name in exactly:
        assert listed == exactly[name]
    else:
        assert {"wildbox-redis", "identity", "guardian", "cspm", "agents"} <= listed
    assert _parse(env_file.read_text())[name] not in result.stdout + result.stderr


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
