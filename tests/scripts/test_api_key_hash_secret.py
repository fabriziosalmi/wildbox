"""API_KEY_HASH_SECRET must reach identity, and the JWT rotation guard must
check that it does (#648).

generate_secrets.py wrote API_KEY_HASH_SECRET to .env, but docker-compose.yml
never passed it to identity, which then keyed every API-key digest with
JWT_SECRET_KEY. rotate_secrets.sh refused a JWT rotation only when .env lacked
the variable, so the guard always passed and a routine JWT rotation
invalidated every API key.

These tests cover the three places that broke:

- both compose files pass API_KEY_HASH_SECRET to identity, as a required
  variable;
- the generator draws it independently of JWT_SECRET_KEY;
- rotate_secrets.sh refuses the JWT rotation unless the compose configuration
  (and the running identity, when there is one) carries the variable, and
  --init copies JWT_SECRET_KEY into it without printing either value.

The script is run against a temporary .env and a stub `docker` on PATH, so no
stack and no real secret is involved.
"""

import ast
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ROTATE = REPO_ROOT / "scripts" / "rotate_secrets.sh"
GENERATOR = REPO_ROOT / "scripts" / "generate_secrets.py"

# Fake values, shaped like generated ones. Never real secrets.
JWT = "3f9c1e7a5b2d8f4096e1c7a3b5d9f2e48a6c0b1d3e5f7a9c2b4d6e8f0a1c3e5b"
HASH = "9d1f3b5e7a0c2e4f6b8d0a2c4e6f8b1d3a5c7e9f0b2d4a6c8e0f1b3d5a7c9e2f"


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose tags such as !override as plain nodes."""


def _untagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _untagged)


def _identity_environment(compose_file):
    text = (REPO_ROOT / compose_file).read_text()
    service = yaml.load(text, Loader=_ComposeLoader)["services"][
        "identity"
    ]  # nosec B506
    env = service.get("environment") or []
    if isinstance(env, dict):
        return {k: str(v) for k, v in env.items()}
    return dict(item.split("=", 1) for item in env)


# --- compose ----------------------------------------------------------------


@pytest.mark.parametrize(
    "compose_file", ["docker-compose.yml", "docker-compose.prod.yml"]
)
def test_compose_passes_the_hash_secret_to_identity_as_required(compose_file):
    env = _identity_environment(compose_file)
    assert (
        "API_KEY_HASH_SECRET" in env
    ), f"{compose_file} does not pass API_KEY_HASH_SECRET to identity"
    # ${VAR:?...}: `docker compose config` fails when it is unset, rather than
    # handing identity an empty string.
    assert env["API_KEY_HASH_SECRET"].startswith("${API_KEY_HASH_SECRET:?")


def test_the_base_file_does_not_alias_the_jwt_key():
    """Not a fixed value and not JWT_SECRET_KEY under another name."""
    env = _identity_environment("docker-compose.yml")
    assert "JWT_SECRET_KEY" not in env["API_KEY_HASH_SECRET"]


# --- generator --------------------------------------------------------------


def _generated_secret_calls():
    """The secrets_map literal in generate_secrets.main(), as source text."""
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


def test_a_fresh_install_gets_an_independent_hash_secret():
    calls = _generated_secret_calls()
    assert "API_KEY_HASH_SECRET" in calls
    # Its own random draw: a call to a generate_* helper that does not read
    # the JWT entry.
    assert calls["API_KEY_HASH_SECRET"].startswith("generate_")
    assert "JWT" not in calls["API_KEY_HASH_SECRET"]


# --- rotate_secrets.sh ------------------------------------------------------

FAKE_DOCKER = """#!/usr/bin/env bash
# Stub for `docker compose ...` as rotate_secrets.sh calls it.
echo "$*" >> "$FAKE_DOCKER_LOG"
case " $* " in
  *" config "*) cat "$FAKE_COMPOSE_CONFIG" ;;
  *" ps "*) [ -n "${FAKE_IDENTITY_ID:-}" ] && echo "$FAKE_IDENTITY_ID" ;;
  *" exec "*) exit "${FAKE_EXEC_RC:-0}" ;;
esac
exit 0
"""


@pytest.fixture
def harness(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
    env_file = tmp_path / ".env"
    config = tmp_path / "compose.json"
    log = tmp_path / "docker.log"
    log.write_text("")

    def write_env(**values):
        env_file.write_text("".join(f"{k}={v}\n" for k, v in values.items()))

    def identity_gets(**variables):
        config.write_text(
            json.dumps({"services": {"identity": {"environment": variables}}})
        )

    def run(*args, identity_id="", exec_rc=0):
        env = dict(os.environ)
        env.update(
            PATH=f"{bin_dir}{os.pathsep}{env['PATH']}",
            ENV_FILE=str(env_file),
            FAKE_COMPOSE_CONFIG=str(config),
            FAKE_DOCKER_LOG=str(log),
            FAKE_IDENTITY_ID=identity_id,
            FAKE_EXEC_RC=str(exec_rc),
        )
        env.pop("COMPOSE_FILE", None)
        return subprocess.run(
            ["bash", str(ROTATE), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def read_env():
        return dict(
            line.split("=", 1)
            for line in env_file.read_text().splitlines()
            if "=" in line
        )

    class H:
        pass

    h = H()
    h.write_env, h.identity_gets, h.run, h.read_env, h.log = (
        write_env,
        identity_gets,
        run,
        read_env,
        log,
    )
    return h


def _assert_no_secret_printed(result):
    for value in (JWT, HASH):
        assert value not in result.stdout
        assert value not in result.stderr


def test_jwt_rotation_is_refused_when_env_lacks_the_hash_secret(harness):
    harness.write_env(JWT_SECRET_KEY=JWT)
    harness.identity_gets(JWT_SECRET_KEY=JWT)
    result = harness.run("--secret", "JWT_SECRET_KEY")
    assert result.returncode == 1
    assert "REFUSING" in result.stderr
    assert harness.read_env() == {"JWT_SECRET_KEY": JWT}


def test_jwt_rotation_is_refused_when_identity_does_not_receive_it(harness):
    """#648: .env has it, compose does not pass it. The old guard passed here."""
    harness.write_env(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    harness.identity_gets(JWT_SECRET_KEY=JWT)
    result = harness.run("--secret", "JWT_SECRET_KEY")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "compose configuration does not pass API_KEY_HASH_SECRET" in result.stderr
    assert harness.read_env()["JWT_SECRET_KEY"] == JWT
    _assert_no_secret_printed(result)


def test_jwt_rotation_is_refused_when_compose_passes_it_empty(harness):
    harness.write_env(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    harness.identity_gets(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET="")
    result = harness.run("--secret", "JWT_SECRET_KEY")
    assert result.returncode == 1
    assert harness.read_env()["JWT_SECRET_KEY"] == JWT


def test_jwt_rotation_is_refused_when_running_identity_lacks_it(harness):
    harness.write_env(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    harness.identity_gets(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    result = harness.run("--secret", "JWT_SECRET_KEY", identity_id="abc123", exec_rc=1)
    assert result.returncode == 1
    assert "running identity container does not have" in result.stderr
    assert harness.read_env()["JWT_SECRET_KEY"] == JWT


@pytest.mark.parametrize("identity_id", ["", "abc123"], ids=["stopped", "running"])
def test_jwt_rotation_proceeds_when_identity_receives_it(harness, identity_id):
    harness.write_env(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    harness.identity_gets(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    result = harness.run(
        "--secret", "JWT_SECRET_KEY", identity_id=identity_id, exec_rc=0
    )
    assert result.returncode == 0, result.stderr
    after = harness.read_env()
    assert after["JWT_SECRET_KEY"] != JWT
    assert after["API_KEY_HASH_SECRET"] == HASH
    _assert_no_secret_printed(result)
    calls = harness.log.read_text()
    assert "config --format json" in calls
    assert ("exec -T identity" in calls) == bool(identity_id)


def test_init_seeds_the_hash_secret_with_the_jwt_key_without_printing_it(harness):
    harness.write_env(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    result = harness.run("--secret", "API_KEY_HASH_SECRET", "--init")
    assert result.returncode == 0, result.stderr
    after = harness.read_env()
    assert after["API_KEY_HASH_SECRET"] == JWT
    assert after["JWT_SECRET_KEY"] == JWT
    _assert_no_secret_printed(result)


def test_init_points_at_the_upgrade_not_at_a_restart(harness):
    # Seeding runs while the old stack is up, before the new images exist:
    # restarting the old stack would apply nothing, so the script must not
    # tell the operator to do it.
    harness.write_env(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    result = harness.run("--secret", "API_KEY_HASH_SECRET", "--init")
    assert result.returncode == 0, result.stderr
    assert "Seeded API_KEY_HASH_SECRET" in result.stdout
    assert "UPGRADING.md" in result.stdout
    assert "force-recreate" not in result.stdout


def test_init_is_a_no_op_once_seeded(harness):
    harness.write_env(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=JWT)
    result = harness.run("--secret", "API_KEY_HASH_SECRET", "--init")
    assert result.returncode == 0
    assert "nothing to do" in result.stdout
    assert not list(Path(harness.log).parent.glob(".env.bak.*"))


def test_init_keeps_a_backslash_in_the_value(harness):
    jwt = JWT[:20] + "\\1" + JWT[22:]
    harness.write_env(JWT_SECRET_KEY=jwt, API_KEY_HASH_SECRET=HASH)
    result = harness.run("--secret", "API_KEY_HASH_SECRET", "--init")
    assert result.returncode == 0, result.stderr
    assert harness.read_env()["API_KEY_HASH_SECRET"] == jwt


def test_init_applies_to_the_hash_secret_only(harness):
    harness.write_env(JWT_SECRET_KEY=JWT, API_KEY_HASH_SECRET=HASH)
    result = harness.run("--secret", "JWT_SECRET_KEY", "--init")
    assert result.returncode == 2
    assert harness.read_env()["JWT_SECRET_KEY"] == JWT
