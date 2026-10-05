"""`make backup` and `make restore-drill` work on the default stack (#681).

scripts/backup_postgres.sh ran on the host and needed three things the
default stack does not give it: POSTGRES_PASSWORD in the environment, a
POSTGRES_HOST the host can resolve, and pg_dump installed. It also skipped
Redis and still exited 0 when redis-cli or REDIS_PASSWORD was missing.

The scripts now run the database tools inside the stack's containers with
`docker compose exec` (compose mode) and keep a host mode for an external
database. Two kinds of test:

- with a stub `docker` (or stub client tools) on PATH: what the scripts ask
  for, that no password reaches an argument list, that a failed step leaves
  nothing behind, and how the drill compares row counts;
- against a real throwaway PostgreSQL and Redis, started under this test's
  own Compose project name: that the archives restore, the drill passes
  without touching the live databases, and the Redis snapshot can be put
  back.

No test reads a real .env: every run gets ENV_FILE, COMPOSE_FILE and
BACKUP_DIR in a temporary directory, and the passwords are made up here.
"""

import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP = REPO_ROOT / "scripts" / "backup_postgres.sh"
RESTORE = REPO_ROOT / "scripts" / "restore_postgres.sh"
RESTORE_REDIS = REPO_ROOT / "scripts" / "restore_redis.sh"
DRILL = REPO_ROOT / "scripts" / "verify_restore.sh"

# Made up for these tests. Never real secrets.
PG_PASSWORD = "pg-password-made-up-for-tests"
REDIS_PASSWORD = "redis-password-made-up-for-tests"
SECRETS = (PG_PASSWORD, REDIS_PASSWORD)

DATABASES = ("identity", "data", "guardian")


def _executable(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def _assert_no_secret(*texts):
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


# --- stub docker ------------------------------------------------------------

FAKE_DOCKER = r'''#!/usr/bin/env python3
"""Stub for `docker compose ...` as the backup scripts call it."""
import os
import sys

state = os.environ["FAKE_STATE"]
with open(os.path.join(state, "docker.log"), "a") as log:
    log.write(" ".join(sys.argv[1:]).replace("\n", " ") + "\n")

args = sys.argv[1:]
assert args[0] == "compose", args
args = args[1:]
if args[0] == "--env-file":
    args = args[2:]
command, args = args[0], args[1:]


def option(name, values):
    return values[values.index(name) + 1] if name in values else None


def counted(name):
    """How many times `name` was asked for, this call included."""
    path = os.path.join(state, "calls_" + name)
    count = int(open(path).read()) + 1 if os.path.exists(path) else 1
    open(path, "w").write(str(count))
    return count


if command == "ps":
    if args[-1] in os.environ.get("FAKE_RUNNING", "").split():
        print("0123456789ab")
    sys.exit(0)

if command == "exec":
    assert args[0] == "-T", args
    service, rest = args[1], args[2:]
    if service == "wildbox-redis":
        password = sys.stdin.readline().rstrip("\n")
        open(os.path.join(state, "redis_stdin"), "w").write(password)
        sys.stdout.write(os.environ.get("FAKE_REDIS_OUTPUT", "REDIS0011-fake"))
        sys.exit(int(os.environ.get("FAKE_REDIS_RC", "0")))

    # sh -c SCRIPT sh TOOL ARGS...
    assert rest[:2] == ["sh", "-c"] and rest[3] == "sh", rest
    tool, tool_args = rest[4], rest[5:]
    database = option("-d", tool_args)
    if tool == "pg_dump":
        if database in os.environ.get("FAKE_FAIL_DUMP", "").split():
            sys.stderr.write("pg_dump: error: stub failure\n")
            sys.exit(1)
        sys.stdout.write("PGDMP-fake-archive-of-" + database)
    elif tool == "pg_restore":
        data = sys.stdin.read()
        if "--list" in tool_args:
            print("; Archive created by the stub")
            print("1; 1259 16385 TABLE public widgets owner")
        else:
            open(os.path.join(state, "restored_" + database), "w").write(data)
    elif tool == "psql":
        sql = option("-c", tool_args)
        if "query_to_xml" in sql:
            base = os.path.join(os.environ["FAKE_COUNTS"], database)
            nth = base + "." + str(counted(database))
            sys.stdout.write(open(nth if os.path.exists(nth) else base).read())
        elif "FROM pg_database" in sql:
            pass
        elif "information_schema.tables" in sql:
            print(2)
    sys.exit(0)

sys.exit(0)
'''


class Harness:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.state = tmp_path / "state"
        self.counts = tmp_path / "counts"
        self.backups = tmp_path / "backups"
        self.scratch = tmp_path / "tmp"
        for directory in (self.bin, self.state, self.counts, self.scratch):
            directory.mkdir()
        self.env_file = tmp_path / "stack.env"
        self.env_file.write_text(
            f"POSTGRES_PASSWORD={PG_PASSWORD}\nREDIS_PASSWORD={REDIS_PASSWORD}\n"
        )

    def stub_docker(self):
        _executable(self.bin / "docker", FAKE_DOCKER)

    def run(self, script, *args, path=None, **overrides):
        env = {
            "PATH": path or f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "TMPDIR": str(self.scratch),
            "ENV_FILE": str(self.env_file),
            "BACKUP_DIR": str(self.backups),
            "FAKE_STATE": str(self.state),
            "FAKE_COUNTS": str(self.counts),
            "FAKE_RUNNING": "postgres wildbox-redis",
        }
        for name, value in overrides.items():
            if value is None:
                env.pop(name, None)
            else:
                env[name] = value
        # Not the repository: nothing here may resolve a relative .env.
        return subprocess.run(
            ["bash", str(script), *args],
            env=env,
            cwd=self.tmp,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def docker_log(self):
        log = self.state / "docker.log"
        return log.read_text() if log.exists() else ""

    def kept(self):
        if not self.backups.exists():
            return []
        return sorted(p.name for p in self.backups.iterdir())


@pytest.fixture
def harness(tmp_path):
    h = Harness(tmp_path)
    h.stub_docker()
    return h


def test_compose_mode_dumps_three_databases_and_redis_through_the_containers(
    harness,
):
    result = harness.run(BACKUP)
    assert result.returncode == 0, result.stdout + result.stderr

    names = harness.kept()
    assert len(names) == 4, names
    for db in DATABASES:
        assert any(n.startswith(f"{db}_") and n.endswith(".sql.gz") for n in names)
    assert any(n.startswith("redis_") and n.endswith(".rdb.gz") for n in names)

    log = harness.docker_log()
    for db in DATABASES:
        assert f"sh pg_dump -d {db} --format=custom" in log
    # The env file named by the operator is the one Compose reads.
    assert f"compose --env-file {harness.env_file} exec -T postgres" in log
    assert "exec -T wildbox-redis" in log
    assert "Mode:       compose" in result.stdout


def test_no_password_reaches_an_argument_list_or_the_output(harness):
    result = harness.run(BACKUP)
    assert result.returncode == 0, result.stderr
    _assert_no_secret(result.stdout, result.stderr, harness.docker_log())
    # Redis gets its password, over stdin.
    assert (harness.state / "redis_stdin").read_text() == REDIS_PASSWORD


def test_the_redis_password_can_come_from_the_environment(harness):
    harness.env_file.write_text("")
    result = harness.run(BACKUP, REDIS_PASSWORD="from-the-environment")
    assert result.returncode == 0, result.stderr
    assert (harness.state / "redis_stdin").read_text() == "from-the-environment"
    assert "from-the-environment" not in harness.docker_log()


def test_archives_are_private_and_no_temporary_file_is_left(harness):
    result = harness.run(BACKUP)
    assert result.returncode == 0, result.stderr
    assert _mode(harness.backups) == 0o700
    for path in harness.backups.iterdir():
        assert _mode(path) == 0o600, path.name
    # No .pgpass, no partial file, no log: nothing outside the four archives.
    assert list(harness.scratch.iterdir()) == []
    assert not [n for n in harness.kept() if n.startswith(".")]


@pytest.mark.parametrize("failing", ["identity", "guardian"])
def test_a_failed_database_fails_the_run_and_keeps_nothing(harness, failing):
    result = harness.run(BACKUP, FAKE_FAIL_DUMP=failing)
    assert result.returncode != 0
    assert "BACKUP FAILED" in result.stderr
    assert "Backup complete" not in result.stdout
    assert harness.kept() == []


def test_a_redis_failure_fails_the_run_and_keeps_nothing(harness):
    """An error where the snapshot should be, behind a zero exit status."""
    result = harness.run(BACKUP, FAKE_REDIS_OUTPUT="NOAUTH Authentication required")
    assert result.returncode != 0
    assert "Redis did not return an RDB snapshot" in result.stderr
    assert "BACKUP FAILED" in result.stderr
    assert harness.kept() == []


def test_a_missing_redis_password_is_an_error_not_a_skip(harness):
    harness.env_file.write_text(f"POSTGRES_PASSWORD={PG_PASSWORD}\n")
    result = harness.run(BACKUP)
    assert result.returncode != 0
    assert "no Redis password" in result.stderr
    assert harness.kept() == []


def test_redis_is_left_out_only_when_asked_and_it_says_so(harness):
    result = harness.run(BACKUP, SKIP_REDIS="true")
    assert result.returncode == 0, result.stderr
    assert "SKIPPED (SKIP_REDIS=true)" in result.stdout
    assert "NOT in this backup" in result.stdout
    assert "Redis skipped" in result.stdout
    assert len(harness.kept()) == 3
    assert "wildbox-redis" not in harness.docker_log()


@pytest.mark.parametrize("stopped", ["postgres", "wildbox-redis"])
def test_a_stopped_service_is_refused(harness, stopped):
    running = " ".join(s for s in ("postgres", "wildbox-redis") if s != stopped)
    result = harness.run(BACKUP, FAKE_RUNNING=running)
    assert result.returncode != 0
    assert f"the '{stopped}' service is not running" in result.stderr
    assert harness.kept() == []


def test_retention_removes_only_old_backups_and_only_after_success(harness):
    harness.backups.mkdir()
    old_archive = harness.backups / "identity_20200101_000000.sql.gz"
    old_redis = harness.backups / "redis_20200101_000000.rdb.gz"
    unrelated = harness.backups / "notes.sql.gz"
    for path in (old_archive, old_redis, unrelated):
        path.write_text("old")
        os.utime(path, (0, 0))

    failed = harness.run(BACKUP, FAKE_FAIL_DUMP="data")
    assert failed.returncode != 0
    assert old_archive.exists() and old_redis.exists()

    result = harness.run(BACKUP)
    assert result.returncode == 0, result.stderr
    assert not old_archive.exists()
    assert not old_redis.exists()
    assert unrelated.exists()


def test_the_databases_option_takes_both_spellings(harness):
    for args in (["--databases", "identity,data"], ["--databases=identity,data"]):
        result = harness.run(BACKUP, *args, SKIP_REDIS="true")
        assert result.returncode == 0, result.stderr
        assert "PostgreSQL: identity data\n" in result.stdout
    assert "pg_dump -d guardian" not in harness.docker_log()


def test_an_unknown_argument_is_refused(harness):
    result = harness.run(BACKUP, "--database", "identity")
    assert result.returncode == 2
    assert harness.docker_log() == ""


def test_a_database_name_cannot_carry_sql_or_a_path(harness):
    result = harness.run(BACKUP, "--databases", 'identity";DROP DATABASE x;--')
    assert result.returncode != 0
    assert "not a database name" in result.stderr
    assert harness.docker_log() == ""


FAKE_GPG = """#!/usr/bin/env bash
# Stub gpg --encrypt: copies the input to --output.
out=""
while [ $# -gt 0 ]; do
  [ "$1" = "--output" ] && out="$2"
  last="$1"
  shift
done
cp "$last" "$out"
"""

FAKE_AWS = """#!/usr/bin/env bash
echo "$*" >> "$FAKE_STATE/aws.log"
exit "${FAKE_AWS_RC:-0}"
"""


def test_encryption_and_upload_cover_redis_too(harness):
    _executable(harness.bin / "gpg", FAKE_GPG)
    _executable(harness.bin / "aws", FAKE_AWS)
    result = harness.run(
        BACKUP, "--upload-s3", GPG_RECIPIENT="ops@example.com", S3_BUCKET="bucket"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    names = harness.kept()
    # Only the encrypted files remain.
    assert len(names) == 4 and all(n.endswith(".gz.gpg") for n in names), names
    uploads = (harness.state / "aws.log").read_text().splitlines()
    assert len(uploads) == 4
    assert any("s3://bucket/redis-backups/redis_" in line for line in uploads)
    assert any("s3://bucket/postgres-backups/guardian/" in line for line in uploads)


def test_an_upload_without_a_bucket_is_refused_before_anything_runs(harness):
    _executable(harness.bin / "aws", FAKE_AWS)
    result = harness.run(BACKUP, "--upload-s3")
    assert result.returncode != 0
    assert "--upload-s3 needs S3_BUCKET" in result.stderr
    assert harness.docker_log() == ""


def test_a_failed_upload_fails_the_run_but_keeps_the_local_backup(harness):
    _executable(harness.bin / "aws", FAKE_AWS)
    result = harness.run(BACKUP, "--upload-s3", S3_BUCKET="bucket", FAKE_AWS_RC="1")
    assert result.returncode != 0
    assert "The local backup is complete" in result.stderr
    assert len(harness.kept()) == 4


# --- host mode --------------------------------------------------------------

FAKE_CLIENT = r"""#!/usr/bin/env bash
# Stub PostgreSQL / Redis client: logs argv and which secrets it was given
# through the environment, never their values.
tool=$(basename "$0")
{
  printf '%s %s' "$tool" "$*"
  [ -n "${PGPASSWORD:-}" ] && printf ' [PGPASSWORD]'
  [ -n "${REDISCLI_AUTH:-}" ] && printf ' [REDISCLI_AUTH]'
  [ -n "${PGPASSFILE:-}" ] && printf ' [PGPASSFILE]'
  printf '\n'
} >> "$FAKE_STATE/clients.log"
case "$tool" in
  pg_dump) printf 'PGDMP-fake-archive' ;;
  pg_restore) cat >/dev/null; echo "1; 1259 16385 TABLE public widgets owner" ;;
  redis-cli)
    while [ $# -gt 0 ]; do
      if [ "$1" = "--rdb" ]; then printf 'REDIS0011-fake' > "$2"; fi
      shift
    done ;;
esac
exit 0
"""

# What the backup script runs besides the database clients. PATH is this
# directory alone, so the test decides which client tools exist: a CI runner
# has a real pg_dump in /usr/bin, and a workstation may have redis-cli.
SYSTEM_TOOLS = (
    "bash basename cat chmod cut date dirname du env find grep gzip head "
    "mkdir mv rm sed sort tail tr wc"
).split()


@pytest.fixture
def host(tmp_path):
    h = Harness(tmp_path)
    for tool in ("pg_dump", "pg_restore", "psql", "redis-cli"):
        _executable(h.bin / tool, FAKE_CLIENT)
    for tool in SYSTEM_TOOLS:
        (h.bin / tool).symlink_to(shutil.which(tool))
    h.path = str(h.bin)
    return h


def _host_env(**extra):
    env = {
        "POSTGRES_HOST": "db.example.internal",
        "POSTGRES_PASSWORD": PG_PASSWORD,
        "REDIS_PASSWORD": REDIS_PASSWORD,
        "ENV_FILE": None,
    }
    env.update(extra)
    return env


def test_host_mode_connects_directly_without_a_password_file(host):
    result = host.run(BACKUP, path=host.path, **_host_env())
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Mode:       host (db.example.internal:5432)" in result.stdout
    assert len(host.kept()) == 4

    log = (host.state / "clients.log").read_text()
    _assert_no_secret(log, result.stdout, result.stderr)
    assert "pg_dump -h db.example.internal -p 5432 -U postgres -w -d identity" in log
    # The password is in the child's environment; no .pgpass is written.
    assert "[PGPASSWORD]" in log and "[PGPASSFILE]" not in log
    assert "[REDISCLI_AUTH]" in log
    assert list(host.scratch.iterdir()) == []


def test_setting_postgres_host_selects_host_mode_and_docker_is_not_needed(host):
    result = host.run(BACKUP, path=host.path, **_host_env())
    assert result.returncode == 0, result.stderr
    assert not (host.state / "docker.log").exists()


def test_host_mode_without_redis_cli_fails_instead_of_skipping_redis(host):
    """#681: this printed a warning, skipped Redis and exited 0."""
    (host.bin / "redis-cli").unlink()
    result = host.run(BACKUP, path=host.path, **_host_env())
    assert result.returncode != 0
    assert "needs redis-cli" in result.stderr
    assert host.kept() == []


def test_host_mode_without_a_redis_password_fails_instead_of_skipping(host):
    result = host.run(BACKUP, path=host.path, **_host_env(REDIS_PASSWORD=None))
    assert result.returncode != 0
    assert "no Redis password" in result.stderr
    assert host.kept() == []


def test_host_mode_states_what_it_needs(host):
    (host.bin / "pg_dump").unlink()
    result = host.run(BACKUP, path=host.path, **_host_env())
    assert result.returncode != 0
    assert "host mode needs pg_dump on PATH" in result.stderr

    result = host.run(
        BACKUP, path=host.path, **_host_env(POSTGRES_PASSWORD=None, BACKUP_MODE="host")
    )
    assert result.returncode != 0
    assert "host mode needs POSTGRES_PASSWORD" in result.stderr


def test_the_backup_profile_container_uses_host_mode():
    """It is on the Compose network with the client tools and has no docker."""
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())
    environment = compose["services"]["backup"]["environment"]
    assert "BACKUP_MODE=host" in environment
    assert "POSTGRES_HOST=wildbox-postgres" in environment


# --- the drill's comparison -------------------------------------------------


def _counts(harness, name, **tables):
    (harness.counts / name).write_text(
        "".join(f"public.{t}|{n}\n" for t, n in sorted(tables.items()))
    )


def _drill(harness, **overrides):
    return harness.run(DRILL, DATABASES="identity", **overrides)


def test_the_drill_passes_when_the_restored_counts_match(harness):
    _counts(harness, "identity", users=12, teams=3)
    _counts(harness, "identity_restore_drill", users=12, teams=3)
    result = _drill(harness)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "identity: OK (2 tables, 15 rows" in result.stdout
    assert "Restore drill PASSED" in result.stdout


def test_the_drill_fails_when_rows_are_missing_from_the_restore(harness):
    _counts(harness, "identity", users=12, teams=3)
    _counts(harness, "identity_restore_drill", users=0, teams=3)
    result = _drill(harness)
    assert result.returncode == 1
    assert "public.users: restored 0 rows, source had 12" in result.stderr
    assert "Restore drill FAILED" in result.stderr


def test_the_drill_fails_when_a_table_is_missing_from_the_restore(harness):
    _counts(harness, "identity", users=12, teams=3)
    _counts(harness, "identity_restore_drill", teams=3)
    result = _drill(harness)
    assert result.returncode == 1
    assert "missing from the restore: public.users" in result.stderr


def test_the_drill_fails_when_the_restore_is_empty(harness):
    _counts(harness, "identity", users=12)
    (harness.counts / "identity_restore_drill").write_text("")
    result = _drill(harness)
    assert result.returncode == 1
    assert "no tables in the restored database" in result.stderr


def test_the_drill_tolerates_rows_written_while_it_ran(harness):
    """Before 12, after 14: a snapshot holding 13 is a correct restore."""
    _counts(harness, "identity.1", users=12)
    _counts(harness, "identity.2", users=14)
    _counts(harness, "identity_restore_drill", users=13)
    result = _drill(harness)
    assert result.returncode == 0, result.stderr
    assert "1 table(s) changed during the drill" in result.stdout

    for name in ("calls_identity", "calls_identity_restore_drill"):
        (harness.state / name).unlink()
    _counts(harness, "identity_restore_drill", users=11)
    assert _drill(harness).returncode == 1


def test_the_drill_only_creates_and_drops_scratch_databases(harness):
    _counts(harness, "identity", users=12)
    _counts(harness, "identity_restore_drill", users=12)
    result = _drill(harness)
    assert result.returncode == 0, result.stderr
    statements = [
        line for line in harness.docker_log().splitlines() if " DATABASE " in line
    ]
    assert statements, "the drill never created its scratch database"
    for line in statements:
        assert '"identity_restore_drill"' in line, line
    # The restore went into the scratch database, not the live one.
    assert (harness.state / "restored_identity_restore_drill").exists()
    assert not (harness.state / "restored_identity").exists()
    # The drill's archives are gone with its private directory.
    assert list(harness.scratch.iterdir()) == []
    assert harness.kept() == []


def test_the_drill_fails_when_the_backup_fails(harness):
    _counts(harness, "identity", users=12)
    result = _drill(harness, FAKE_FAIL_DUMP="identity")
    assert result.returncode == 1
    assert "the backup did not complete" in result.stderr
    assert not (harness.state / "restored_identity_restore_drill").exists()


def test_redis_restore_refuses_a_running_redis(harness):
    harness.backups.mkdir()
    (harness.backups / "redis_20260101_000000.rdb.gz").write_bytes(b"")
    result = harness.run(RESTORE_REDIS, "--latest")
    assert result.returncode != 0
    assert "service is running" in result.stderr
    assert " run " not in harness.docker_log()


# --- a real PostgreSQL and Redis --------------------------------------------

REAL_COMPOSE = """\
services:
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?required}
      - POSTGRES_DB=identity
    volumes:
      - %(init_sql)s:/docker-entrypoint-initdb.d/10-init-databases.sql:ro
    tmpfs:
      - /var/lib/postgresql/data
    healthcheck:
      # Over TCP: the image's first-run server listens on the socket only.
      test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U $${POSTGRES_USER} -d guardian"]
      interval: 1s
      timeout: 5s
      retries: 60
  wildbox-redis:
    image: redis:7-alpine
    command: >-
      redis-server --appendonly yes --maxmemory-policy noeviction
      --databases 16 --requirepass ${REDIS_PASSWORD:?required}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep -q -e PONG -e NOAUTH"]
      interval: 1s
      timeout: 5s
      retries: 60
volumes:
  redis_data:
"""


def _docker_available():
    if not shutil.which("docker"):
        return False
    probe = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, timeout=30
    )
    if probe.returncode != 0:
        return False
    return (
        subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode
        == 0
    )


class Stack:
    """A throwaway PostgreSQL and Redis under this test's own project name."""

    def __init__(self, root):
        self.root = root
        self.project = f"wbtest681-{uuid.uuid4().hex[:8]}"
        self.compose_file = root / "compose.yml"
        self.compose_file.write_text(
            REAL_COMPOSE % {"init_sql": REPO_ROOT / "scripts" / "init-databases.sql"}
        )
        self.pg_password = f"pg-{uuid.uuid4().hex}"
        self.redis_password = f"redis-{uuid.uuid4().hex}"
        self.env_file = root / "stack.env"
        # Not the image's default user: the scripts must use the container's.
        self.env_file.write_text(
            "POSTGRES_USER=wbadmin\n"
            f"POSTGRES_PASSWORD={self.pg_password}\n"
            f"REDIS_PASSWORD={self.redis_password}\n"
        )
        self.env_file.chmod(0o600)
        self.scratch = root / "tmp"
        self.scratch.mkdir()

    def env(self, **extra):
        env = {
            "PATH": os.environ["PATH"],
            "HOME": os.environ.get("HOME", str(self.root)),
            "TMPDIR": str(self.scratch),
            "COMPOSE_FILE": str(self.compose_file),
            "COMPOSE_PROJECT_NAME": self.project,
            "ENV_FILE": str(self.env_file),
        }
        for name in ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT"):
            if name in os.environ:
                env[name] = os.environ[name]
        env.update({k: v for k, v in extra.items() if v is not None})
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

    def script(self, script, *args, **extra):
        return subprocess.run(
            ["bash", str(script), *args],
            env=self.env(**extra),
            capture_output=True,
            text=True,
            timeout=300,
        )

    def psql(self, database, sql):
        return self.compose(
            "exec",
            "-T",
            "postgres",
            "sh",
            "-c",
            'psql -U "$POSTGRES_USER" -d "$1" -v ON_ERROR_STOP=1 -X -q -tA -c "$2"',
            "sh",
            database,
            sql,
        ).stdout.strip()

    def redis(self, *args):
        return self.compose(
            "exec",
            "-T",
            "wildbox-redis",
            "sh",
            "-c",
            'IFS= read -r REDISCLI_AUTH; export REDISCLI_AUTH; redis-cli "$@"',
            "sh",
            *args,
            stdin=self.redis_password + "\n",
        ).stdout.strip()

    def databases(self):
        return sorted(
            self.psql(
                "postgres", "SELECT datname FROM pg_database WHERE NOT datistemplate"
            ).split()
        )

    def no_secret_in(self, *texts):
        for text in texts:
            assert self.pg_password not in text
            assert self.redis_password not in text


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    if not _docker_available():
        if os.environ.get("WILDBOX_REQUIRE_DOCKER_TESTS") == "1":
            pytest.fail("docker is required for these tests and is not available")
        pytest.skip("docker is not available")
    s = Stack(tmp_path_factory.mktemp("stack681"))
    try:
        s.compose("up", "-d", "--wait")
        rows = 10
        for db in DATABASES:
            s.psql(
                db,
                "CREATE TABLE widgets (id serial PRIMARY KEY, name text NOT NULL);"
                "CREATE TABLE empty_table (id int);"
                "INSERT INTO widgets (name) "
                f"SELECT md5(g::text) FROM generate_series(1, {rows}) g",
            )
            rows *= 3
        s.psql("guardian", "CREATE EXTENSION pg_trgm")
        s.redis("SET", "cspm:scan:1", "done")
        s.redis("-n", "3", "SET", "other:database", "yes")
        yield s
    finally:
        s.compose("down", "-v", "--remove-orphans", check=False)


def test_real_backup_writes_restorable_archives_and_a_redis_snapshot(stack, tmp_path):
    backups = tmp_path / "backups"
    result = stack.script(BACKUP, BACKUP_DIR=str(backups))
    assert result.returncode == 0, result.stdout + result.stderr
    stack.no_secret_in(result.stdout, result.stderr)

    names = sorted(p.name for p in backups.iterdir())
    assert len(names) == 4, names
    assert _mode(backups) == 0o700
    assert all(_mode(p) == 0o600 for p in backups.iterdir())
    assert list(stack.scratch.iterdir()) == []

    # The archives load: restore them next to the live databases and count.
    restored = stack.script(
        RESTORE, "--latest", "--into-suffix", "_copy", BACKUP_DIR=str(backups)
    )
    assert restored.returncode == 0, restored.stdout + restored.stderr
    try:
        assert stack.psql("identity_copy", "SELECT count(*) FROM widgets") == "10"
        assert stack.psql("data_copy", "SELECT count(*) FROM widgets") == "30"
        assert stack.psql("guardian_copy", "SELECT count(*) FROM widgets") == "90"
        assert (
            stack.psql(
                "guardian_copy",
                "SELECT count(*) FROM pg_extension WHERE extname = 'pg_trgm'",
            )
            == "1"
        )
    finally:
        for db in DATABASES:
            stack.psql("postgres", f'DROP DATABASE IF EXISTS "{db}_copy" WITH (FORCE)')


def test_real_drill_passes_and_leaves_the_live_databases_alone(stack):
    before = stack.databases()
    result = stack.script(DRILL)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "identity: OK (2 tables, 10 rows" in result.stdout
    assert "data: OK (2 tables, 30 rows" in result.stdout
    assert "guardian: OK (2 tables, 90 rows" in result.stdout
    assert "Restore drill PASSED" in result.stdout
    stack.no_secret_in(result.stdout, result.stderr)

    assert stack.databases() == before
    assert stack.psql("guardian", "SELECT count(*) FROM widgets") == "90"
    # The archives the drill took are gone with its private directory.
    assert list(stack.scratch.iterdir()) == []


def test_real_drill_replaces_a_stale_scratch_database(stack):
    """One left by --keep must not be compared in place of this restore."""
    stack.psql("postgres", 'CREATE DATABASE "identity_restore_drill"')
    stack.psql("identity_restore_drill", "CREATE TABLE leftover (id int)")
    result = stack.script(DRILL, DATABASES="identity")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "identity_restore_drill" not in stack.databases()


def test_real_backup_of_a_missing_database_fails_and_keeps_nothing(stack, tmp_path):
    backups = tmp_path / "backups"
    result = stack.script(
        BACKUP, "--databases", "identity,no_such_database", BACKUP_DIR=str(backups)
    )
    assert result.returncode != 0
    assert "BACKUP FAILED" in result.stderr
    assert list(backups.iterdir()) == []


def test_real_backup_with_a_wrong_redis_password_fails_and_keeps_nothing(
    stack, tmp_path
):
    backups = tmp_path / "backups"
    result = stack.script(
        BACKUP, BACKUP_DIR=str(backups), REDIS_PASSWORD="not-the-password"
    )
    assert result.returncode != 0
    assert "Redis did not return an RDB snapshot" in result.stderr
    assert list(backups.iterdir()) == []


def test_real_redis_snapshot_can_be_restored(stack, tmp_path):
    backups = tmp_path / "backups"
    result = stack.script(BACKUP, BACKUP_DIR=str(backups))
    assert result.returncode == 0, result.stdout + result.stderr

    # Diverge from the backup, so the restore is observable.
    stack.redis("DEL", "cspm:scan:1")
    stack.redis("SET", "written:after:backup", "yes")

    refused = stack.script(RESTORE_REDIS, "--latest", BACKUP_DIR=str(backups))
    assert refused.returncode != 0
    assert "service is running" in refused.stderr

    stack.compose("stop", "wildbox-redis")
    try:
        restored = stack.script(RESTORE_REDIS, "--latest", BACKUP_DIR=str(backups))
        assert restored.returncode == 0, restored.stdout + restored.stderr
        stack.no_secret_in(restored.stdout, restored.stderr)
    finally:
        stack.compose("up", "-d", "--wait", "wildbox-redis")

    assert stack.redis("GET", "cspm:scan:1") == "done"
    assert stack.redis("-n", "3", "GET", "other:database") == "yes"
    assert stack.redis("EXISTS", "written:after:backup") == "0"
    # Still append-only, and the restored data survives a restart.
    assert "yes" in stack.redis("CONFIG", "GET", "appendonly")
    stack.compose("restart", "wildbox-redis")
    stack.compose("up", "-d", "--wait", "wildbox-redis")
    assert stack.redis("GET", "cspm:scan:1") == "done"
