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

The drill compares a restore with the source as one snapshot saw it (#723):
it counts inside a transaction whose snapshot the backup is dumped from. The
stub tests check that plumbing; the real ones write to the database between
the drill's own steps, where the old before-and-after comparison failed a
correct restore and passed a lossy one.

No test reads a real .env: every run gets ENV_FILE, COMPOSE_FILE and
BACKUP_DIR in a temporary directory, and the passwords are made up here.
"""

import gzip
import os
import re
import shutil
import signal
import stat
import subprocess
import time
import uuid
import zlib
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
import time
import zlib

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


def snapshot_id(database):
    """What pg_export_snapshot() returns in the stub: one per database."""
    return "%08X-0000001B-1" % zlib.crc32(database.encode())


def session(database):
    """psql fed on stdin: it answers as it reads and stays until stdin ends.

    That is the drill's snapshot session. Its transaction, and so the
    snapshot it exported, lasts as long as this process.
    """
    ended = os.path.join(state, "session_" + database)
    if os.path.exists(ended):
        os.remove(ended)
    dumped = os.path.join(state, "dumped_" + database)
    if os.path.exists(dumped):
        os.remove(dumped)
    if database in os.environ.get("FAKE_FAIL_SESSION", "").split():
        sys.stderr.write("psql: error: stub failure\n")
        sys.exit(2)
    statement = ""
    for line in sys.stdin:
        statement += line
        if not line.rstrip().endswith(";"):
            continue
        if "pg_export_snapshot" in statement:
            print("snapshot:" + snapshot_id(database), flush=True)
        elif "query_to_xml" in statement:
            counts = os.path.join(os.environ["FAKE_COUNTS"], database)
            sys.stdout.write(open(counts).read())
            sys.stdout.flush()
        elif "counted:all" in statement:
            print("counted:all", flush=True)
            if database in os.environ.get("FAKE_SESSION_ENDS_EARLY", "").split():
                break
        statement = ""
    # Whether the dump had been taken by the time the snapshot was let go.
    with open(ended, "w") as record:
        record.write("after the dump" if os.path.exists(dumped) else "before the dump")
    sys.exit(0)


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
        for argument in tool_args:
            # As the server does: a snapshot can be adopted only while the
            # transaction that exported it is still running.
            if argument.startswith("--snapshot=") and (
                argument != "--snapshot=" + snapshot_id(database)
                or os.path.exists(os.path.join(state, "session_" + database))
            ):
                sys.stderr.write("pg_dump: error: invalid snapshot identifier\n")
                sys.exit(1)
        if os.environ.get("FAKE_SLOW_DUMP"):
            open(os.path.join(state, "dumping_" + database), "w").close()
            time.sleep(float(os.environ["FAKE_SLOW_DUMP"]))
        open(os.path.join(state, "dumped_" + database), "w").close()
        sys.stdout.write("PGDMP-fake-archive-of-" + database)
    elif tool == "pg_restore":
        data = sys.stdin.read()
        if "--list" in tool_args:
            if data.rsplit("-", 1)[-1] in os.environ.get("FAKE_BAD_ARCHIVE", "").split():
                sys.stderr.write("pg_restore: error: input file does not appear to be a valid archive\n")
                sys.exit(1)
            print("; Archive created by the stub")
            print("1; 1259 16385 TABLE public widgets owner")
        elif database in os.environ.get("FAKE_FAIL_RESTORE", "").split():
            # As --single-transaction leaves it: nothing of this archive.
            sys.stderr.write("pg_restore: error: could not execute query: stub failure\n")
            sys.exit(1)
        else:
            open(os.path.join(state, "restored_" + database), "w").write(data)
            # Whether any snapshot session was still open when the restore
            # began: every session that has ended left a session_* file.
            opened = [n for n in os.listdir(state) if n.startswith("dumped_")]
            closed = [n for n in os.listdir(state) if n.startswith("session_")]
            with open(os.path.join(state, "sessions_at_restore"), "a") as record:
                record.write("held\n" if len(closed) < len(opened) else "released\n")
    elif tool == "psql":
        sql = option("-c", tool_args)
        if sql is None:
            session(database)
        if "query_to_xml" in sql:
            base = os.path.join(os.environ["FAKE_COUNTS"], database)
            nth = base + "." + str(counted(database))
            sys.stdout.write(open(nth if os.path.exists(nth) else base).read())
        elif "FROM pg_database" in sql:
            for name in os.environ.get("FAKE_EXISTING_DATABASES", "").split():
                if "'%s'" % name in sql:
                    print(1)
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

    def env(self, path=None, **overrides):
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
        return env

    def run(self, script, *args, path=None, **overrides):
        # Not the repository: nothing here may resolve a relative .env.
        return subprocess.run(
            ["bash", str(script), *args],
            env=self.env(path=path, **overrides),
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


def _snapshot_id(database):
    """The identifier the stub's pg_export_snapshot() gives a database."""
    return "%08X-0000001B-1" % zlib.crc32(database.encode())


def _session_ended(harness, database):
    """When the drill let a database's snapshot go; None if it never did."""
    ended = harness.state / f"session_{database}"
    return ended.read_text() if ended.exists() else None


def test_the_drill_passes_when_the_restored_counts_match(harness):
    _counts(harness, "identity", users=12, teams=3)
    _counts(harness, "identity_restore_drill", users=12, teams=3)
    result = _drill(harness)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "identity: OK (2 tables, 15 rows" in result.stdout
    assert "Restore drill PASSED" in result.stdout


def test_the_drill_dumps_each_database_from_the_snapshot_it_counted_in(harness):
    """The two sides of the comparison are one snapshot (#723)."""
    for index, db in enumerate(DATABASES):
        _counts(harness, db, widgets=10 + index)
        _counts(harness, f"{db}_restore_drill", widgets=10 + index)
    result = harness.run(DRILL)
    assert result.returncode == 0, result.stdout + result.stderr

    log = harness.docker_log()
    for db in DATABASES:
        # One session per database: psql fed on stdin, which exports the
        # snapshot of a read-only REPEATABLE READ transaction and counts in it.
        assert f"sh psql -d {db} -v ON_ERROR_STOP=1 -X -q -tA\n" in log
        # The dump adopts that snapshot, and the session outlives the dump.
        assert (
            f"sh pg_dump -d {db} --format=custom --compress=9 --no-owner "
            f"--no-privileges --snapshot={_snapshot_id(db)}\n"
        ) in log
        assert _session_ended(harness, db) == "after the dump"
    # And not longer than the backup: the transactions on the live databases
    # were over before the first scratch database was restored.
    at_restore = (harness.state / "sessions_at_restore").read_text().split()
    assert at_restore == ["released"] * len(DATABASES)
    # The live databases were counted once, in the session; every other
    # count is of a scratch database.
    counted = [line for line in log.splitlines() if "query_to_xml" in line]
    assert len(counted) == len(DATABASES)
    assert all("_restore_drill" in line for line in counted)
    script = DRILL.read_text()
    assert "BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY;" in script
    assert "pg_export_snapshot()" in script


@pytest.mark.parametrize("restored", [0, 11, 13], ids=["none", "one-less", "one-more"])
def test_the_drill_fails_on_any_difference_in_a_row_count(harness, restored):
    """No tolerance: one row less is a lossy restore, one more is not ours."""
    _counts(harness, "identity", users=12, teams=3)
    _counts(harness, "identity_restore_drill", users=restored, teams=3)
    result = _drill(harness)
    assert result.returncode == 1
    assert (
        f"public.users: restored {restored} rows, the source had 12 in the snapshot"
        in result.stderr
    )
    assert "Restore drill FAILED" in result.stderr
    assert "PASSED" not in result.stdout


def test_the_drill_fails_when_the_restore_has_a_table_the_source_does_not(harness):
    _counts(harness, "identity", users=12)
    _counts(harness, "identity_restore_drill", users=12, strangers=1)
    result = _drill(harness)
    assert result.returncode == 1
    assert "not in the source: public.strangers" in result.stderr


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


def test_the_drill_fails_when_a_snapshot_cannot_be_opened(harness):
    _counts(harness, "identity", users=12)
    _counts(harness, "identity_restore_drill", users=12)
    result = _drill(harness, FAKE_FAIL_SESSION="identity")
    assert result.returncode == 1
    assert "could not count 'identity' in a snapshot" in result.stderr
    assert "psql: error: stub failure" in result.stderr
    # Nothing was dumped or restored on the strength of a count it lacks.
    assert "pg_dump" not in harness.docker_log()
    assert not (harness.state / "restored_identity_restore_drill").exists()
    assert list(harness.scratch.iterdir()) == []


def test_the_drill_fails_when_a_snapshot_is_gone_before_the_dump(harness):
    """A dump from another snapshot would be compared with these counts."""
    _counts(harness, "identity", users=12)
    _counts(harness, "identity_restore_drill", users=12)
    result = _drill(harness, FAKE_SESSION_ENDS_EARLY="identity")
    assert result.returncode == 1
    assert "invalid snapshot identifier" in result.stderr
    assert "the backup did not complete" in result.stderr
    assert not (harness.state / "restored_identity_restore_drill").exists()


@pytest.mark.parametrize(
    "overrides, status",
    [
        ({}, 0),
        ({"FAKE_FAIL_DUMP": "identity"}, 1),
        ({"FAKE_FAIL_SESSION": "data"}, 1),
    ],
    ids=["passed", "backup-failed", "another-session-failed"],
)
def test_the_drill_has_let_its_snapshots_go_by_the_time_it_returns(
    harness, overrides, status
):
    """A session left behind holds a transaction open on a live database.

    The drill writes to files here, not to pipes: a pipe would make this test
    wait for whatever the drill left running, and hide exactly that.
    """
    for db in ("identity", "data"):
        _counts(harness, db, users=12)
        _counts(harness, f"{db}_restore_drill", users=12)
    with (harness.tmp / "drill.out").open("w") as out:
        drill = subprocess.Popen(
            ["bash", str(DRILL)],
            env=harness.env(DATABASES="identity,data", **overrides),
            cwd=harness.tmp,
            stdout=out,
            stderr=subprocess.STDOUT,
        )
        assert drill.wait(timeout=120) == status, (harness.tmp / "drill.out").read_text()
    # At this moment, not a second later.
    assert _session_ended(harness, "identity") is not None
    if "FAKE_FAIL_SESSION" not in overrides:
        assert _session_ended(harness, "data") is not None
    assert list(harness.scratch.iterdir()) == []


def test_a_killed_drill_does_not_leave_its_snapshot_open(harness):
    """SIGKILL runs no trap: the session has to notice that the drill is gone."""
    _counts(harness, "identity", users=12)
    drill = subprocess.Popen(
        ["bash", str(DRILL)],
        env=harness.env(DATABASES="identity", FAKE_SLOW_DUMP="60"),
        cwd=harness.tmp,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        deadline = time.time() + 60
        while not (harness.state / "dumping_identity").exists():
            assert drill.poll() is None and time.time() < deadline
            time.sleep(0.05)
        # The dump is running, and the snapshot it adopted is still held.
        assert _session_ended(harness, "identity") is None
        drill.kill()
        drill.wait(timeout=30)
        deadline = time.time() + 15
        while _session_ended(harness, "identity") is None:
            assert time.time() < deadline, "the session outlived the drill"
            time.sleep(0.1)
    finally:
        # Whatever the drill started: the stub's slow dump, and its callers.
        try:
            os.killpg(drill.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_the_backup_dumps_a_database_from_the_snapshot_it_is_given(harness):
    result = harness.run(
        BACKUP, "--snapshot", f"data={_snapshot_id('data')}", SKIP_REDIS="true"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    log = harness.docker_log()
    assert (
        "sh pg_dump -d data --format=custom --compress=9 --no-owner "
        f"--no-privileges --snapshot={_snapshot_id('data')}\n"
    ) in log
    # Only that database: the others are dumped as pg_dump sees them.
    assert log.count("--snapshot=") == 1
    assert f"from the exported snapshot {_snapshot_id('data')}" in result.stdout


@pytest.mark.parametrize(
    "value, reason",
    [
        ("identity", "--snapshot takes DATABASE=SNAPSHOT_ID"),
        ("identity=", "--snapshot takes DATABASE=SNAPSHOT_ID"),
        ("identity=0003-1B-1 --schema=public", "--snapshot takes DATABASE=SNAPSHOT_ID"),
        ("identity=0003-1B-1;id", "--snapshot takes DATABASE=SNAPSHOT_ID"),
        ("reporting=00000003-0000001B-1", "not one of the databases to back up"),
    ],
    ids=["no-id", "empty-id", "extra-option", "shell", "another-database"],
)
def test_a_snapshot_option_that_is_not_a_snapshot_is_refused(harness, value, reason):
    """It reaches pg_dump's command line."""
    result = harness.run(BACKUP, "--snapshot", value)
    assert result.returncode != 0
    assert reason in result.stderr
    assert harness.docker_log() == ""
    assert harness.kept() == []


def test_a_backup_from_a_snapshot_that_is_gone_fails_and_keeps_nothing(harness):
    result = harness.run(BACKUP, "--snapshot", "data=00000003-0000001B-1")
    assert result.returncode != 0
    assert "invalid snapshot identifier" in result.stderr
    assert "BACKUP FAILED" in result.stderr
    assert harness.kept() == []


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
    assert _session_ended(harness, "identity") == "before the dump"


def test_redis_restore_refuses_a_running_redis(harness):
    harness.backups.mkdir()
    (harness.backups / "redis_20260101_000000.rdb.gz").write_bytes(b"")
    for flags in ([], ["--replace-redis-data"]):
        result = harness.run(RESTORE_REDIS, "--latest", *flags)
        assert result.returncode != 0
        assert "service is running" in result.stderr
    assert " run " not in harness.docker_log()


# --- restoring over live data is a decision (#723) ---------------------------

STAMP = "20260101_000000"


def _archives(harness, databases=DATABASES, stamp=STAMP):
    """Backup files as the backup script names them, with stub contents."""
    harness.backups.mkdir(exist_ok=True)
    for db in databases:
        with gzip.open(harness.backups / f"{db}_{stamp}.sql.gz", "wb") as archive:
            archive.write(f"PGDMP-fake-archive-of-{db}".encode())
    with gzip.open(harness.backups / f"redis_{stamp}.rdb.gz", "wb") as snapshot:
        snapshot.write(b"REDIS0011-fake")


def _restored(harness):
    """The databases the stub server was asked to restore into."""
    return sorted(p.name[len("restored_") :] for p in harness.state.glob("restored_*"))


@pytest.mark.parametrize(
    "selector",
    [["--timestamp", STAMP], ["--latest"], ["--latest", "--databases", "data"]],
    ids=["timestamp", "latest", "one-database"],
)
def test_restore_over_the_live_databases_is_refused_without_the_flag(
    harness, selector
):
    """It used to be what the script did when --into-suffix was left out."""
    _archives(harness)
    result = harness.run(RESTORE, *selector)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "REFUSING to restore over the live databases" in result.stderr
    assert "Nothing was changed" in result.stderr
    # What would have been overwritten, and from what.
    named = DATABASES if "--databases" not in selector else ("data",)
    for db in DATABASES:
        line = re.search(rf"^    {db} +from {db}_{STAMP}\.sql\.gz$", result.stderr, re.M)
        assert bool(line) == (db in named), db
    for option in ("--overwrite-live-databases", "--into-suffix", "--dry-run"):
        assert option in result.stderr
    # Nothing reached the server, not even a read.
    assert harness.docker_log() == ""
    assert _restored(harness) == []
    assert "Restore complete" not in result.stdout


def test_restore_over_the_live_databases_runs_with_the_flag_and_no_prompt(harness):
    _archives(harness)
    # No terminal and nothing on stdin: a deliberate operator's script.
    result = harness.run(RESTORE, "--timestamp", STAMP, "--overwrite-live-databases")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Target:     the LIVE databases (--overwrite-live-databases)" in result.stdout
    assert _restored(harness) == sorted(DATABASES)
    for db in DATABASES:
        restored = (harness.state / f"restored_{db}").read_text()
        assert restored == f"PGDMP-fake-archive-of-{db}"


def test_the_harmless_targets_need_no_flag(harness):
    _archives(harness)
    result = harness.run(RESTORE, "--latest", "--into-suffix", "_check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _restored(harness) == sorted(f"{db}_check" for db in DATABASES)

    for path in harness.state.glob("restored_*"):
        path.unlink()
    result = harness.run(RESTORE, "--latest", "--dry-run")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "dry run: would restore into 'identity'" in result.stdout
    assert _restored(harness) == []


def test_a_dry_run_with_the_flag_still_writes_nothing(harness):
    _archives(harness)
    result = harness.run(RESTORE, "--latest", "--dry-run", "--overwrite-live-databases")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _restored(harness) == []


def test_the_two_targets_cannot_be_named_together(harness):
    _archives(harness)
    result = harness.run(
        RESTORE, "--latest", "--into-suffix", "_check", "--overwrite-live-databases"
    )
    assert result.returncode == 2
    assert "two different targets" in result.stderr
    assert harness.docker_log() == ""


def test_a_flag_that_is_only_close_is_not_the_flag(harness):
    _archives(harness)
    for near in ("--overwrite", "--overwrite-live", "--force", "--yes", "-y"):
        result = harness.run(RESTORE, "--latest", near)
        assert result.returncode == 2, near
        assert f"Unknown argument: {near}" in result.stderr
    assert harness.docker_log() == ""


def test_a_missing_archive_stops_the_restore_before_any_database_is_touched(harness):
    """It used to overwrite identity and data, then fail on guardian."""
    _archives(harness, databases=("identity", "data"))
    result = harness.run(
        RESTORE, "--timestamp", STAMP, "--overwrite-live-databases"
    )
    assert result.returncode == 1
    assert "no backup found for 'guardian'" in result.stderr
    assert _restored(harness) == []
    assert harness.docker_log() == ""


# --- a failed restore leaves what was there (#740) ----------------------------

LIVE = ("--latest", "--overwrite-live-databases")


def test_each_database_is_restored_in_one_transaction(harness):
    """pg_restore ran statement by statement and carried on after an error."""
    _archives(harness)
    result = harness.run(RESTORE, *LIVE)
    assert result.returncode == 0, result.stdout + result.stderr
    restores = [
        line
        for line in harness.docker_log().splitlines()
        if " sh pg_restore -d " in line
    ]
    assert len(restores) == len(DATABASES)
    for db, line in zip(DATABASES, restores):
        assert line.endswith(
            f"sh pg_restore -d {db} --no-owner --no-privileges --clean --if-exists "
            "--single-transaction"
        ), line


@pytest.mark.parametrize("unreadable", DATABASES)
def test_an_unreadable_archive_stops_the_restore_before_any_database(
    harness, unreadable
):
    """It was found when its turn came, after the databases before it."""
    _archives(harness)
    result = harness.run(RESTORE, *LIVE, FAKE_BAD_ARCHIVE=unreadable)
    assert result.returncode == 1
    assert f"{unreadable}_{STAMP}.sql.gz is not a readable pg_dump" in result.stderr
    assert "No database was touched." in result.stderr
    assert _restored(harness) == []
    log = harness.docker_log()
    assert " sh pg_restore -d " not in log and "CREATE DATABASE" not in log


def test_a_database_that_fails_is_reported_with_what_was_and_was_not_restored(
    harness,
):
    """The three are separate transactions, and the script says where it stopped."""
    _archives(harness)
    result = harness.run(
        RESTORE, *LIVE, FAKE_FAIL_RESTORE="data", FAKE_EXISTING_DATABASES="identity data guardian"
    )
    assert result.returncode == 1
    assert "FAILED: the restore of 'data' was rolled back" in result.stderr
    assert "restored from the backup: identity\n" in result.stderr
    assert "failed, as it was before: data\n" in result.stderr
    assert "not attempted, unchanged: guardian\n" in result.stderr
    assert "run the same command again" in result.stderr
    assert "Restore complete" not in result.stdout
    assert _restored(harness) == ["identity"]
    log = harness.docker_log()
    assert "pg_restore -d guardian" not in log
    # Databases that were there before the run are never dropped.
    assert "DROP DATABASE" not in log


def test_a_database_the_run_created_is_removed_when_its_restore_fails(harness):
    _archives(harness)
    result = harness.run(
        RESTORE, "--latest", "--into-suffix", "_check",
        FAKE_FAIL_RESTORE="data_check", FAKE_EXISTING_DATABASES="identity_check",
    )  # fmt: skip
    assert result.returncode == 1
    assert "failed, as it was before: data_check\n" in result.stderr
    assert "not attempted, unchanged: guardian_check\n" in result.stderr
    drops = [line for line in harness.docker_log().splitlines() if "DROP DATABASE" in line]
    # Only the one this run created, which holds nothing.
    assert len(drops) == 1 and 'DROP DATABASE IF EXISTS "data_check"' in drops[0]


def test_the_first_database_failing_restores_none(harness):
    _archives(harness)
    result = harness.run(RESTORE, *LIVE, FAKE_FAIL_RESTORE="identity")
    assert result.returncode == 1
    assert "restored from the backup: none\n" in result.stderr
    assert "not attempted, unchanged: data guardian\n" in result.stderr
    assert _restored(harness) == []


# --- --latest is one backup run (#740) ----------------------------------------

OLDER, NEWER = "20260101_000000", "20260202_000000"


def _restored_from(result):
    """{database: timestamp of the archive it was restored from}."""
    return dict(
        re.findall(r"^Restoring (\w+) from \1_(\d{8}_\d{6})\.sql\.gz", result.stdout, re.M)
    )


def test_latest_restores_the_newest_run_whatever_the_file_times_say(harness):
    """The timestamp is in the name. A copy from another disk resets mtimes."""
    _archives(harness, stamp=NEWER)
    _archives(harness, stamp=OLDER)
    for path in harness.backups.iterdir():
        # The older run's files are the most recently written ones.
        when = 2_000_000_000 if OLDER in path.name else 1_000_000_000
        os.utime(path, (when, when))
    result = harness.run(RESTORE, "--latest", "--into-suffix", "_check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _restored_from(result) == {db: NEWER for db in DATABASES}

    redis = harness.run(
        RESTORE_REDIS, "--latest", "--replace-redis-data", FAKE_RUNNING="postgres"
    )
    assert redis.returncode == 0, redis.stdout + redis.stderr
    assert f"Snapshot: redis_{NEWER}.rdb.gz" in redis.stdout


@pytest.mark.parametrize(
    "target",
    [["--overwrite-live-databases"], ["--into-suffix", "_check"], ["--dry-run"]],
    ids=["live", "suffix", "dry-run"],
)
def test_latest_refuses_a_newest_run_that_lacks_a_database(harness, target):
    """It restored identity and data from one run and guardian from another."""
    _archives(harness, stamp=OLDER)
    _archives(harness, stamp=NEWER, databases=("identity", "data"))
    result = harness.run(RESTORE, "--latest", *target)
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"REFUSING --latest: the newest backup run, {NEWER}" in result.stderr
    assert re.search(rf"^    identity +identity_{NEWER}$", result.stderr, re.M)
    assert re.search(
        rf"^    guardian +not in this run; its newest archive is from {OLDER}$",
        result.stderr,
        re.M,
    )
    assert "Nothing was changed" in result.stderr
    # The way out is named: the newest run that holds all three.
    assert f"--timestamp {OLDER}   the newest run that holds all of them" in result.stderr
    assert harness.docker_log() == ""
    assert _restored(harness) == []


def test_a_run_is_complete_for_the_databases_that_are_asked_for(harness):
    _archives(harness, stamp=OLDER)
    _archives(harness, stamp=NEWER, databases=("identity", "data"))
    result = harness.run(
        RESTORE, "--latest", "--databases", "identity,data", "--into-suffix", "_check"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _restored_from(result) == {"identity": NEWER, "data": NEWER}


def test_a_run_that_is_not_the_newest_is_restored_by_its_timestamp(harness):
    _archives(harness, stamp=OLDER)
    _archives(harness, stamp=NEWER, databases=("identity", "data"))
    result = harness.run(RESTORE, "--timestamp", OLDER, "--into-suffix", "_check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _restored_from(result) == {db: OLDER for db in DATABASES}
    # And mixing runs is something an operator can still do, by naming them.
    one = harness.run(
        RESTORE, "--timestamp", NEWER, "--databases", "data", "--into-suffix", "_check"
    )
    assert one.returncode == 0, one.stdout + one.stderr
    assert _restored_from(one) == {"data": NEWER}


def test_latest_says_so_when_no_run_holds_every_database(harness):
    _archives(harness, stamp=OLDER, databases=("identity",))
    _archives(harness, stamp=NEWER, databases=("data",))
    result = harness.run(RESTORE, "--latest", "--into-suffix", "_check")
    assert result.returncode == 1
    assert "holds all of them)" in result.stderr and "(no run in" in result.stderr
    assert re.search(r"^    guardian +not in this run, and in no other$", result.stderr, re.M)
    assert _restored(harness) == []


def test_latest_without_any_archive_is_an_error(harness):
    harness.backups.mkdir()
    result = harness.run(RESTORE, "--latest", "--into-suffix", "_check")
    assert result.returncode == 1
    assert "no backup found for identity data guardian" in result.stderr


def test_redis_latest_refuses_a_snapshot_older_than_the_newest_run(harness):
    """The newest run was taken with SKIP_REDIS=true: it has no snapshot."""
    _archives(harness, stamp=OLDER)
    _archives(harness, stamp=NEWER)
    (harness.backups / f"redis_{NEWER}.rdb.gz").unlink()
    result = harness.run(
        RESTORE_REDIS, "--latest", "--replace-redis-data", FAKE_RUNNING="postgres"
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert f"REFUSING --latest: the newest backup run, {NEWER}, holds no Redis" in result.stderr
    assert f"--timestamp {OLDER}" in result.stderr
    assert " run " not in harness.docker_log()

    named = harness.run(
        RESTORE_REDIS, "--timestamp", OLDER, "--replace-redis-data", FAKE_RUNNING="postgres"
    )
    assert named.returncode == 0, named.stdout + named.stderr
    assert f"Snapshot: redis_{OLDER}.rdb.gz" in named.stdout


def test_redis_restore_is_refused_without_the_flag(harness):
    _archives(harness)
    result = harness.run(RESTORE_REDIS, "--latest", FAKE_RUNNING="postgres")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "REFUSING to replace the Redis data" in result.stderr
    assert "data volume of the 'wildbox-redis'" in result.stderr
    assert f"redis_{STAMP}.rdb.gz" in result.stderr
    assert "Nothing was changed" in result.stderr
    assert "--replace-redis-data" in result.stderr
    # No container was started on the volume.
    assert " run " not in harness.docker_log()
    assert "Redis restore complete" not in result.stdout


def test_redis_restore_runs_with_the_flag_and_no_prompt(harness):
    _archives(harness)
    result = harness.run(
        RESTORE_REDIS, "--latest", "--replace-redis-data", FAKE_RUNNING="postgres"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert " run --rm -T --no-deps --entrypoint sh wildbox-redis " in (
        harness.docker_log()
    )
    assert "Redis restore complete" in result.stdout


def test_no_make_target_and_no_other_script_restores_over_live_data():
    """The flags are for an operator's own command line."""
    flags = ("--overwrite-live-databases", "--replace-redis-data")
    callers = [REPO_ROOT / "Makefile", DRILL, BACKUP, REPO_ROOT / "docker-compose.yml"]
    for path in callers:
        # What runs, not what a comment says about it.
        code = "\n".join(
            line
            for line in path.read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        for flag in flags:
            assert flag not in code, f"{path.name} passes {flag}"
    # And no make target runs a restore script at all, with or without one.
    makefile = (REPO_ROOT / "Makefile").read_text()
    recipes = [line for line in makefile.splitlines() if line.startswith("\t")]
    assert not [line for line in recipes if "restore_" in line]
    # The drill names its own target, a scratch suffix that is never empty.
    drill = DRILL.read_text()
    assert 'restore_postgres.sh" --latest --into-suffix "$SUFFIX"' in drill
    assert 'SUFFIX="_restore_drill"' in drill


def test_the_help_texts_end_where_the_headers_end():
    for script, last in (
        (RESTORE, "# scripts/restore_redis.sh."),
        (RESTORE_REDIS, "# GPG_RECIPIENT are decrypted with the local gpg key."),
        (BACKUP, "# written."),
        (DRILL, "# that snapshot means replacing the running Redis data."),
    ):
        result = subprocess.run(
            ["bash", str(script), "--help"], capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0
        assert result.stdout.splitlines()[-1] == last
        assert "set -euo pipefail" not in result.stdout


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
def stack(docker, tmp_path_factory):
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


# The real docker, with writes slipped in around the drill's own steps:
#
#   just before pg_dump of `identity` starts   five rows are inserted
#   SHIM_MODE=shrink, after that pg_dump ends  the five rows are deleted
#   SHIM_MODE=lose, after pg_restore into the scratch database
#                                              one restored row is deleted
#
# Each write leaves a file in SHIM_DIR, so a test can tell that it happened.
WRITING_DOCKER = r"""#!/usr/bin/env python3
import os
import subprocess
import sys

real = os.environ["REAL_DOCKER"]
args = sys.argv[1:]
if "exec" not in args:
    os.execv(real, [real, *args])


def sql(database, statement, done):
    subprocess.run(
        [real, *args[: args.index("exec")], "exec", "-T", "postgres", "sh", "-c",
         'psql -U "$POSTGRES_USER" -d "$1" -v ON_ERROR_STOP=1 -X -q -c "$2"',
         "sh", database, statement],
        check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )
    open(os.path.join(os.environ["SHIM_DIR"], done), "w").close()


mode = os.environ["SHIM_MODE"]
dump = "pg_dump" in args and "identity" in args
restore = (
    "pg_restore" in args and "identity_restore_drill" in args and "--list" not in args
)
if dump:
    sql(
        "identity",
        "INSERT INTO widgets (name) "
        "SELECT 'written during the drill' FROM generate_series(1, 5)",
        "inserted",
    )
status = subprocess.run([real, *args]).returncode
if dump and mode == "shrink":
    sql("identity", "DELETE FROM widgets WHERE name = 'written during the drill'", "deleted")
if restore and mode == "lose" and status == 0:
    sql(
        "identity_restore_drill",
        "DELETE FROM widgets WHERE id = (SELECT min(id) FROM widgets)",
        "lost",
    )
sys.exit(status)
"""


def _drill_with_writes(stack, tmp_path, mode):
    shim = tmp_path / "bin"
    shim.mkdir()
    _executable(shim / "docker", WRITING_DOCKER)
    result = stack.script(
        DRILL,
        PATH=f"{shim}{os.pathsep}{os.environ['PATH']}",
        REAL_DOCKER=shutil.which("docker"),
        SHIM_DIR=str(tmp_path),
        SHIM_MODE=mode,
        DATABASES="identity",
    )
    return result


def test_real_drill_passes_when_a_table_grows_and_shrinks_while_it_runs(
    stack, tmp_path
):
    """#723: 10 rows before, 15 in the dump, 10 after. That failed the drill."""
    count = "SELECT count(*) FROM widgets"
    assert stack.psql("identity", count) == "10"
    try:
        result = _drill_with_writes(stack, tmp_path, "shrink")
        assert (tmp_path / "inserted").exists() and (tmp_path / "deleted").exists()
        assert result.returncode == 0, result.stdout + result.stderr
        # The rows written after the snapshot are on neither side.
        assert "identity: OK (2 tables, 10 rows" in result.stdout
        assert "Restore drill PASSED" in result.stdout
    finally:
        stack.psql("identity", "DELETE FROM widgets WHERE name = 'written during the drill'")
    assert stack.psql("identity", count) == "10"
    assert "identity_restore_drill" not in stack.databases()


def test_real_drill_fails_when_the_restore_loses_a_row_of_a_table_that_grew(
    stack, tmp_path
):
    """#723: 10 rows before and 15 after made 14 restored rows acceptable."""
    count = "SELECT count(*) FROM widgets"
    assert stack.psql("identity", count) == "10"
    try:
        result = _drill_with_writes(stack, tmp_path, "lose")
        assert (tmp_path / "inserted").exists() and (tmp_path / "lost").exists()
        # The source really grew while the drill ran.
        assert stack.psql("identity", count) == "15"
        assert result.returncode == 1, result.stdout + result.stderr
        assert (
            "public.widgets: restored 9 rows, the source had 10 in the snapshot"
            in result.stderr
        )
        assert "Restore drill FAILED" in result.stderr
        assert "PASSED" not in result.stdout
    finally:
        stack.psql("identity", "DELETE FROM widgets WHERE name = 'written during the drill'")
    assert stack.psql("identity", count) == "10"
    assert "identity_restore_drill" not in stack.databases()


def test_real_drill_leaves_no_session_on_the_live_databases(stack):
    result = stack.script(DRILL)
    assert result.returncode == 0, result.stdout + result.stderr
    # Its snapshot sessions are gone: nothing sits in a transaction.
    idle = stack.psql(
        "postgres",
        "SELECT count(*) FROM pg_stat_activity "
        "WHERE state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()",
    )
    assert idle == "0"


def test_real_drill_replaces_a_stale_scratch_database(stack):
    """One left by --keep must not be compared in place of this restore."""
    stack.psql("postgres", 'CREATE DATABASE "identity_restore_drill"')
    stack.psql("identity_restore_drill", "CREATE TABLE leftover (id int)")
    result = stack.script(DRILL, DATABASES="identity")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "identity_restore_drill" not in stack.databases()


def test_real_restore_over_the_live_databases_happens_only_with_the_flag(
    stack, tmp_path
):
    backups = tmp_path / "backups"
    result = stack.script(BACKUP, BACKUP_DIR=str(backups), SKIP_REDIS="true")
    assert result.returncode == 0, result.stdout + result.stderr

    # Written after the backup: what a restore over the live database loses.
    marker = "written after the backup"
    stack.psql("identity", f"INSERT INTO widgets (name) VALUES ('{marker}')")
    count = "SELECT count(*) FROM widgets"
    assert stack.psql("identity", count) == "11"
    try:
        selection = ("--latest", "--databases", "identity")
        refused = stack.script(RESTORE, *selection, BACKUP_DIR=str(backups))
        assert refused.returncode == 2, refused.stdout + refused.stderr
        assert "REFUSING to restore over the live databases" in refused.stderr
        assert re.search(
            r"^    identity +from identity_\d+_\d+\.sql\.gz$", refused.stderr, re.M
        )
        # The live database still holds the row.
        assert stack.psql("identity", count) == "11"

        restored = stack.script(
            RESTORE, *selection, "--overwrite-live-databases", BACKUP_DIR=str(backups)
        )
        assert restored.returncode == 0, restored.stdout + restored.stderr
        stack.no_secret_in(restored.stdout, restored.stderr)
        # As it was when the backup was taken; the other databases untouched.
        assert stack.psql("identity", count) == "10"
        assert stack.psql("data", count) == "30"
    finally:
        stack.psql("identity", f"DELETE FROM widgets WHERE name = '{marker}'")


def test_real_failed_restore_leaves_the_database_as_it_was(stack, tmp_path):
    """#740: a restore that fails partway used to leave a damaged database.

    A view created after the backup depends on a table of `data`, so
    pg_restore --clean cannot drop that table. Statement by statement it had
    already dropped the primary key by then, and went on to load the rows a
    second time.
    """
    backups = tmp_path / "backups"
    result = stack.script(BACKUP, BACKUP_DIR=str(backups), SKIP_REDIS="true")
    assert result.returncode == 0, result.stdout + result.stderr

    marker = "written after the backup"
    count = "SELECT count(*) FROM widgets"
    keys = (
        "SELECT count(*) FROM pg_constraint "
        "WHERE conrelid = 'widgets'::regclass AND contype = 'p'"
    )
    for db in DATABASES:
        stack.psql(db, f"INSERT INTO widgets (name) VALUES ('{marker}')")
    stack.psql("data", "CREATE VIEW widget_names AS SELECT name FROM widgets")
    command = (RESTORE, "--latest", "--overwrite-live-databases")
    try:
        failed = stack.script(*command, BACKUP_DIR=str(backups))
        assert failed.returncode == 1, failed.stdout + failed.stderr
        assert "widget_names" in failed.stderr
        assert "the restore of 'data' was rolled back" in failed.stderr
        assert "restored from the backup: identity\n" in failed.stderr
        assert "failed, as it was before: data\n" in failed.stderr
        assert "not attempted, unchanged: guardian\n" in failed.stderr

        # data: exactly as it was. Its rows, its primary key, the view.
        assert stack.psql("data", count) == "31"
        assert stack.psql("data", keys) == "1"
        assert stack.psql("data", "SELECT count(*) FROM widget_names") == "31"
        # What remains non-atomic: the database before it is restored, the
        # one after it was not reached.
        assert stack.psql("identity", count) == "10"
        assert stack.psql("guardian", count) == "91"

        # With the cause removed, the same command restores all three.
        stack.psql("data", "DROP VIEW widget_names")
        again = stack.script(*command, BACKUP_DIR=str(backups))
        assert again.returncode == 0, again.stdout + again.stderr
        assert [stack.psql(db, count) for db in DATABASES] == ["10", "30", "90"]
        assert stack.psql("data", keys) == "1"
    finally:
        stack.psql("data", "DROP VIEW IF EXISTS widget_names")
        for db in DATABASES:
            stack.psql(db, f"DELETE FROM widgets WHERE name = '{marker}'")


def _damaged_copy(snapshot, stamp):
    """A snapshot that starts like an RDB file and stops halfway."""
    whole = gzip.decompress(snapshot.read_bytes())
    assert whole[:5] == b"REDIS" and len(whole) > 60
    damaged = snapshot.with_name(f"redis_{stamp}.rdb.gz")
    damaged.write_bytes(gzip.compress(whole[: len(whole) // 2]))
    return damaged


def test_real_redis_restore_of_a_damaged_snapshot_leaves_the_data_in_place(
    stack, tmp_path
):
    """#740: the volume was emptied first, so this left an empty Redis."""
    backups = tmp_path / "backups"
    result = stack.script(BACKUP, BACKUP_DIR=str(backups))
    assert result.returncode == 0, result.stdout + result.stderr
    (snapshot,) = backups.glob("redis_*.rdb.gz")
    _damaged_copy(snapshot, "20990101_000000")

    stack.redis("SET", "written:after:backup", "kept")
    stack.compose("stop", "wildbox-redis")
    try:
        failed = stack.script(
            RESTORE_REDIS, "--timestamp", "20990101_000000", "--replace-redis-data",
            BACKUP_DIR=str(backups),
        )  # fmt: skip
        assert failed.returncode != 0, failed.stdout + failed.stderr
        assert "not a complete RDB file" in failed.stderr
        assert "the Redis data is as it was before this restore." in failed.stderr
        assert "Redis restore complete" not in failed.stdout
    finally:
        stack.compose("up", "-d", "--wait", "wildbox-redis")
    # Everything that was there, including what no backup holds.
    assert stack.redis("GET", "cspm:scan:1") == "done"
    assert stack.redis("-n", "3", "GET", "other:database") == "yes"
    assert stack.redis("GET", "written:after:backup") == "kept"
    listing = stack.compose(
        "exec", "-T", "wildbox-redis", "sh", "-c", "ls -A /data"
    ).stdout.split()
    assert ".restore-incoming" not in listing and ".restore-previous" not in listing
    stack.redis("DEL", "written:after:backup")


def test_real_latest_does_not_mix_two_backup_runs(stack, tmp_path):
    """A full run, then one of `identity` alone: --latest used to take
    identity from the second and the other two from the first."""
    backups = tmp_path / "backups"
    full = stack.script(BACKUP, BACKUP_DIR=str(backups), SKIP_REDIS="true")
    assert full.returncode == 0, full.stdout + full.stderr
    (first,) = {p.name.split("_", 1)[1].split(".")[0] for p in backups.iterdir()}
    while True:
        # The next run needs a timestamp of its own, one second later.
        partial = stack.script(
            BACKUP, "--databases", "identity", BACKUP_DIR=str(backups), SKIP_REDIS="true"
        )
        assert partial.returncode == 0, partial.stdout + partial.stderr
        if len(list(backups.glob("identity_*.sql.gz"))) == 2:
            break

    before = stack.databases()
    refused = stack.script(RESTORE, "--latest", "--into-suffix", "_mix", BACKUP_DIR=str(backups))
    assert refused.returncode == 1, refused.stdout + refused.stderr
    assert "REFUSING --latest" in refused.stderr
    assert f"--timestamp {first}   the newest run that holds all of them" in refused.stderr
    assert stack.databases() == before

    # The run it names restores, all three from the same moment.
    named = stack.script(
        RESTORE, "--timestamp", first, "--into-suffix", "_mix", BACKUP_DIR=str(backups)
    )
    try:
        assert named.returncode == 0, named.stdout + named.stderr
        assert stack.psql("guardian_mix", "SELECT count(*) FROM widgets") == "90"
    finally:
        for db in DATABASES:
            stack.psql("postgres", f'DROP DATABASE IF EXISTS "{db}_mix" WITH (FORCE)')


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

    refused = stack.script(
        RESTORE_REDIS, "--latest", "--replace-redis-data", BACKUP_DIR=str(backups)
    )
    assert refused.returncode != 0
    assert "service is running" in refused.stderr

    stack.compose("stop", "wildbox-redis")
    try:
        # Stopped is not yet a decision to replace its data (#723).
        refused = stack.script(RESTORE_REDIS, "--latest", BACKUP_DIR=str(backups))
        assert refused.returncode == 2
        assert "REFUSING to replace the Redis data" in refused.stderr

        restored = stack.script(
            RESTORE_REDIS, "--latest", "--replace-redis-data", BACKUP_DIR=str(backups)
        )
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
