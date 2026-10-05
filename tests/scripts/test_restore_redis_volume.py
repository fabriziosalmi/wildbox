"""A Redis restore that fails leaves the data that was there (#740).

scripts/restore_redis.sh deleted the contents of the Redis data volume and
then loaded the snapshot. A snapshot that did not load left an empty Redis:
scan and run state, queued work, revoked tokens and lockouts gone, for a
restore that restored nothing.

The part that runs on the volume is now scripts/lib/restore_redis_volume.sh.
It loads the snapshot in a scratch directory next to the data, checks what
was loaded, and only then swaps the two. These tests run that file with
`sh`, on a temporary directory in place of /data, with stub Redis tools on
PATH that behave as the real ones were measured to (redis:7-alpine): what
each failure leaves behind, and what a run that dies in the middle of the
swap leaves and how the next run deals with it.

tests/scripts/test_backup_restore.py runs the same file inside a real Redis
container, with a real damaged snapshot.
"""

import os
import shutil
import signal
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VOLUME_SCRIPT = REPO_ROOT / "scripts" / "lib" / "restore_redis_volume.sh"

# One stub, installed under the name of each Redis tool. A snapshot is a text
# that starts with REDIS; words in it say how the tools behave with it:
#   keys=N expired=N   what it holds, and how many of those have expired
#   DAMAGED            redis-check-rdb finds an error
#   CRASH              the server aborts while loading, as on a short read
#   LOSES              the server loads one key less than the file holds
#   SLOW               the server never finishes loading
#   MUTE               the server does not answer PING
#   NOAOF              the server never finishes writing the append-only file
#   BADAOF             redis-check-aof finds an error in what was written
FAKE_REDIS = r"""#!/usr/bin/env python3
import json
import os
import re
import signal
import subprocess
import sys

tool, args = os.path.basename(sys.argv[0]), sys.argv[1:]
state_file = os.path.join(os.environ["FAKE_STATE"], "server.json")
with open(os.path.join(os.environ["FAKE_STATE"], "calls.log"), "a") as log:
    log.write(tool + " " + " ".join(args) + "\n")


def number(name, text):
    found = re.search(name + r"=(\d+)", text)
    return int(found.group(1)) if found else 0


def option(name):
    return args[args.index(name) + 1]


if tool == "redis-check-rdb":
    text = open(args[0], errors="replace").read()
    if not text.startswith("REDIS") or "DAMAGED" in text:
        print("--- RDB ERROR DETECTED ---")
        print("[offset 55] Unexpected EOF reading RDB file")
        sys.exit(1)
    print("[offset 140] \\o/ RDB looks OK! \\o/")
    if "NOCOUNT" not in text:
        print("[info] %d keys read" % number("keys", text))
    print("[info] %d already expired" % number("expired", text))
    sys.exit(0)

if tool == "redis-check-aof":
    written = open(os.path.join(os.path.dirname(args[0]), "appendonly.aof.1.base.rdb")).read()
    sys.exit(1 if "BADAOF" in written else 0)

if tool == "redis-server":
    directory = option("--dir")
    text = open(os.path.join(directory, option("--dbfilename")), errors="replace").read()
    open(option("--logfile"), "w").write("stub server\n")
    if "CRASH" in text:
        # The parent of a daemonized server returns 0; the child wrote its
        # pid and aborted.
        gone = subprocess.Popen(["true"])
        gone.wait()
        open(option("--pidfile"), "w").write(str(gone.pid))
        open(option("--logfile"), "a").write("Short read or OOM loading DB. Unrecoverable error, aborting now.\n")
        sys.exit(0)
    server = subprocess.Popen(["sleep", "300"], start_new_session=True)
    open(option("--pidfile"), "w").write(str(server.pid))
    state = {"dir": directory, "text": text, "pid": server.pid, "aof": False}
    state["pidfile"] = option("--pidfile")
    json.dump(state, open(state_file, "w"))
    sys.exit(0)

assert tool == "redis-cli", tool
# The temporary server has no password: nothing may offer it one.
assert "REDISCLI_AUTH" not in os.environ
command = args[2:]
try:
    state = json.load(open(state_file))
    os.kill(state["pid"], 0)
except (OSError, ValueError):
    print("Could not connect to Redis at %s: Connection refused" % args[1])
    sys.exit(1)
text = state["text"]
keys, expired = number("keys", text), number("expired", text)
loaded = keys - expired - (1 if "LOSES" in text else 0)
if command == ["PING"]:
    print("LOADING Redis is loading the dataset in memory" if "MUTE" in text else "PONG")
elif command == ["INFO", "persistence"]:
    print("# Persistence\r")
    print("loading:%d\r" % (1 if "SLOW" in text else 0))
    print("rdb_last_load_keys_expired:%d\r" % expired)
    print("rdb_last_load_keys_loaded:%d\r" % loaded)
    print("aof_enabled:%d\r" % (1 if state["aof"] else 0))
    print("aof_rewrite_in_progress:0\r")
    print("aof_last_bgrewrite_status:ok\r")
elif command == ["INFO", "keyspace"]:
    print("# Keyspace\r")
    if loaded:
        print("db0:keys=%d,expires=0,avg_ttl=0\r" % loaded)
elif command == ["CONFIG", "SET", "appendonly", "yes"]:
    if "NOAOF" not in text:
        target = os.path.join(state["dir"], "appendonlydir")
        os.mkdir(target)
        manifest = "file appendonly.aof.1.base.rdb seq 1 type b\n"
        open(os.path.join(target, "appendonly.aof.manifest"), "w").write(manifest)
        open(os.path.join(target, "appendonly.aof.1.base.rdb"), "w").write("restored from: " + text)
        state["aof"] = True
        json.dump(state, open(state_file, "w"))
    print("OK")
elif command == ["SHUTDOWN", "NOSAVE"]:
    os.kill(state["pid"], signal.SIGKILL)
    os.remove(state["pidfile"])
else:
    raise SystemExit("unexpected: %r" % command)
"""

# `mv` that does its work and then, on its N-th call, kills the script that
# called it: a run that dies between two steps of the swap, with no trap.
DYING_MV = r"""#!/bin/sh
count_file="$FAKE_STATE/mv_calls"
count=$(($(cat "$count_file" 2>/dev/null || echo 0) + 1))
echo "$count" > "$count_file"
if [ "$count" = "${FAKE_MV_FAILS_AT:-0}" ]; then
  echo "mv: stub failure" >&2
  exit 1
fi
"$REAL_MV" "$@"
if [ "$count" = "${FAKE_MV_KILLS_AT:-0}" ]; then
  kill -9 "$PPID"
fi
"""

GOOD = "REDIS0011 keys=5 expired=0"


class Volume:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.data = tmp_path / "data"
        self.run_dir = tmp_path / "run"
        self.state = tmp_path / "state"
        self.bin = tmp_path / "bin"
        for directory in (self.data, self.run_dir, self.state, self.bin):
            directory.mkdir()
        for tool in ("redis-server", "redis-cli", "redis-check-rdb", "redis-check-aof"):
            self._install(tool, FAKE_REDIS)
        self._install("mv", DYING_MV)

    def _install(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def existing_data(self):
        """What a running stack leaves in the volume."""
        (self.data / "appendonlydir").mkdir()
        (self.data / "appendonlydir" / "appendonly.aof.manifest").write_text(
            "old manifest\n"
        )
        (self.data / "appendonlydir" / "appendonly.aof.7.base.rdb").write_text(
            "the data before\n"
        )
        (self.data / "dump.rdb").write_text("an older dump\n")
        return self.tree()

    def tree(self):
        """{relative path: contents} of everything in the volume."""
        return {
            str(path.relative_to(self.data)): path.read_text()
            for path in sorted(self.data.rglob("*"))
            if path.is_file()
        }

    def restore(self, snapshot, **overrides):
        env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "DATA_DIR": str(self.data),
            "RUN_DIR": str(self.run_dir),
            "WAIT_SECONDS": "3",
            "FAKE_STATE": str(self.state),
            "REAL_MV": shutil.which("mv"),
            # As in a container of the service after #740.
            "REDISCLI_AUTH": "made-up-health-check-password",
        }
        env.update(overrides)
        return subprocess.run(
            ["sh", str(VOLUME_SCRIPT)],
            env=env,
            input=snapshot,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def calls(self):
        log = self.state / "calls.log"
        return log.read_text() if log.exists() else ""

    def server_is_gone(self):
        pidfile = self.run_dir / "restore.pid"
        if not pidfile.exists():
            return True
        try:
            os.kill(int(pidfile.read_text()), 0)
        except OSError:
            return True
        return False

    def restored(self):
        """True when the volume holds what the stub server wrote, and no more."""
        tree = self.tree()
        return set(tree) == {
            "appendonlydir/appendonly.aof.manifest",
            "appendonlydir/appendonly.aof.1.base.rdb",
        } and tree["appendonlydir/appendonly.aof.1.base.rdb"].startswith(
            "restored from: REDIS"
        )


@pytest.fixture
def volume(tmp_path):
    v = Volume(tmp_path)
    yield v
    # A stub server a test left running.
    pidfile = v.run_dir / "restore.pid"
    if pidfile.exists():
        try:
            os.kill(int(pidfile.read_text()), signal.SIGKILL)
        except (OSError, ValueError):
            pass


def test_a_snapshot_is_loaded_checked_and_only_then_put_in_place(volume):
    volume.existing_data()
    result = volume.restore("REDIS0011 keys=5 expired=2")
    assert result.returncode == 0, result.stdout + result.stderr
    assert volume.restored()
    assert (
        "loaded the snapshot: 3 keys in 1 Redis database(s); 2 had expired"
        in result.stdout
    )
    assert volume.server_is_gone()

    calls = volume.calls().splitlines()
    scratch = f"{volume.data}/.restore-incoming"
    # In a scratch directory of the volume, on a socket, with no network port.
    assert calls[0] == f"redis-check-rdb {scratch}/dump.rdb"
    server = next(line for line in calls if line.startswith("redis-server "))
    assert f"--dir {scratch} " in server and "--port 0 " in server
    assert f"--unixsocket {volume.run_dir}/restore.sock" in server
    # What it wrote was read back before anything was swapped.
    assert f"redis-check-aof {scratch}/appendonlydir/appendonly.aof.manifest" in calls


def test_an_empty_volume_is_restored_too(volume):
    result = volume.restore(GOOD)
    assert result.returncode == 0, result.stdout + result.stderr
    assert volume.restored()
    assert "loaded the snapshot: 5 keys in 1 Redis database(s)\n" in result.stdout


@pytest.mark.parametrize(
    "snapshot, reason",
    [
        ("not a snapshot at all", "not a complete RDB file"),
        ("REDIS0011 keys=5 DAMAGED", "not a complete RDB file"),
        ("REDIS0011 keys=5 CRASH", "stopped before it could load the snapshot"),
        ("REDIS0011 keys=5 SLOW", "did not load the snapshot in 3 seconds"),
        ("REDIS0011 keys=5 MUTE", "does not answer PING"),
        ("REDIS0011 keys=5 LOSES", "holds 5 keys, and the temporary Redis loaded 4"),
        ("REDIS0011 keys=5 NOAOF", "did not write the append-only file"),
        ("REDIS0011 keys=5 BADAOF", "does not read back"),
        ("", "not a complete RDB file"),
    ],
    ids=[
        "not-rdb",
        "damaged",
        "server-aborts",
        "never-loads",
        "no-ping",
        "keys-missing",
        "no-aof",
        "bad-aof",
        "empty",
    ],
)
def test_a_snapshot_that_does_not_load_leaves_the_data_that_was_there(
    volume, snapshot, reason
):
    """#740: each of these used to leave an empty Redis."""
    before = volume.existing_data()
    result = volume.restore(snapshot)
    assert result.returncode != 0, result.stdout
    assert reason in result.stderr
    assert "the Redis data is as it was before this restore." in result.stderr
    assert "loaded the snapshot" not in result.stdout
    # Byte for byte, with nothing of the attempt left next to it.
    assert volume.tree() == before
    assert not (volume.data / ".restore-incoming").exists()
    assert not (volume.data / ".restore-previous").exists()
    assert volume.server_is_gone()


def test_a_snapshot_whose_keys_cannot_be_counted_is_still_loaded_and_read_back(volume):
    """redis-check-rdb's exit status is the gate; its count is a cross-check."""
    volume.existing_data()
    result = volume.restore("REDIS0011 keys=5 NOCOUNT")
    assert result.returncode == 0, result.stdout + result.stderr
    assert volume.restored()


def test_a_failed_move_during_the_swap_puts_the_old_data_back(volume):
    before = volume.existing_data()
    # The third move is the new data going into place.
    result = volume.restore(GOOD, FAKE_MV_FAILS_AT="3")
    assert result.returncode != 0
    assert "the previous data is back in place" in result.stderr
    assert volume.tree() == before
    assert not (volume.data / ".restore-previous").exists()
    assert not (volume.data / ".restore-incoming").exists()


@pytest.mark.parametrize("moves", ["1", "2"], ids=["after-the-aof", "after-the-dump"])
def test_a_run_killed_between_the_two_renames_is_undone_by_the_next_run(volume, moves):
    """No trap runs on SIGKILL: the old data is in .restore-previous."""
    before = volume.existing_data()
    killed = volume.restore(GOOD, FAKE_MV_KILLS_AT=moves)
    assert killed.returncode == -signal.SIGKILL
    assert not (volume.data / "appendonlydir").exists()
    assert (volume.data / ".restore-previous" / "appendonlydir").is_dir()

    # The next run, with a snapshot that does not load: all that happens is
    # that the old data goes back where it was.
    (volume.state / "mv_calls").unlink()
    again = volume.restore("not a snapshot at all")
    assert again.returncode != 0
    assert "an earlier restore was interrupted" in again.stdout
    assert "back in place" in again.stdout
    assert volume.tree() == before


def test_a_run_killed_between_the_two_renames_does_not_block_a_good_restore(volume):
    volume.existing_data()
    assert volume.restore(GOOD, FAKE_MV_KILLS_AT="1").returncode == -signal.SIGKILL
    (volume.state / "mv_calls").unlink()
    again = volume.restore(GOOD)
    assert again.returncode == 0, again.stdout + again.stderr
    assert "an earlier restore was interrupted" in again.stdout
    assert volume.restored()


def test_leftovers_of_a_completed_swap_are_removed(volume):
    """Killed while it deleted the old data: the marker says the swap was done."""
    volume.existing_data()
    previous = volume.data / ".restore-previous"
    (previous / "appendonlydir").mkdir(parents=True)
    (previous / "appendonlydir" / "half-deleted").write_text("leftover\n")
    (previous / ".swapped").write_text("")
    before = volume.tree()
    result = volume.restore("not a snapshot at all")
    assert result.returncode != 0
    assert not previous.exists()
    # The data in place was not touched by the clean-up.
    expected = {
        k: v for k, v in before.items() if not k.startswith(".restore-previous")
    }
    assert volume.tree() == expected


def test_old_data_set_aside_next_to_data_in_place_is_not_guessed_at(volume):
    """Killed right after the new data went in, before the marker; or Redis
    was started on the half-swapped volume. Only one of the two is the data
    to keep, and nothing here says which."""
    volume.existing_data()
    previous = volume.data / ".restore-previous"
    (previous / "appendonlydir").mkdir(parents=True)
    (previous / "appendonlydir" / "appendonly.aof.3.base.rdb").write_text("set aside\n")
    before = volume.tree()
    result = volume.restore(GOOD)
    assert result.returncode != 0
    assert "cannot tell which" in result.stderr
    assert str(previous) in result.stderr
    # Both kept, and no server was started.
    assert volume.tree() == before
    assert "redis-server" not in volume.calls()


def test_the_volume_script_is_what_the_restore_runs_in_the_container():
    restore = (REPO_ROOT / "scripts" / "restore_redis.sh").read_text()
    assert (
        '-c "$(cat "$SCRIPT_DIR/lib/restore_redis_volume.sh")" < "$STAGED"' in restore
    )
    # Nothing in the restore itself deletes from the volume any more.
    assert "rm -rf appendonlydir" not in restore
    script = VOLUME_SCRIPT.read_text()
    assert script.index('cat > "$INCOMING/dump.rdb"') < script.index(
        'mkdir "$PREVIOUS"'
    )
