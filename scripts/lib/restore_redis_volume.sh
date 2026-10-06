# shellcheck shell=sh
#
# The part of scripts/restore_redis.sh that runs inside a one-off container
# of the Redis service, on its data volume, with the snapshot on stdin.
# restore_redis.sh hands this file to `sh -c`; it is not run on the host.
#
# The data that is there stays in place until the snapshot has been loaded
# and checked (#740). The restore used to delete it first, so a snapshot that
# did not load left an empty Redis.
#
#   1. The snapshot goes into a scratch directory on the same volume,
#      $DATA_DIR/.restore-incoming, and redis-check-rdb reads it to the end.
#   2. A temporary server (no network port, a Unix socket) loads it there.
#      It has to answer PING, and what it loaded plus what it left out as
#      already expired has to be the number of keys the snapshot holds.
#   3. That server writes the append-only file, which is what the service
#      reads at start, and redis-check-aof reads it back.
#   4. Only then the old data is moved to $DATA_DIR/.restore-previous, the
#      new append-only file is moved into place, and the old data is removed.
#
# A failure in steps 1 to 3 leaves the volume as it was. Step 4 is two
# renames, not one: if the run dies between them, the old data is in
# .restore-previous and the next run puts it back before it does anything
# else. .restore-previous/.swapped marks a swap that completed, so what a
# later run finds can be told apart: old data to put back, or leftovers to
# remove.
#
# The volume needs room for the old data and the new at the same time.
#
# DATA_DIR, RUN_DIR and WAIT_SECONDS exist for the tests.

set -eu

DATA_DIR="${DATA_DIR:-/data}"
RUN_DIR="${RUN_DIR:-/tmp}"
WAIT_SECONDS="${WAIT_SECONDS:-600}"
INCOMING="$DATA_DIR/.restore-incoming"
PREVIOUS="$DATA_DIR/.restore-previous"
SWAPPED="$PREVIOUS/.swapped"
SOCKET="$RUN_DIR/restore.sock"
LOG="$RUN_DIR/restore.log"
PIDFILE="$RUN_DIR/restore.pid"

# The service's containers carry the password of its health check. The
# temporary server has no password, and redis-cli would complain about one.
unset REDISCLI_AUTH

say() { echo "  $*"; }
fail() {
  echo "$*" >&2
  exit 1
}

rcli() { redis-cli -s "$SOCKET" "$@"; }
field() { rcli INFO "$1" 2>/dev/null | tr -d '\r' | sed -n "s/^$2://p"; }

server_alive() {
  [ -s "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

stop_server() {
  server_alive || return 0
  rcli SHUTDOWN NOSAVE >/dev/null 2>&1 || true
  i=0
  while server_alive && [ "$i" -lt 30 ]; do
    i=$((i + 1))
    sleep 1
  done
  ! server_alive || kill -9 "$(cat "$PIDFILE")" 2>/dev/null || true
}

# The old data back where it was, if the swap had begun to move it.
put_previous_back() {
  for item in appendonlydir dump.rdb; do
    if [ -e "$PREVIOUS/$item" ] && [ ! -e "$DATA_DIR/$item" ]; then
      mv "$PREVIOUS/$item" "$DATA_DIR/$item"
    fi
  done
  rmdir "$PREVIOUS" 2>/dev/null || true
}

STAGE=preparing
finish() {
  status=$?
  trap - EXIT
  stop_server
  if [ "$STAGE" = swapping ]; then
    put_previous_back
    echo "the restore failed while the data was being swapped: the previous data is back in place." >&2
  fi
  if [ "$STAGE" != swapped ]; then
    rm -rf "$INCOMING"
    [ "$status" -eq 0 ] || echo "the Redis data is as it was before this restore." >&2
  elif [ "$status" -ne 0 ]; then
    echo "the snapshot is in place, but the data from before it could not be removed: delete $PREVIOUS." >&2
  fi
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- what an interrupted run left behind ---------------------------------------

if [ -d "$PREVIOUS" ]; then
  if [ -e "$SWAPPED" ] || [ ! -e "$PREVIOUS/appendonlydir" ]; then
    # That swap completed, or there was no data to move away: leftovers.
    rm -rf "$PREVIOUS"
  elif [ ! -e "$DATA_DIR/appendonlydir" ]; then
    put_previous_back
    say "an earlier restore was interrupted while it swapped the data: the data from before it is back in place."
  else
    STAGE=refused
    fail "$PREVIOUS holds the Redis data from before an earlier restore that was interrupted, and $DATA_DIR/appendonlydir exists as well. Only one of them is the data to keep, and this script cannot tell which: look at both, then remove $PREVIOUS or move its content back, and restore again."
  fi
fi
rm -rf "$INCOMING"
mkdir "$INCOMING"

# --- 1. the snapshot, in a scratch directory -----------------------------------

STAGE=loading
cat > "$INCOMING/dump.rdb"
if ! checked=$(redis-check-rdb "$INCOMING/dump.rdb" 2>&1); then
  printf '%s\n' "$checked" | tail -n 4 >&2
  fail "the snapshot is not a complete RDB file (redis-check-rdb)."
fi
expected=$(printf '%s\n' "$checked" | sed -n 's/^\[info\] \([0-9][0-9]*\) keys read$/\1/p')

# --- 2. a temporary server loads it --------------------------------------------

redis-server --dir "$INCOMING" --dbfilename dump.rdb --appendonly no --save "" \
  --port 0 --unixsocket "$SOCKET" --daemonize yes \
  --logfile "$LOG" --pidfile "$PIDFILE" >/dev/null

# wait_until WHAT TEST...: until the test passes. A server that is gone, or
# that takes longer than WAIT_SECONDS, fails the restore with its log.
wait_until() {
  what="$1"
  shift
  i=0
  until "$@"; do
    i=$((i + 1))
    if [ "$i" -gt 2 ] && ! server_alive; then
      echo "the temporary Redis stopped before it could $what:" >&2
      tail -n 5 "$LOG" >&2 2>/dev/null || true
      exit 1
    fi
    if [ "$i" -gt "$WAIT_SECONDS" ]; then
      echo "the temporary Redis did not $what in $WAIT_SECONDS seconds:" >&2
      tail -n 5 "$LOG" >&2 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
}

loaded_it() { [ "$(field persistence loading)" = "0" ]; }
wait_until "load the snapshot" loaded_it

[ "$(rcli PING 2>/dev/null)" = "PONG" ] \
  || fail "the temporary Redis loaded the snapshot and does not answer PING."
loaded=$(field persistence rdb_last_load_keys_loaded)
expired=$(field persistence rdb_last_load_keys_expired)
case "$loaded:$expired" in
  *[!0-9:]* | :* | *:) fail "the temporary Redis does not say how many keys it loaded." ;;
esac
if [ -n "$expected" ] && [ $((loaded + expired)) -ne "$expected" ]; then
  fail "the snapshot holds $expected keys, and the temporary Redis loaded $loaded and left out $expired as expired: the load is not complete."
fi
databases=$(rcli INFO keyspace | tr -d '\r' | grep -c '^db' || true)

# --- 3. it writes the append-only file -----------------------------------------

# Turning the append-only file on makes this server write one from the data
# it just loaded; that file is what the service reads at start.
rcli CONFIG SET appendonly yes >/dev/null
wrote_it() {
  [ "$(field persistence aof_enabled)" = "1" ] \
    && [ "$(field persistence aof_rewrite_in_progress)" = "0" ] \
    && [ "$(field persistence aof_last_bgrewrite_status)" = "ok" ]
}
wait_until "write the append-only file" wrote_it
stop_server
[ -f "$INCOMING/appendonlydir/appendonly.aof.manifest" ] \
  || fail "the temporary Redis wrote no append-only file."
redis-check-aof "$INCOMING/appendonlydir/appendonly.aof.manifest" >/dev/null 2>&1 \
  || fail "the append-only file the temporary Redis wrote does not read back (redis-check-aof)."

# --- 4. the swap ---------------------------------------------------------------

STAGE=swapping
mkdir "$PREVIOUS"
for item in appendonlydir dump.rdb; do
  [ ! -e "$DATA_DIR/$item" ] || mv "$DATA_DIR/$item" "$PREVIOUS/$item"
done
mv "$INCOMING/appendonlydir" "$DATA_DIR/appendonlydir"
STAGE=swapped
: > "$SWAPPED"
rm -rf "$PREVIOUS" "$INCOMING"

if [ "$expired" -gt 0 ]; then
  say "loaded the snapshot: $loaded keys in $databases Redis database(s); $expired had expired since the backup and were left out"
else
  say "loaded the snapshot: $loaded keys in $databases Redis database(s)"
fi
