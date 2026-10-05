#!/usr/bin/env bash
#
# Redis restore for the Wildbox Security Suite.
#
# backup_postgres.sh snapshots Redis as redis_<timestamp>.rdb.gz. The stack
# runs Redis with `--appendonly yes`, and a Redis that has the append-only
# file enabled does not read dump.rdb at start: copying the snapshot into the
# data volume and starting the service gives an EMPTY Redis. This script
# loads the snapshot in a one-off container of the Redis service (same image,
# same data volume, no network port, append-only off), has that server write
# the append-only file, and stops it. The service then starts with the
# restored data.
#
# It REPLACES everything in the Redis data volume, and it refuses to run
# while the Redis service is running. Stop the services that use Redis, then
# Redis, restore, and start them again:
#
#   docker compose stop                      # or just the Redis clients
#   ./scripts/restore_redis.sh --latest
#   docker compose up -d
#
# Usage:
#   ./scripts/restore_redis.sh --timestamp 20260908_120000
#   ./scripts/restore_redis.sh --latest
#
# Compose only: it works on the stack's own Redis volume, honoring
# COMPOSE_FILE, COMPOSE_PROJECT_NAME and ENV_FILE like the backup. For a
# Redis you run elsewhere, load the RDB file the way that Redis is operated.
#
# Environment variables: BACKUP_DIR (default: <repository>/backups),
# REDIS_SERVICE (default: wildbox-redis). Snapshots encrypted with
# GPG_RECIPIENT are decrypted with the local gpg key.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib/db_access.sh
. "$SCRIPT_DIR/lib/db_access.sh"

TIMESTAMP=""
USE_LATEST=false
while [ $# -gt 0 ]; do
  case "$1" in
    --timestamp) TIMESTAMP="$2"; shift 2 ;;
    --timestamp=*) TIMESTAMP="${1#*=}"; shift ;;
    --latest) USE_LATEST=true; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$TIMESTAMP" ] && [ "$USE_LATEST" != true ]; then
  echo "ERROR: pass --timestamp <stamp> or --latest" >&2
  exit 2
fi
if [ -n "$TIMESTAMP" ] && ! [[ "$TIMESTAMP" =~ ^[0-9]{8}_[0-9]{6}$ ]]; then
  echo "ERROR: --timestamp looks like 20260908_120000, got: $TIMESTAMP" >&2
  exit 2
fi

BACKUP_MODE=compose
wb_init_mode

BACKUP_DIR="${BACKUP_DIR:-$SCRIPT_DIR/../backups}"
[ -d "$BACKUP_DIR" ] || wb_die "backup directory not found: $BACKUP_DIR"
BACKUP_DIR="$(cd "$BACKUP_DIR" && pwd)"
cd "$SCRIPT_DIR/.."

if [ "$USE_LATEST" = true ]; then
  # shellcheck disable=SC2012
  SNAPSHOT=$(ls -t "${BACKUP_DIR}/redis_"[0-9]*.rdb.gz* 2>/dev/null | head -1 || true)
else
  # shellcheck disable=SC2012
  SNAPSHOT=$(ls "${BACKUP_DIR}/redis_${TIMESTAMP}.rdb.gz"* 2>/dev/null | head -1 || true)
fi
[ -n "$SNAPSHOT" ] || wb_die "no Redis snapshot found in $BACKUP_DIR"

running=$("${WB_COMPOSE[@]}" ps --status running -q "$REDIS_SERVICE" </dev/null) \
  || wb_die "docker compose could not list the '$REDIS_SERVICE' service. Check COMPOSE_FILE, COMPOSE_PROJECT_NAME and the env file."
[ -z "$running" ] \
  || wb_die "the '$REDIS_SERVICE' service is running. This restore replaces its data: stop the services that use Redis, then Redis itself (docker compose stop), and run this again."

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=== Wildbox Redis Restore ==="
echo "Snapshot: $(basename "$SNAPSHOT")"
echo "Target:   the data volume of the '$REDIS_SERVICE' service (REPLACED)"
echo ""

STAGED="$WORKDIR/dump.rdb"
if [[ "$SNAPSHOT" == *.gpg ]]; then
  gpg --batch --yes --decrypt "$SNAPSHOT" | gunzip -c > "$STAGED"
else
  gunzip -c "$SNAPSHOT" > "$STAGED"
fi
[ "$(head -c 5 "$STAGED")" = "REDIS" ] || wb_die "$(basename "$SNAPSHOT") is not an RDB snapshot."

# One container of the service: its image and its /data volume, nothing
# else. The temporary server listens on a Unix socket only.
# shellcheck disable=SC2016
"${WB_COMPOSE[@]}" run --rm -T --no-deps --entrypoint sh "$REDIS_SERVICE" -c '
  set -eu
  cd /data
  rm -rf appendonlydir dump.rdb
  cat > dump.rdb
  rcli() { redis-cli -s /tmp/restore.sock "$@"; }
  field() { rcli INFO "$1" 2>/dev/null | tr -d "\r" | sed -n "s/^$2://p"; }
  redis-server --dir /data --dbfilename dump.rdb --appendonly no --save "" \
    --port 0 --unixsocket /tmp/restore.sock --daemonize yes \
    --logfile /tmp/restore.log >/dev/null
  i=0
  until [ "$(field persistence loading)" = "0" ]; do
    i=$((i + 1))
    if [ "$i" -gt 600 ]; then
      echo "the temporary Redis did not finish loading the snapshot:" >&2
      cat /tmp/restore.log >&2
      exit 1
    fi
    sleep 1
  done
  keys=$(rcli INFO keyspace | tr -d "\r" | grep -c "^db" || true)
  # Turning the append-only file on makes this server write one from the
  # data it just loaded; that file is what the service reads at start.
  rcli CONFIG SET appendonly yes >/dev/null
  i=0
  until [ "$(field persistence aof_enabled)" = "1" ] \
     && [ "$(field persistence aof_rewrite_in_progress)" = "0" ] \
     && [ "$(field persistence aof_last_bgrewrite_status)" = "ok" ]; do
    i=$((i + 1))
    if [ "$i" -gt 600 ]; then
      echo "the temporary Redis did not write the append-only file:" >&2
      cat /tmp/restore.log >&2
      exit 1
    fi
    sleep 1
  done
  rcli SHUTDOWN NOSAVE >/dev/null 2>&1 || true
  [ -d appendonlydir ] || { echo "no append-only file was written" >&2; exit 1; }
  echo "  loaded the snapshot: $keys Redis database(s) with keys"
' < "$STAGED"

echo ""
echo "=== Redis restore complete ==="
echo "NEXT: start Redis and the services that use it:  docker compose up -d"
