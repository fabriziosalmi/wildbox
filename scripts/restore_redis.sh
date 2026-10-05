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
# The data that is in the volume stays there until the snapshot has been
# loaded and checked: it is loaded in a scratch directory of the volume, the
# temporary server has to answer and to hold as many keys as the snapshot,
# the append-only file it writes is read back, and only then are the two
# swapped. A snapshot that does not load leaves Redis as it was; it used to
# leave it empty (#740). scripts/lib/restore_redis_volume.sh is that part,
# and says what a run that dies during the swap leaves and how the next run
# deals with it. The volume needs room for both copies meanwhile.
#
# It REPLACES everything in the Redis data volume: scan and run state,
# queued work, revoked tokens and lockouts written since the backup are
# lost. So it runs only when told to, with --replace-redis-data, and it
# refuses while the Redis service is running. Without the flag it says which
# volume it would have replaced with which snapshot and changes nothing
# (#723); there is no prompt, so a script can still run it. Stop the
# services that use Redis, then Redis, restore, and start them again:
#
#   docker compose stop                      # or just the Redis clients
#   ./scripts/restore_redis.sh --latest --replace-redis-data
#   docker compose up -d
#
# Usage:
#   ./scripts/restore_redis.sh --timestamp 20260908_120000 --replace-redis-data
#   ./scripts/restore_redis.sh --latest --replace-redis-data
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
REPLACE=false
while [ $# -gt 0 ]; do
  case "$1" in
    --timestamp) TIMESTAMP="$2"; shift 2 ;;
    --timestamp=*) TIMESTAMP="${1#*=}"; shift ;;
    --latest) USE_LATEST=true; shift ;;
    --replace-redis-data) REPLACE=true; shift ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
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

# The timestamps in the names of the files matching the pattern $1 with the
# suffix $2, oldest first. From the names, which the backup writes, not from
# modification times, which a copy changes.
stamps_of() {
  local file
  for file in "${BACKUP_DIR}"/$1; do
    [ -e "$file" ] || continue
    file="${file##*/}"
    file="${file%%"$2"*}"
    file="${file: -15}"
    [[ "$file" =~ ^[0-9]{8}_[0-9]{6}$ ]] && echo "$file"
  done | sort -u
}

if [ "$USE_LATEST" = true ]; then
  # The newest backup RUN, as restore_postgres.sh --latest takes it. A run
  # taken with SKIP_REDIS=true has archives and no snapshot: the newest
  # snapshot is then older than the databases --latest restores, and the
  # two would be from different moments (#740).
  NEWEST=$(stamps_of 'redis_[0-9]*.rdb.gz*' .rdb.gz | tail -n 1)
  [ -n "$NEWEST" ] || wb_die "no Redis snapshot found in $BACKUP_DIR"
  NEWEST_RUN=$({ echo "$NEWEST"; stamps_of '*_[0-9]*.sql.gz*' .sql.gz; } | sort -u | tail -n 1)
  if [ "$NEWEST_RUN" != "$NEWEST" ]; then
    cat >&2 <<MSG
REFUSING --latest: the newest backup run, $NEWEST_RUN, holds no Redis
snapshot (a run with SKIP_REDIS=true). The newest snapshot is from
$NEWEST, an earlier run than the one restore_postgres.sh --latest
restores. Nothing was changed. Name the snapshot to restore it:

    --timestamp $NEWEST
MSG
    exit 1
  fi
  # shellcheck disable=SC2012
  SNAPSHOT=$(ls "${BACKUP_DIR}/redis_${NEWEST}.rdb.gz"* 2>/dev/null | head -1 || true)
else
  # shellcheck disable=SC2012
  SNAPSHOT=$(ls "${BACKUP_DIR}/redis_${TIMESTAMP}.rdb.gz"* 2>/dev/null | head -1 || true)
fi
[ -n "$SNAPSHOT" ] || wb_die "no Redis snapshot found in $BACKUP_DIR"

running=$("${WB_COMPOSE[@]}" ps --status running -q "$REDIS_SERVICE" </dev/null) \
  || wb_die "docker compose could not list the '$REDIS_SERVICE' service. Check COMPOSE_FILE, COMPOSE_PROJECT_NAME and the env file."
[ -z "$running" ] \
  || wb_die "the '$REDIS_SERVICE' service is running. This restore replaces its data: stop the services that use Redis, then Redis itself (docker compose stop), and run this again."

# There is no harmless form of this restore, so it is never what a missing
# option means.
if [ "$REPLACE" != true ]; then
  cat >&2 <<MSG
REFUSING to replace the Redis data without --replace-redis-data.

This would delete everything in the data volume of the '$REDIS_SERVICE'
service and load $(basename "$SNAPSHOT") in its place.
Scan and run state, queued work, revoked tokens and lockouts written since
that backup would be lost. Nothing was changed.

    --replace-redis-data   replace the data with the snapshot
MSG
  exit 2
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=== Wildbox Redis Restore ==="
echo "Snapshot: $(basename "$SNAPSHOT")"
echo "Target:   the data volume of the '$REDIS_SERVICE' service (replaced once"
echo "          the snapshot has loaded; kept as it is if it does not)"
echo ""

STAGED="$WORKDIR/dump.rdb"
if [[ "$SNAPSHOT" == *.gpg ]]; then
  gpg --batch --yes --decrypt "$SNAPSHOT" | gunzip -c > "$STAGED"
else
  gunzip -c "$SNAPSHOT" > "$STAGED"
fi
[ "$(head -c 5 "$STAGED")" = "REDIS" ] || wb_die "$(basename "$SNAPSHOT") is not an RDB snapshot."

# One container of the service: its image and its /data volume, nothing
# else. What runs in it is scripts/lib/restore_redis_volume.sh, with the
# snapshot on stdin: it loads the snapshot next to the data that is there,
# checks what was loaded, and only then swaps the two.
"${WB_COMPOSE[@]}" run --rm -T --no-deps --entrypoint sh "$REDIS_SERVICE" \
  -c "$(cat "$SCRIPT_DIR/lib/restore_redis_volume.sh")" < "$STAGED"

echo ""
echo "=== Redis restore complete ==="
echo "NEXT: start Redis and the services that use it:  docker compose up -d"
