#!/usr/bin/env bash
#
# Restore drill: prove that a backup can produce a working database.
#
# The rubric this repository was audited against is explicit that an untested
# restore is not a backup (WILDBO-DATA-03). This script closes that loop: it
# takes a backup, restores it into a scratch database, asserts the data is there,
# and drops the scratch database again. Run it on a schedule, or in CI against a
# seeded Postgres.
#
# Usage:
#   ./scripts/verify_restore.sh                # back up, restore, verify, clean up
#   ./scripts/verify_restore.sh --keep         # leave the scratch databases

set -euo pipefail
cd "$(dirname "$0")/.."

KEEP=false
[ "${1:-}" = "--keep" ] && KEEP=true

: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
POSTGRES_HOST="${POSTGRES_HOST:-wildbox-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
export BACKUP_DIR="${BACKUP_DIR:-/tmp/wildbox-restore-drill}"
SUFFIX="_restore_drill"
# Same default as backup_postgres.sh. A drill that skips a database is not a
# drill for that database: guardian carries eight Django apps worth of assets,
# vulnerabilities and compliance data, and it was the one omitted here.
DATABASES="${DATABASES:-identity,data,guardian}"

mkdir -p "$BACKUP_DIR"

PGPASS_FILE=$(mktemp); chmod 600 "$PGPASS_FILE"
echo "${POSTGRES_HOST}:${POSTGRES_PORT}:*:${POSTGRES_USER}:${POSTGRES_PASSWORD}" > "$PGPASS_FILE"
export PGPASSFILE="$PGPASS_FILE"
cleanup() {
  if [ "$KEEP" != true ]; then
    IFS=',' read -ra DBS <<< "$DATABASES"
    for db in "${DBS[@]}"; do
      psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d postgres \
        -c "DROP DATABASE IF EXISTS \"$(echo "$db" | xargs)${SUFFIX}\"" >/dev/null 2>&1 || true
    done
  fi
  rm -f "$PGPASS_FILE"
}
trap cleanup EXIT

echo "=== Restore drill ==="
echo "1/3  Taking a backup..."
SKIP_REDIS=true DATABASES="$DATABASES" ./scripts/backup_postgres.sh >/dev/null
echo "     done"

echo "2/3  Restoring into scratch databases (<db>${SUFFIX})..."
DATABASES="$DATABASES" ./scripts/restore_postgres.sh --latest --into-suffix "$SUFFIX"

echo "3/3  Verifying the restored databases match the originals..."
status=0
IFS=',' read -ra DBS <<< "$DATABASES"

# Counting tables is not enough: a restore that produced the schema and none of
# the rows would pass that check while having lost every byte that mattered.
# Compare the live database and the restored copy table by table.
row_counts() {
  psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$1" -tAF, -c "
    SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY relname" 2>/dev/null
}

for db in "${DBS[@]}"; do
  db=$(echo "$db" | xargs)
  count=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
    -d "${db}${SUFFIX}" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null || echo 0)
  if [ "$count" -eq 0 ]; then
    echo "     ${db}: FAILED (no tables in the restored database)" >&2
    status=1
    continue
  fi

  # ANALYZE so pg_stat_user_tables reports the restored copy accurately.
  psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
    -d "${db}${SUFFIX}" -qc "ANALYZE" >/dev/null 2>&1 || true
  psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
    -d "$db" -qc "ANALYZE" >/dev/null 2>&1 || true

  src=$(row_counts "$db")
  dst=$(row_counts "${db}${SUFFIX}")
  if [ "$src" = "$dst" ]; then
    rows=$(echo "$src" | awk -F, '{n+=$2} END {print n+0}')
    echo "     ${db}: OK ($count tables, $rows rows, identical to the source)"
  else
    echo "     ${db}: FAILED (restored row counts differ from the source)" >&2
    diff <(echo "$src") <(echo "$dst") | sed 's/^/       /' >&2 || true
    status=1
  fi
done

[ "$status" -eq 0 ] && echo "=== Restore drill PASSED ===" || echo "=== Restore drill FAILED ===" >&2
exit "$status"
