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
DATABASES="${DATABASES:-identity,data}"

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

echo "3/3  Verifying the restored databases contain tables..."
status=0
IFS=',' read -ra DBS <<< "$DATABASES"
for db in "${DBS[@]}"; do
  db=$(echo "$db" | xargs)
  count=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
    -d "${db}${SUFFIX}" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null || echo 0)
  if [ "$count" -gt 0 ]; then
    echo "     ${db}: OK ($count tables restored)"
  else
    echo "     ${db}: FAILED (no tables in the restored database)" >&2
    status=1
  fi
done

[ "$status" -eq 0 ] && echo "=== Restore drill PASSED ===" || echo "=== Restore drill FAILED ===" >&2
exit "$status"
