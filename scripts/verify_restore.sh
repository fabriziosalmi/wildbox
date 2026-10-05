#!/usr/bin/env bash
#
# Restore drill: prove that a backup can produce a working database.
#
# The rubric this repository was audited against is explicit that an untested
# restore is not a backup (WILDBO-DATA-03). This script closes that loop: it
# takes a backup with backup_postgres.sh, restores it with restore_postgres.sh
# into scratch databases named <db>_restore_drill, compares every table's row
# count with the source, and drops the scratch databases again. Run it on a
# schedule.
#
# The live databases are only read: the drill counts their rows and dumps
# them. Everything it creates or drops is named <db>_restore_drill, and its
# archives go to a private temporary directory that is removed at the end.
#
# Usage:
#   ./scripts/verify_restore.sh           # back up, restore, compare, clean up
#   ./scripts/verify_restore.sh --keep    # keep the scratch databases and
#                                         # the drill's archives
#
# It reaches the database the way the backup does: inside the stack's
# postgres container by default, or directly with BACKUP_MODE=host. See
# scripts/lib/db_access.sh and backup_postgres.sh for the variables.
#
# Redis is not part of the drill: `make backup` snapshots it, and restoring
# that snapshot means replacing the running Redis data.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib/db_access.sh
. "$SCRIPT_DIR/lib/db_access.sh"

KEEP=false
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=true; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Fixed and never empty: every database the drill creates or drops carries
# it, so a live database can never be the target.
SUFFIX="_restore_drill"
# Same default as backup_postgres.sh. A drill that skips a database is not a
# drill for that database: guardian carries eight Django apps worth of assets,
# vulnerabilities and compliance data, and it was the one omitted here.
DATABASES="${DATABASES:-identity,data,guardian}"

wb_init_mode

DBS=()
IFS=',' read -ra RAW_DBS <<< "$DATABASES"
for db in "${RAW_DBS[@]}"; do
  db="${db//[[:space:]]/}"
  [ -n "$db" ] || continue
  wb_valid_db_name "$db" || wb_die "not a database name: '$db'"
  DBS+=("$db")
done
[ "${#DBS[@]}" -gt 0 ] || wb_die "no database to drill (DATABASES is empty)."
DATABASES=$(IFS=,; echo "${DBS[*]}")

# The drill's archives hold every password hash; they get their own
# directory, never the operator's BACKUP_DIR.
DRILL_DIR=$(mktemp -d "${TMPDIR:-/tmp}/wildbox-restore-drill.XXXXXX")
export BACKUP_MODE DATABASES
export BACKUP_DIR="$DRILL_DIR"

if [ "$BACKUP_MODE" = compose ]; then
  cd "$SCRIPT_DIR/.."
fi

# Drops only <db>_restore_drill. Returns non-zero if any drop failed.
# WITH (FORCE) ends a session that is still closing on the scratch database
# (PostgreSQL 13 and later); the plain form is the fallback for older servers.
drop_scratch() {
  local db failed=0
  for db in "${DBS[@]}"; do
    if ! wb_psql postgres "DROP DATABASE IF EXISTS \"${db}${SUFFIX}\" WITH (FORCE)" >/dev/null 2>&1 \
      && ! wb_psql postgres "DROP DATABASE IF EXISTS \"${db}${SUFFIX}\"" >/dev/null 2>&1; then
      echo "WARNING: could not drop the scratch database ${db}${SUFFIX}; it holds a copy of ${db}. Drop it by hand." >&2
      failed=1
    fi
  done
  return "$failed"
}

# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
  local status=$?
  if [ "$KEEP" = true ]; then
    echo "Kept: the <db>${SUFFIX} databases and the archives in $DRILL_DIR"
  else
    # A copy of the data left behind is not a clean drill.
    if ! drop_scratch && [ "$status" -eq 0 ]; then
      status=1
    fi
    rm -rf "$DRILL_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Exact row counts, one "schema.table|rows" line per table. Read-only: no
# ANALYZE, no statistics, so the live database is not written to and a large
# table is not estimated.
row_counts() {
  wb_psql "$1" "
    SELECT format('%I.%I', table_schema, table_name) || '|' ||
           (xpath('/row/n/text()', query_to_xml(
              format('SELECT count(*) AS n FROM %I.%I', table_schema, table_name),
              false, true, '')))[1]::text
    FROM information_schema.tables
    WHERE table_type = 'BASE TABLE'
      AND table_schema NOT IN ('pg_catalog', 'information_schema')
    ORDER BY 1"
}

echo "=== Restore drill ==="
echo "Mode:      $WB_MODE_LABEL"
echo "Databases: ${DBS[*]}"
echo "Redis:     not part of the drill"
echo ""

wb_require_postgres

# The backup is a snapshot taken somewhere between two counts of a database
# that may be in use. A table passes when its restored row count lies between
# the count before the backup and the count after it; on a quiet database
# all three are equal.
echo "1/4  Counting rows in the live databases (read-only)..."
for db in "${DBS[@]}"; do
  row_counts "$db" > "$DRILL_DIR/${db}.before"
done

echo "2/4  Taking a backup..."
if ! SKIP_REDIS=true "$SCRIPT_DIR/backup_postgres.sh" > "$DRILL_DIR/backup.log" 2>&1; then
  cat "$DRILL_DIR/backup.log" >&2
  echo "=== Restore drill FAILED: the backup did not complete ===" >&2
  exit 1
fi
for db in "${DBS[@]}"; do
  row_counts "$db" > "$DRILL_DIR/${db}.after"
done

echo "3/4  Restoring into scratch databases (<db>${SUFFIX})..."
# A scratch database left by an earlier --keep would be compared instead of
# this restore.
drop_scratch || wb_die "a scratch database from an earlier drill is in the way; drop it and run the drill again."
"$SCRIPT_DIR/restore_postgres.sh" --latest --into-suffix "$SUFFIX" | sed 's/^/     /'

echo "4/4  Comparing the restored databases with the originals..."
status=0
for db in "${DBS[@]}"; do
  row_counts "${db}${SUFFIX}" > "$DRILL_DIR/${db}.restored"

  if [ ! -s "$DRILL_DIR/${db}.restored" ]; then
    echo "     ${db}: FAILED (no tables in the restored database)" >&2
    status=1
    continue
  fi

  if report=$(awk -F'|' '
      FILENAME == ARGV[1] { before[$1] = $2; seen[$1] = 1; next }
      FILENAME == ARGV[2] { after[$1] = $2; seen[$1] = 1; next }
      { restored[$1] = $2; seen[$1] = 1 }
      END {
        bad = 0
        for (t in seen) {
          if (!(t in restored)) { printf "missing from the restore: %s\n", t; bad = 1; continue }
          if (!(t in before) && !(t in after)) { printf "not in the source: %s\n", t; bad = 1; continue }
          b = (t in before) ? before[t] : after[t]
          a = (t in after) ? after[t] : before[t]
          lo = (a + 0 < b + 0) ? a + 0 : b + 0
          hi = (a + 0 > b + 0) ? a + 0 : b + 0
          r = restored[t] + 0
          if (r < lo || r > hi) {
            printf "%s: restored %d rows, source had %d before and %d after the backup\n", t, r, b, a
            bad = 1
          }
          tables++; rows += r
          if (a != b) moved++
        }
        if (bad) exit 1
        printf "%d tables, %d rows", tables, rows
        if (moved) printf ", %d table(s) changed during the drill", moved
        printf "\n"
      }' "$DRILL_DIR/${db}.before" "$DRILL_DIR/${db}.after" "$DRILL_DIR/${db}.restored"); then
    echo "     ${db}: OK ($report, row counts match the source)"
  else
    echo "     ${db}: FAILED (the restored copy differs from the source)" >&2
    printf '%s\n' "$report" | sed 's/^/       /' >&2
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "=== Restore drill PASSED ==="
else
  echo "=== Restore drill FAILED ===" >&2
fi
exit "$status"
