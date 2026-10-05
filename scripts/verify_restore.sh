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
# The comparison is exact, on a database that is in use. For each database
# the drill opens one REPEATABLE READ transaction, exports its snapshot
# (pg_export_snapshot), counts every table inside it, and has the backup
# dumped from that same snapshot (pg_dump --snapshot). The restored copy must
# then hold the same tables with the same row counts, to the row: whatever
# is written while the drill runs is in neither side of the comparison.
#
# It used to count the source before and after the backup and accept any
# restored count in between (#723). A table that grew and shrank during the
# drill failed it for no reason, and a restore that lost rows of a table that
# grew passed it.
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
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
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

# Exact row counts, one "schema.table|rows" line per table. Read-only: no
# ANALYZE, no statistics, so the live database is not written to and a large
# table is not estimated. One statement, so it runs in whatever transaction
# and snapshot the session that sends it holds.
ROW_COUNTS_SQL="
  SELECT format('%I.%I', table_schema, table_name) || '|' ||
         (xpath('/row/n/text()', query_to_xml(
            format('SELECT count(*) AS n FROM %I.%I', table_schema, table_name),
            false, true, '')))[1]::text
  FROM information_schema.tables
  WHERE table_type = 'BASE TABLE'
    AND table_schema NOT IN ('pg_catalog', 'information_schema')
  ORDER BY 1"

row_counts() {
  wb_psql "$1" "$ROW_COUNTS_SQL"
}

# --- the snapshot the backup and the comparison share -------------------------

# One background psql session per database. It opens a read-only REPEATABLE
# READ transaction, prints the identifier of its snapshot, counts every
# table inside it, and then keeps the transaction open until the drill
# releases it, because pg_dump can only adopt a snapshot whose transaction is
# still running. Its stdin stays open for that long; it ends when the release
# file appears, when the drill's directory is gone, or when the drill itself
# is: a session left behind would hold a transaction open on the live
# database.
SESSION_PIDS=()

open_snapshot() {
  local db="$1" out="$DRILL_DIR/$1.session"
  {
    # The server must not end the session for sitting in its transaction
    # while another database is being dumped.
    echo "SET idle_in_transaction_session_timeout = 0;"
    echo "BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY;"
    echo "SELECT 'snapshot:' || pg_export_snapshot();"
    echo "${ROW_COUNTS_SQL};"
    echo "SELECT 'counted:all';"
    while kill -0 "$$" 2>/dev/null && [ -d "$DRILL_DIR" ] \
      && [ ! -e "$DRILL_DIR/release" ]; do
      sleep 1
    done
  } | wb_pg_stdin psql -d "$db" -v ON_ERROR_STOP=1 -X -q -tA \
        > "$out" 2> "${out}.err" &
  SESSION_PIDS+=("$!")
}

# Wait until the session of database $1 (the $2-th) has counted, then leave
# its counts in <db>.source and echo its snapshot identifier. A session that
# ended before it got there fails the drill with what it said.
await_snapshot() {
  local db="$1" pid="${SESSION_PIDS[$2]}" out="$DRILL_DIR/$1.session"
  until grep -qx 'counted:all' "$out" 2>/dev/null; do
    if ! kill -0 "$pid" 2>/dev/null; then
      grep -qx 'counted:all' "$out" 2>/dev/null && break
      cat "${out}.err" >&2 2>/dev/null || true
      echo "=== Restore drill FAILED: could not count '$db' in a snapshot ===" >&2
      exit 1
    fi
    sleep 1
  done
  grep -F '|' "$out" > "$DRILL_DIR/${db}.source" || true
  local snapshot
  snapshot=$(sed -n 's/^snapshot://p' "$out")
  if [ -z "$snapshot" ]; then
    echo "=== Restore drill FAILED: '$db' exported no snapshot ===" >&2
    exit 1
  fi
  printf '%s' "$snapshot"
}

# End every session: their transactions roll back, nothing was written.
release_snapshots() {
  [ ! -d "$DRILL_DIR" ] || : > "$DRILL_DIR/release"
  local pid
  for pid in "${SESSION_PIDS[@]+"${SESSION_PIDS[@]}"}"; do
    wait "$pid" 2>/dev/null || true
  done
  SESSION_PIDS=()
}

# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
  local status=$?
  release_snapshots
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

echo "=== Restore drill ==="
echo "Mode:      $WB_MODE_LABEL"
echo "Databases: ${DBS[*]}"
echo "Redis:     not part of the drill"
echo ""

wb_require_postgres

echo "1/4  Counting rows in a snapshot of each live database (read-only)..."
for db in "${DBS[@]}"; do
  open_snapshot "$db"
done
SNAPSHOT_ARGS=()
for i in "${!DBS[@]}"; do
  snapshot=$(await_snapshot "${DBS[$i]}" "$i")
  SNAPSHOT_ARGS+=(--snapshot "${DBS[$i]}=${snapshot}")
done

echo "2/4  Taking a backup from the same snapshots..."
if ! SKIP_REDIS=true "$SCRIPT_DIR/backup_postgres.sh" "${SNAPSHOT_ARGS[@]}" \
    > "$DRILL_DIR/backup.log" 2>&1; then
  cat "$DRILL_DIR/backup.log" >&2
  echo "=== Restore drill FAILED: the backup did not complete ===" >&2
  exit 1
fi
release_snapshots

echo "3/4  Restoring into scratch databases (<db>${SUFFIX})..."
# A scratch database left by an earlier --keep would be compared instead of
# this restore.
drop_scratch || wb_die "a scratch database from an earlier drill is in the way; drop it and run the drill again."
"$SCRIPT_DIR/restore_postgres.sh" --latest --into-suffix "$SUFFIX" | sed 's/^/     /'

echo "4/4  Comparing the restored databases with the snapshots..."
status=0
for db in "${DBS[@]}"; do
  row_counts "${db}${SUFFIX}" > "$DRILL_DIR/${db}.restored"

  if [ ! -s "$DRILL_DIR/${db}.restored" ]; then
    echo "     ${db}: FAILED (no tables in the restored database)" >&2
    status=1
    continue
  fi

  # The same tables, each with the same number of rows. No tolerance: both
  # sides are the one snapshot.
  if report=$(awk -F'|' '
      FILENAME == ARGV[1] { source[$1] = $2; seen[$1] = 1; next }
      { restored[$1] = $2; seen[$1] = 1 }
      END {
        bad = 0
        for (t in seen) {
          if (!(t in restored)) { printf "missing from the restore: %s\n", t; bad = 1; continue }
          if (!(t in source)) { printf "not in the source: %s\n", t; bad = 1; continue }
          if (restored[t] + 0 != source[t] + 0) {
            printf "%s: restored %d rows, the source had %d in the snapshot the backup was taken from\n", t, restored[t], source[t]
            bad = 1
            continue
          }
          tables++; rows += restored[t]
        }
        if (bad) exit 1
        printf "%d tables, %d rows\n", tables, rows
      }' "$DRILL_DIR/${db}.source" "$DRILL_DIR/${db}.restored"); then
    echo "     ${db}: OK ($report, every row count equals the source's)"
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
