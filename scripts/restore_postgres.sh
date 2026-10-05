#!/usr/bin/env bash
#
# PostgreSQL restore for the Wildbox Security Suite.
#
# backup_postgres.sh writes pg_dump --format=custom archives, which only
# pg_restore can read -- and pg_restore appeared nowhere in the repository. The
# backup script's "Verifying backup integrity" step ran `gzip -t`, which proves
# the gzip container is intact and proves nothing about whether the dump inside
# it can be loaded into a working database. Nobody had ever demonstrated that
# these backups could produce a running system, and the first attempt would have
# happened during an incident (WILDBO-DATA-03).
#
# Usage:
#   ./restore_postgres.sh --timestamp 20260908_120000                # all DBs
#   ./restore_postgres.sh --timestamp 20260908_120000 --databases data
#   ./restore_postgres.sh --timestamp 20260908_120000 --into-suffix _verify
#   ./restore_postgres.sh --latest --databases identity --dry-run
#
# Without --into-suffix this restores OVER the live databases: stop the
# services that use them first. --into-suffix restores into "<db><suffix>"
# instead, which is how the drill in scripts/verify_restore.sh exercises this
# path without touching live data.
#
# Like the backup, it runs pg_restore and psql inside the stack's postgres
# container by default (compose mode) and connects directly with
# BACKUP_MODE=host; see scripts/lib/db_access.sh and backup_postgres.sh for
# the variables (BACKUP_MODE, BACKUP_DIR, DATABASES, POSTGRES_*, ENV_FILE).
# Archives encrypted with GPG_RECIPIENT are decrypted with the local gpg key.
#
# Redis is restored by hand from the redis_<timestamp>.rdb.gz snapshot; the
# deployment guide has the steps.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib/db_access.sh
. "$SCRIPT_DIR/lib/db_access.sh"

DATABASES="${DATABASES:-identity,data,guardian}"
TIMESTAMP=""
INTO_SUFFIX=""
DRY_RUN=false
USE_LATEST=false

while [ $# -gt 0 ]; do
  case "$1" in
    --timestamp) TIMESTAMP="$2"; shift 2 ;;
    --timestamp=*) TIMESTAMP="${1#*=}"; shift ;;
    --databases) DATABASES="$2"; shift 2 ;;
    --databases=*) DATABASES="${1#*=}"; shift ;;
    --into-suffix) INTO_SUFFIX="$2"; shift 2 ;;
    --into-suffix=*) INTO_SUFFIX="${1#*=}"; shift ;;
    --latest) USE_LATEST=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
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
if [ -n "$INTO_SUFFIX" ] && ! [[ "$INTO_SUFFIX" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "ERROR: --into-suffix takes letters, digits and underscores, got: $INTO_SUFFIX" >&2
  exit 2
fi

wb_init_mode

if [ "$BACKUP_MODE" = compose ]; then
  BACKUP_DIR="${BACKUP_DIR:-$SCRIPT_DIR/../backups}"
else
  BACKUP_DIR="${BACKUP_DIR:-/backups/postgres}"
fi
[ -d "$BACKUP_DIR" ] || wb_die "backup directory not found: $BACKUP_DIR"
BACKUP_DIR="$(cd "$BACKUP_DIR" && pwd)"

DB_ARRAY=()
IFS=',' read -ra RAW_DBS <<< "$DATABASES"
for db in "${RAW_DBS[@]}"; do
  db="${db//[[:space:]]/}"
  [ -n "$db" ] || continue
  wb_valid_db_name "$db" || wb_die "not a database name: '$db'"
  DB_ARRAY+=("$db")
done
[ "${#DB_ARRAY[@]}" -gt 0 ] || wb_die "no database to restore (DATABASES is empty)."

if [ "$BACKUP_MODE" = compose ]; then
  cd "$SCRIPT_DIR/.."
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=== Wildbox PostgreSQL Restore ==="
echo "Mode:       $WB_MODE_LABEL"
echo "Backup dir: $BACKUP_DIR"
echo "Databases:  ${DB_ARRAY[*]}"
if [ -n "$INTO_SUFFIX" ]; then
  echo "Target:     <database>${INTO_SUFFIX} (not the live database)"
else
  echo "Target:     the LIVE databases"
fi
[ "$DRY_RUN" = true ] && echo "MODE:       dry run, nothing will be written"
echo ""

wb_require_postgres

for db in "${DB_ARRAY[@]}"; do
  if [ "$USE_LATEST" = true ]; then
    # shellcheck disable=SC2012
    ARCHIVE=$(ls -t "${BACKUP_DIR}/${db}_"[0-9]*.sql.gz* 2>/dev/null | head -1 || true)
  else
    # shellcheck disable=SC2012
    ARCHIVE=$(ls "${BACKUP_DIR}/${db}_${TIMESTAMP}.sql.gz"* 2>/dev/null | head -1 || true)
  fi
  if [ -z "$ARCHIVE" ]; then
    echo "ERROR: no backup found for '$db' in $BACKUP_DIR" >&2
    exit 1
  fi
  echo "Restoring $db from $(basename "$ARCHIVE")"

  STAGED="$WORKDIR/${db}.dump"
  if [[ "$ARCHIVE" == *.gpg ]]; then
    gpg --batch --yes --decrypt "$ARCHIVE" > "${STAGED}.gz"
    gunzip -f "${STAGED}.gz"
  else
    gunzip -c "$ARCHIVE" > "$STAGED"
  fi

  # Prove the archive is a readable pg_dump before touching any database. This
  # is the check `gzip -t` could not make.
  if ! wb_pg_stdin pg_restore --list < "$STAGED" > "$WORKDIR/${db}.toc" 2>"$WORKDIR/${db}.err"; then
    echo "  FAILED: archive is not a readable pg_dump custom archive" >&2
    cat "$WORKDIR/${db}.err" >&2
    exit 1
  fi
  echo "  archive readable: $(grep -c '^[0-9]' "$WORKDIR/${db}.toc" || true) objects"

  TARGET_DB="${db}${INTO_SUFFIX}"
  if [ "$DRY_RUN" = true ]; then
    echo "  dry run: would restore into '$TARGET_DB'"
    continue
  fi

  exists=$(wb_psql postgres "SELECT 1 FROM pg_database WHERE datname = '${TARGET_DB}'")
  if [ "$exists" = "1" ]; then
    echo "  database '$TARGET_DB' already exists, restoring into it"
  else
    wb_psql postgres "CREATE DATABASE \"${TARGET_DB}\""
  fi

  wb_pg_stdin pg_restore -d "$TARGET_DB" \
    --no-owner --no-privileges --clean --if-exists \
    < "$STAGED"

  COUNT=$(wb_psql "$TARGET_DB" \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
  echo "  restored into '$TARGET_DB': $COUNT tables"
done

echo ""
echo "=== Restore complete ==="
