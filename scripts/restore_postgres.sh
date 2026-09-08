#!/usr/bin/env bash
#
# PostgreSQL restore for the Wildbox Security Suite.
#
# backup_postgres.sh writes pg_dump --format=custom archives, which only
# pg_restore can read -- and pg_restore appeared nowhere in the repository. The
# backup script's "Verifying backup integrity" step runs `gzip -t`, which proves
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
# --into-suffix restores into "<db><suffix>" instead of over the live database,
# which is how the drill in scripts/verify_restore.sh exercises this path
# without touching production data.
#
# Environment variables: as backup_postgres.sh (POSTGRES_HOST, POSTGRES_PORT,
# POSTGRES_USER, POSTGRES_PASSWORD, BACKUP_DIR, GPG_RECIPIENT).

set -euo pipefail

POSTGRES_HOST="${POSTGRES_HOST:-wildbox-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
BACKUP_DIR="${BACKUP_DIR:-/backups/postgres}"
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
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "${POSTGRES_PASSWORD:-}" ]; then
  echo "ERROR: POSTGRES_PASSWORD environment variable is required" >&2
  exit 1
fi
if [ -z "$TIMESTAMP" ] && [ "$USE_LATEST" != true ]; then
  echo "ERROR: pass --timestamp <stamp> or --latest" >&2
  exit 2
fi

PGPASS_FILE=$(mktemp)
chmod 600 "$PGPASS_FILE"
echo "${POSTGRES_HOST}:${POSTGRES_PORT}:*:${POSTGRES_USER}:${POSTGRES_PASSWORD}" > "$PGPASS_FILE"
export PGPASSFILE="$PGPASS_FILE"
WORKDIR=$(mktemp -d)
trap 'rm -f "$PGPASS_FILE"; rm -rf "$WORKDIR"' EXIT

echo "=== Wildbox PostgreSQL Restore ==="
echo "Host:      $POSTGRES_HOST:$POSTGRES_PORT"
echo "Backup dir:$BACKUP_DIR"
echo "Databases: $DATABASES"
[ -n "$INTO_SUFFIX" ] && echo "Target:    <database>${INTO_SUFFIX} (not the live database)"
[ "$DRY_RUN" = true ] && echo "MODE:      dry run, nothing will be written"
echo ""

IFS=',' read -ra DB_ARRAY <<< "$DATABASES"
for db in "${DB_ARRAY[@]}"; do
  db=$(echo "$db" | xargs)

  if [ "$USE_LATEST" = true ]; then
    ARCHIVE=$(ls -t "${BACKUP_DIR}/${db}_"*.sql.gz* 2>/dev/null | head -1 || true)
  else
    ARCHIVE=$(ls "${BACKUP_DIR}/${db}_${TIMESTAMP}.sql.gz"* 2>/dev/null | head -1 || true)
  fi
  if [ -z "$ARCHIVE" ]; then
    echo "ERROR: no backup found for '$db'" >&2
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
  if ! pg_restore --list "$STAGED" > "$WORKDIR/${db}.toc" 2>"$WORKDIR/${db}.err"; then
    echo "  FAILED: archive is not a readable pg_dump custom archive" >&2
    cat "$WORKDIR/${db}.err" >&2
    exit 1
  fi
  echo "  archive readable: $(grep -c . "$WORKDIR/${db}.toc") objects"

  TARGET_DB="${db}${INTO_SUFFIX}"
  if [ "$DRY_RUN" = true ]; then
    echo "  dry run: would restore into '$TARGET_DB'"
    continue
  fi

  psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d postgres \
    -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$TARGET_DB\"" 2>/dev/null \
    || echo "  database '$TARGET_DB' already exists, restoring into it"

  pg_restore \
    -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
    -d "$TARGET_DB" \
    --no-owner --no-privileges --clean --if-exists \
    "$STAGED"

  COUNT=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$TARGET_DB" \
    -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
  echo "  restored into '$TARGET_DB': $COUNT tables"
done

echo ""
echo "=== Restore complete ==="
