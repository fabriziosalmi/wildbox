#!/usr/bin/env bash
#
# Backup for the Wildbox Security Suite: PostgreSQL and Redis.
#
# What it backs up:
#
#   PostgreSQL  The three databases scripts/init-databases.sql provisions:
#               identity, data and guardian. One pg_dump custom-format
#               archive each, gzip-compressed.
#   Redis       One RDB snapshot of every Redis database. Redis is not a
#               cache here: it holds the only copy of CSPM scan metadata and
#               reports, responder playbook run state, agents analysis
#               results, tools task ownership, identity's revoked-token list
#               and account lockouts, and the Celery queues.
#
# A run either completes or leaves nothing: if any database or Redis fails,
# the script exits non-zero and removes the files this run wrote, so a
# timestamp in the backup directory is always a complete set. Leaving Redis
# out is a decision you state (SKIP_REDIS=true), never a silent fallback.
#
# Usage:
#   ./scripts/backup_postgres.sh                      # the default stack
#   ./scripts/backup_postgres.sh --databases identity,data
#   ./scripts/backup_postgres.sh --upload-s3          # also copy to S3
#   BACKUP_MODE=host POSTGRES_HOST=db.internal POSTGRES_PASSWORD=... \
#     ./scripts/backup_postgres.sh                    # external database
#
# --snapshot DATABASE=ID (repeatable) dumps that database from a snapshot
# another session exported with pg_export_snapshot(), instead of the one
# pg_dump would take itself: the archive then holds exactly what that
# session sees. The session has to keep its transaction open until the dump
# has started, or pg_dump fails. The restore drill uses this to compare a
# restore with the source as the backup saw it (scripts/verify_restore.sh).
#
# Modes (see scripts/lib/db_access.sh):
#   compose  Default. Runs pg_dump and redis-cli inside the stack's
#            containers with `docker compose exec`. Honors COMPOSE_FILE,
#            COMPOSE_PROJECT_NAME and ENV_FILE. Needs only Docker.
#   host     Connects from this machine. Chosen by BACKUP_MODE=host, or by
#            setting POSTGRES_HOST. Needs the PostgreSQL client tools and
#            redis-cli on PATH.
#
# Environment variables:
#   BACKUP_MODE         compose | host (default: host if POSTGRES_HOST is
#                       set, compose otherwise)
#   BACKUP_DIR          default: <repository>/backups in compose mode,
#                       /backups/postgres in host mode
#   BACKUP_RETENTION    days of archives to keep (default: 30)
#   DATABASES           default: identity,data,guardian
#   SKIP_REDIS          true to leave Redis out
#   GPG_RECIPIENT       optional: encrypt every archive for this recipient
#   S3_BUCKET           required by --upload-s3
#   compose mode:       POSTGRES_SERVICE (postgres), REDIS_SERVICE
#                       (wildbox-redis), ENV_FILE (.env), REDIS_PASSWORD
#                       (default: read from the env file)
#   host mode:          POSTGRES_HOST, POSTGRES_PORT, POSTGRES_USER,
#                       POSTGRES_PASSWORD, REDIS_HOST, REDIS_PORT,
#                       REDIS_PASSWORD
#
# Archives are written with mode 600 in a mode-700 directory: they hold
# every password hash and every stored credential. No password file is
# written.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib/db_access.sh
. "$SCRIPT_DIR/lib/db_access.sh"

BACKUP_RETENTION="${BACKUP_RETENTION:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# All three databases scripts/init-databases.sql provisions. This defaulted to
# "identity,data", silently omitting guardian -- eight Django apps' worth of
# assets, vulnerabilities, compliance, remediation and reporting tables
# (WILDBO-DATA-01).
DATABASES="${DATABASES:-identity,data,guardian}"
UPLOAD_S3=false
SNAPSHOTS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --upload-s3) UPLOAD_S3=true; shift ;;
    --databases=*) DATABASES="${1#*=}"; shift ;;
    --databases) DATABASES="${2:?--databases needs a value}"; shift 2 ;;
    --snapshot=*) SNAPSHOTS+=("${1#*=}"); shift ;;
    --snapshot) SNAPSHOTS+=("${2:?--snapshot needs DATABASE=SNAPSHOT_ID}"); shift 2 ;;
    -h|--help) sed -n '2,62p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

wb_init_mode

if [ "$BACKUP_MODE" = compose ]; then
  # Compose resolves its files and .env from the repository root.
  BACKUP_DIR="${BACKUP_DIR:-$SCRIPT_DIR/../backups}"
else
  BACKUP_DIR="${BACKUP_DIR:-/backups/postgres}"
fi

[[ "$BACKUP_RETENTION" =~ ^[0-9]+$ ]] \
  || wb_die "BACKUP_RETENTION must be a number of days, got: $BACKUP_RETENTION"
if [ "$UPLOAD_S3" = true ]; then
  [ -n "${S3_BUCKET:-}" ] || wb_die "--upload-s3 needs S3_BUCKET."
  command -v aws >/dev/null 2>&1 || wb_die "--upload-s3 needs the aws CLI on PATH."
fi
if [ -n "${GPG_RECIPIENT:-}" ]; then
  command -v gpg >/dev/null 2>&1 || wb_die "GPG_RECIPIENT is set but gpg is not on PATH."
fi

DB_ARRAY=()
IFS=',' read -ra RAW_DBS <<< "$DATABASES"
for db in "${RAW_DBS[@]}"; do
  db="${db//[[:space:]]/}"
  [ -n "$db" ] || continue
  wb_valid_db_name "$db" || wb_die "not a database name: '$db'"
  DB_ARRAY+=("$db")
done
[ "${#DB_ARRAY[@]}" -gt 0 ] || wb_die "no database to back up (DATABASES is empty)."

# --snapshot DATABASE=ID. The identifier ends up on pg_dump's command line,
# so it has to look like one, and the database has to be one of this run's:
# a snapshot given for a database that is not dumped would be a comparison
# its caller believes in and nothing made.
for pair in "${SNAPSHOTS[@]+"${SNAPSHOTS[@]}"}"; do
  [[ "$pair" =~ ^([A-Za-z_][A-Za-z0-9_]*)=([0-9A-Fa-f]+(-[0-9A-Fa-f]+)*)$ ]] \
    || wb_die "--snapshot takes DATABASE=SNAPSHOT_ID, the identifier as pg_export_snapshot() returns it; got: $pair"
  case " ${DB_ARRAY[*]} " in
    *" ${BASH_REMATCH[1]} "*) ;;
    *) wb_die "--snapshot names '${BASH_REMATCH[1]}', which is not one of the databases to back up (${DB_ARRAY[*]})." ;;
  esac
done

# Echo the snapshot identifier given for the database $1, if there is one.
snapshot_for() {
  local pair
  for pair in "${SNAPSHOTS[@]+"${SNAPSHOTS[@]}"}"; do
    if [ "${pair%%=*}" = "$1" ]; then
      printf '%s' "${pair#*=}"
      return 0
    fi
  done
}

mkdir -p "$BACKUP_DIR"
BACKUP_DIR="$(cd "$BACKUP_DIR" && pwd)"
# Retention deletes by age from this directory; never from the root.
[ "$BACKUP_DIR" != "/" ] || wb_die "BACKUP_DIR must not be the root directory."
chmod 700 "$BACKUP_DIR"

if [ "$BACKUP_MODE" = compose ]; then
  cd "$SCRIPT_DIR/.."
fi

echo "=== Wildbox backup ==="
echo "Timestamp:  $TIMESTAMP"
echo "Mode:       $WB_MODE_LABEL"
echo "PostgreSQL: ${DB_ARRAY[*]}"
if [ "${SKIP_REDIS:-false}" = "true" ]; then
  echo "Redis:      SKIPPED (SKIP_REDIS=true)"
else
  echo "Redis:      RDB snapshot of every database"
fi
echo "Backup dir: $BACKUP_DIR"
echo ""

# Everything this run writes, so a failure can take all of it back.
RUN_FILES=()
COMPLETE=false
cleanup() {
  local status=$?
  if [ "$COMPLETE" != true ]; then
    for f in "${RUN_FILES[@]+"${RUN_FILES[@]}"}"; do
      rm -f "$f"
    done
    rm -f "$BACKUP_DIR"/.*_"${TIMESTAMP}".partial "$BACKUP_DIR"/.*_"${TIMESTAMP}".partial.log 2>/dev/null || true
    echo "" >&2
    echo "=== BACKUP FAILED: nothing from this run was kept ===" >&2
    [ "$status" -ne 0 ] || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Encrypt FILE in place when GPG_RECIPIENT is set; echo the resulting name.
finish_file() {
  local file="$1"
  if [ -n "${GPG_RECIPIENT:-}" ]; then
    RUN_FILES+=("${file}.gpg")
    gpg --batch --yes --encrypt --recipient "$GPG_RECIPIENT" \
      --output "${file}.gpg" "$file"
    rm -f "$file"
    file="${file}.gpg"
  fi
  FINISHED="$file"
}

wb_require_postgres

S3_UPLOADS=()
for db in "${DB_ARRAY[@]}"; do
  echo "Backing up database: $db"
  partial="${BACKUP_DIR}/.${db}_${TIMESTAMP}.partial"
  archive="${BACKUP_DIR}/${db}_${TIMESTAMP}.sql"

  dump_args=(-d "$db" --format=custom --compress=9 --no-owner --no-privileges)
  snapshot=$(snapshot_for "$db")
  if [ -n "$snapshot" ]; then
    dump_args+=("--snapshot=$snapshot")
    echo "  from the exported snapshot $snapshot"
  fi
  wb_pg pg_dump "${dump_args[@]}" > "$partial"

  # `gzip -t` only proves the gzip container; ask pg_restore to read the
  # archive's table of contents before calling it a backup.
  toc=$(wb_pg_stdin pg_restore --list < "$partial")
  objects=$(printf '%s\n' "$toc" | grep -c '^[0-9]' || true)
  if [ "$objects" -eq 0 ]; then
    echo "  WARNING: the $db database holds no objects; its archive is empty."
  fi

  RUN_FILES+=("$archive" "${archive}.gz")
  mv "$partial" "$archive"
  gzip -f "$archive"
  gzip -t "${archive}.gz"
  finish_file "${archive}.gz"
  echo "  Created: $FINISHED ($(du -h "$FINISHED" | cut -f1), $objects objects)"
  S3_UPLOADS+=("$FINISHED|postgres-backups/${db}/$(basename "$FINISHED")")
done

if [ "${SKIP_REDIS:-false}" = "true" ]; then
  echo "Redis: SKIPPED (SKIP_REDIS=true). Scan state, playbook run state,"
  echo "  revoked tokens and queued work are NOT in this backup."
else
  echo "Backing up Redis"
  partial="${BACKUP_DIR}/.redis_${TIMESTAMP}.partial"
  snapshot="${BACKUP_DIR}/redis_${TIMESTAMP}.rdb"
  wb_redis_snapshot "$partial"
  RUN_FILES+=("$snapshot" "${snapshot}.gz")
  mv "$partial" "$snapshot"
  gzip -f "$snapshot"
  gzip -t "${snapshot}.gz"
  finish_file "${snapshot}.gz"
  echo "  Created: $FINISHED ($(du -h "$FINISHED" | cut -f1))"
  S3_UPLOADS+=("$FINISHED|redis-backups/$(basename "$FINISHED")")
fi

# The local set is complete from here on: a failed upload must not delete it.
COMPLETE=true

if [ "$UPLOAD_S3" = true ]; then
  echo ""
  echo "Uploading to s3://${S3_BUCKET}"
  for entry in "${S3_UPLOADS[@]}"; do
    if ! aws s3 cp "${entry%%|*}" "s3://${S3_BUCKET}/${entry#*|}" --quiet; then
      echo "ERROR: upload of $(basename "${entry%%|*}") failed. The local backup is complete; the copy in S3 is NOT." >&2
      exit 1
    fi
    echo "  Uploaded: s3://${S3_BUCKET}/${entry#*|}"
  done
fi

# Retention runs only after a complete backup, and only on this script's own
# file names, directly in BACKUP_DIR.
echo ""
echo "Removing backups older than ${BACKUP_RETENTION} days..."
DELETED=$(find "$BACKUP_DIR" -maxdepth 1 -type f \
  \( -name '*_[0-9]*_[0-9]*.sql.gz' -o -name '*_[0-9]*_[0-9]*.sql.gz.gpg' \
     -o -name 'redis_[0-9]*_[0-9]*.rdb.gz' -o -name 'redis_[0-9]*_[0-9]*.rdb.gz.gpg' \) \
  -mtime +"$BACKUP_RETENTION" -print -delete | wc -l | tr -d ' ')
echo "  Removed $DELETED old file(s)"

echo ""
echo "=== Backup complete: ${#DB_ARRAY[@]} database(s)$([ "${SKIP_REDIS:-false}" = "true" ] && echo ", Redis skipped" || echo " and Redis") ==="
