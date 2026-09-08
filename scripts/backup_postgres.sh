#!/usr/bin/env bash
#
# PostgreSQL Backup Script for Wildbox Security Suite
#
# Creates timestamped, compressed, encrypted backups of all PostgreSQL databases.
# Supports retention rotation and optional upload to S3.
#
# Usage:
#   ./backup_postgres.sh                  # Backup with defaults
#   ./backup_postgres.sh --upload-s3      # Backup and upload to S3
#   ./backup_postgres.sh --databases identity,data  # Specific databases
#
# Environment variables:
#   POSTGRES_HOST       (default: wildbox-postgres)
#   POSTGRES_PORT       (default: 5432)
#   POSTGRES_USER       (default: postgres)
#   POSTGRES_PASSWORD   (required)
#   BACKUP_DIR          (default: /backups/postgres)
#   BACKUP_RETENTION    (default: 30 days)
#   GPG_RECIPIENT       (optional, for encryption)
#   S3_BUCKET           (optional, for remote upload)

set -euo pipefail

# Configuration
POSTGRES_HOST="${POSTGRES_HOST:-wildbox-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
BACKUP_DIR="${BACKUP_DIR:-/backups/postgres}"
BACKUP_RETENTION="${BACKUP_RETENTION:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# All three databases scripts/init-databases.sql provisions. This defaulted to
# "identity,data", silently omitting guardian -- eight Django apps' worth of
# assets, vulnerabilities, compliance, remediation and reporting tables
# (WILDBO-DATA-01).
DATABASES="${DATABASES:-identity,data,guardian}"
UPLOAD_S3=false

# Parse arguments
for arg in "$@"; do
  case $arg in
    --upload-s3) UPLOAD_S3=true ;;
    --databases=*) DATABASES="${arg#*=}" ;;
  esac
done

# Verify password is set
if [ -z "${POSTGRES_PASSWORD:-}" ]; then
  echo "ERROR: POSTGRES_PASSWORD environment variable is required"
  exit 1
fi

# Use .pgpass file instead of exporting PGPASSWORD (avoids exposure in /proc)
PGPASS_FILE=$(mktemp)
chmod 600 "$PGPASS_FILE"
echo "${POSTGRES_HOST}:${POSTGRES_PORT}:*:${POSTGRES_USER}:${POSTGRES_PASSWORD}" > "$PGPASS_FILE"
export PGPASSFILE="$PGPASS_FILE"
trap 'rm -f "$PGPASS_FILE"' EXIT

# Validate BACKUP_RETENTION is numeric
if ! [[ "$BACKUP_RETENTION" =~ ^[0-9]+$ ]]; then
  echo "ERROR: BACKUP_RETENTION must be a positive integer, got: $BACKUP_RETENTION"
  exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "=== Wildbox PostgreSQL Backup ==="
echo "Timestamp: $TIMESTAMP"
echo "Host: $POSTGRES_HOST:$POSTGRES_PORT"
echo "Databases: $DATABASES"
echo "Backup dir: $BACKUP_DIR"
echo ""

# Redis holds the only copy of CSPM scan state, responder run state and agents
# task ownership -- nothing used to copy it out at all, so a lost volume lost
# that state permanently (WILDBO-DATA-01).
backup_redis() {
  if [ "${SKIP_REDIS:-false}" = "true" ]; then
    echo "Skipping Redis backup (SKIP_REDIS=true)"
    return 0
  fi
  local host="${REDIS_HOST:-wildbox-redis}"
  local port="${REDIS_PORT:-6379}"
  local out="${BACKUP_DIR}/redis_${TIMESTAMP}.rdb"

  if ! command -v redis-cli >/dev/null 2>&1; then
    echo "  WARNING: redis-cli not found; skipping Redis backup"
    return 0
  fi
  if [ -z "${REDIS_PASSWORD:-}" ]; then
    echo "  WARNING: REDIS_PASSWORD not set; skipping Redis backup"
    return 0
  fi

  echo "Backing up Redis (BGSAVE + dump)"
  redis-cli -h "$host" -p "$port" -a "$REDIS_PASSWORD" --no-auth-warning BGSAVE >/dev/null
  # Wait for the background save to finish before copying.
  for _ in $(seq 1 60); do
    if [ "$(redis-cli -h "$host" -p "$port" -a "$REDIS_PASSWORD" --no-auth-warning INFO persistence \
            | tr -d '\r' | grep '^rdb_bgsave_in_progress:' | cut -d: -f2)" = "0" ]; then
      break
    fi
    sleep 1
  done
  redis-cli -h "$host" -p "$port" -a "$REDIS_PASSWORD" --no-auth-warning --rdb "$out" >/dev/null
  gzip -f "$out"
  echo "  Created: ${out}.gz ($(du -h "${out}.gz" | cut -f1))"
}

# Backup each database
IFS=',' read -ra DB_ARRAY <<< "$DATABASES"
for db in "${DB_ARRAY[@]}"; do
  db=$(echo "$db" | xargs)  # trim whitespace
  BACKUP_FILE="${BACKUP_DIR}/${db}_${TIMESTAMP}.sql.gz"

  echo "Backing up database: $db"

  pg_dump \
    -h "$POSTGRES_HOST" \
    -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" \
    -d "$db" \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    -f "${BACKUP_FILE%.gz}"

  # Compress with gzip
  gzip -f "${BACKUP_FILE%.gz}"

  # Encrypt if GPG recipient is set
  if [ -n "${GPG_RECIPIENT:-}" ]; then
    gpg --batch --yes --encrypt --recipient "$GPG_RECIPIENT" "$BACKUP_FILE"
    rm -f "$BACKUP_FILE"
    BACKUP_FILE="${BACKUP_FILE}.gpg"
    echo "  Encrypted: $BACKUP_FILE"
  fi

  # Show file size
  FILE_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
  echo "  Created: $BACKUP_FILE ($FILE_SIZE)"

  # Upload to S3 if requested
  if [ "$UPLOAD_S3" = true ] && [ -n "${S3_BUCKET:-}" ]; then
    S3_KEY="postgres-backups/${db}/${db}_${TIMESTAMP}.sql.gz"
    if [ -n "${GPG_RECIPIENT:-}" ]; then
      S3_KEY="${S3_KEY}.gpg"
    fi
    aws s3 cp "$BACKUP_FILE" "s3://${S3_BUCKET}/${S3_KEY}" --quiet
    echo "  Uploaded to: s3://${S3_BUCKET}/${S3_KEY}"
  fi
done

backup_redis

# Retention: remove backups older than BACKUP_RETENTION days
echo ""
echo "Cleaning up backups older than ${BACKUP_RETENTION} days..."
# Safety: ensure BACKUP_DIR is an absolute path under expected location
case "$BACKUP_DIR" in
  /backups/*|/tmp/*) ;;
  *) echo "ERROR: BACKUP_DIR must be an absolute path under /backups/ or /tmp/, got: $BACKUP_DIR"; exit 1 ;;
esac
DELETED=$(find "$BACKUP_DIR" \( -name "*.sql.gz*" -o -name "*.rdb.gz" \) -mtime +"$BACKUP_RETENTION" -delete -print | wc -l)
echo "  Removed $DELETED old backup(s)"

# Verify backup integrity (test decompression of latest)
echo ""
echo "Verifying backup integrity..."
for db in "${DB_ARRAY[@]}"; do
  db=$(echo "$db" | xargs)
  LATEST=$(ls -t "${BACKUP_DIR}/${db}_"*.sql.gz 2>/dev/null | head -1 || true)
  if [ -n "$LATEST" ]; then
    if gzip -t "$LATEST" 2>/dev/null; then
      echo "  $db: OK"
    else
      echo "  $db: FAILED (corrupt backup)"
      exit 1
    fi
  fi
done

echo ""
echo "=== Backup complete ==="
