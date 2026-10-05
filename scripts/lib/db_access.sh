# shellcheck shell=bash
#
# How backup_postgres.sh, restore_postgres.sh and verify_restore.sh reach
# PostgreSQL and Redis. Sourced, never executed.
#
# Two modes (BACKUP_MODE):
#
#   compose  The default. pg_dump, pg_restore, psql and redis-cli run inside
#            the stack's own containers through `docker compose exec`, so the
#            host needs nothing but Docker: no published database port, no
#            client tools, no POSTGRES_PASSWORD in the environment. PostgreSQL
#            is reached over the container's local socket with the
#            container's own POSTGRES_USER and POSTGRES_PASSWORD. `docker
#            compose` reads COMPOSE_FILE and COMPOSE_PROJECT_NAME itself, so
#            set them the way you start the stack.
#
#   host     For a database this machine reaches directly: an external or
#            managed PostgreSQL, or the `backup` Compose profile, which runs
#            on the Compose network. Needs pg_dump, pg_restore and psql (and
#            redis-cli unless SKIP_REDIS=true) on PATH, POSTGRES_HOST and
#            POSTGRES_PASSWORD.
#
# With BACKUP_MODE unset, host mode is chosen when POSTGRES_HOST is set and
# compose mode otherwise.
#
# wb_init_mode sets BACKUP_MODE, WB_MODE_LABEL (for the caller's banner) and,
# in compose mode, WB_COMPOSE (the `docker compose` command line).
#
# No secret is ever printed or put in an argument list: argv is readable by
# every local user through ps. Passwords travel in the environment of the
# one child process that needs them, or over its stdin.

wb_die() {
  echo "ERROR: $*" >&2
  exit 1
}

# Database names end up in file names and in SQL identifiers.
wb_valid_db_name() {
  [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
}

# shellcheck disable=SC2034  # WB_MODE_LABEL is read by the sourcing script
wb_init_mode() {
  if [ -z "${BACKUP_MODE:-}" ]; then
    if [ -n "${POSTGRES_HOST:-}" ]; then
      BACKUP_MODE=host
    else
      BACKUP_MODE=compose
    fi
  fi

  case "$BACKUP_MODE" in
    compose)
      POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"
      REDIS_SERVICE="${REDIS_SERVICE:-wildbox-redis}"
      command -v docker >/dev/null 2>&1 \
        || wb_die "docker is not on PATH. Compose mode runs the database tools inside the stack's containers; for a database reached directly, set BACKUP_MODE=host."
      WB_COMPOSE=(docker compose)
      if [ -n "${ENV_FILE:-}" ]; then
        WB_COMPOSE+=(--env-file "$ENV_FILE")
      fi
      WB_MODE_LABEL="compose (docker compose exec ${POSTGRES_SERVICE})"
      ;;
    host)
      POSTGRES_HOST="${POSTGRES_HOST:-wildbox-postgres}"
      POSTGRES_PORT="${POSTGRES_PORT:-5432}"
      POSTGRES_USER="${POSTGRES_USER:-postgres}"
      [ -n "${POSTGRES_PASSWORD:-}" ] \
        || wb_die "host mode needs POSTGRES_PASSWORD in the environment."
      local tool
      for tool in pg_dump pg_restore psql; do
        command -v "$tool" >/dev/null 2>&1 \
          || wb_die "host mode needs $tool on PATH (the PostgreSQL client tools, same major version as the server)."
      done
      WB_MODE_LABEL="host (${POSTGRES_HOST}:${POSTGRES_PORT})"
      ;;
    *)
      wb_die "BACKUP_MODE must be 'compose' or 'host', got: $BACKUP_MODE"
      ;;
  esac
}

# Exit unless the named Compose service has a running container.
wb_require_service() {
  local id
  id=$("${WB_COMPOSE[@]}" ps --status running -q "$1" </dev/null) \
    || wb_die "docker compose could not list the '$1' service. Check COMPOSE_FILE, COMPOSE_PROJECT_NAME and the env file."
  [ -n "$id" ] \
    || wb_die "the '$1' service is not running in this Compose project. Start the stack, or set COMPOSE_FILE and COMPOSE_PROJECT_NAME to the ones it was started with."
}

wb_require_postgres() {
  if [ "$BACKUP_MODE" = compose ]; then
    wb_require_service "$POSTGRES_SERVICE"
  fi
}

# wb_pg_stdin TOOL [ARGS...]: run pg_dump, pg_restore or psql against the
# server, with this shell's stdin and stdout. The connection options are
# added here; the caller passes everything else.
wb_pg_stdin() {
  local tool="$1"
  shift
  if [ "$BACKUP_MODE" = compose ]; then
    # Expanded inside the container: its own user and password. The local
    # socket is `trust` in the official image, and PGPASSWORD covers a
    # pg_hba.conf that asks for one.
    # shellcheck disable=SC2016
    "${WB_COMPOSE[@]}" exec -T "$POSTGRES_SERVICE" sh -c '
      tool=$1
      shift
      PGPASSWORD="${POSTGRES_PASSWORD:-}" exec "$tool" -U "${POSTGRES_USER:-postgres}" "$@"
    ' sh "$tool" "$@"
  else
    PGPASSWORD="$POSTGRES_PASSWORD" "$tool" \
      -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -w "$@"
  fi
}

# The same with stdin closed, so a call inside a loop cannot eat the loop's
# input (`docker compose exec -T` forwards stdin).
wb_pg() {
  wb_pg_stdin "$@" </dev/null
}

# wb_psql DATABASE SQL: one statement, unaligned tuples-only output.
wb_psql() {
  wb_pg psql -d "$1" -v ON_ERROR_STOP=1 -X -q -tA -c "$2"
}

# Echo the Redis password without a trailing newline: REDIS_PASSWORD, or in
# compose mode the value in the env file Compose reads (the Redis container
# does not carry it in its environment). Exit 1 when there is none.
wb_redis_password() {
  if [ -n "${REDIS_PASSWORD:-}" ]; then
    printf '%s' "$REDIS_PASSWORD"
    return 0
  fi
  [ "$BACKUP_MODE" = compose ] || return 1
  local file="${ENV_FILE:-.env}" value
  [ -f "$file" ] || return 1
  # The last assignment wins, as it does for Compose.
  value=$(sed -n 's/^REDIS_PASSWORD=//p' "$file" | tail -n 1)
  value="${value%$'\r'}"
  case "$value" in
    \"*\") value="${value#\"}"; value="${value%\"}" ;;
    \'*\') value="${value#\'}"; value="${value%\'}" ;;
  esac
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

# wb_redis_snapshot FILE: write a point-in-time RDB snapshot of every Redis
# database to FILE. redis-cli asks the server for a replication-style dump,
# so nothing has to be copied out of the data volume.
wb_redis_snapshot() {
  local out="$1" password status=0
  password=$(wb_redis_password) \
    || wb_die "no Redis password: set REDIS_PASSWORD (in compose mode it is also read from the stack's env file, ENV_FILE, default .env), or SKIP_REDIS=true to leave Redis out."
  if [ "$BACKUP_MODE" = compose ]; then
    wb_require_service "$REDIS_SERVICE"
    # The password goes over stdin and becomes REDISCLI_AUTH inside the
    # container; `--rdb -` writes the snapshot to stdout.
    # shellcheck disable=SC2016
    printf '%s\n' "$password" | "${WB_COMPOSE[@]}" exec -T "$REDIS_SERVICE" sh -c '
      IFS= read -r REDISCLI_AUTH
      export REDISCLI_AUTH
      exec redis-cli --rdb -
    ' > "$out" 2> "${out}.log" || status=$?
  else
    command -v redis-cli >/dev/null 2>&1 \
      || wb_die "host mode needs redis-cli on PATH to back up Redis (or SKIP_REDIS=true to leave Redis out)."
    REDISCLI_AUTH="$password" redis-cli \
      -h "${REDIS_HOST:-wildbox-redis}" -p "${REDIS_PORT:-6379}" \
      --rdb "$out" > "${out}.log" 2>&1 </dev/null || status=$?
  fi
  # redis-cli narrates the transfer; it matters only when it failed. A
  # refused password can also end in a zero exit status with an error where
  # the snapshot should be, so check for the RDB magic string as well.
  if [ "$status" -ne 0 ] || [ "$(head -c 5 "$out" 2>/dev/null)" != "REDIS" ]; then
    cat "${out}.log" >&2 2>/dev/null || true
    rm -f "${out}.log"
    wb_die "Redis did not return an RDB snapshot."
  fi
  rm -f "${out}.log"
}
