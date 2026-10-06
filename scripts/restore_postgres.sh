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
#   ./restore_postgres.sh --timestamp 20260908_120000 --into-suffix _verify
#   ./restore_postgres.sh --latest --databases identity --dry-run
#   ./restore_postgres.sh --timestamp 20260908_120000 --overwrite-live-databases
#   ./restore_postgres.sh --latest --databases data --overwrite-live-databases
#
# One of three targets has to be named:
#
#   --into-suffix SUFFIX         restore into "<db>SUFFIX" next to the live
#                                databases, which is how the drill in
#                                scripts/verify_restore.sh exercises this
#                                path without touching live data.
#   --dry-run                    only read the archives.
#   --overwrite-live-databases   restore OVER the databases the services use.
#                                Everything written to them since the backup
#                                is lost, and so is every table, view and
#                                sequence made since. Stop the services first.
#
# Without one of them the script refuses and says which databases it would
# have overwritten, from which archives (#723): the destructive form used to
# be the default, one forgotten option away from the harmless one. The flag
# makes it a decision, and keeps it usable from a script: there is no prompt.
#
# --latest restores the newest backup RUN: the archives that carry the
# newest timestamp, which backup_postgres.sh gives every file of one run. If
# that run does not hold every database asked for (it was taken with
# --databases, or a file is missing), the script refuses and says what the
# run holds. It used to take the newest archive of each database on its own,
# so the databases could come from different runs, hours or days apart
# (#740). To restore a run that is not the newest, name it with --timestamp;
# to mix runs on purpose, run the script once per database with --databases
# and --timestamp.
#
# What a restore over a live database leaves (#773): what its archive holds,
# and no other table, view, materialized view or sequence in the schemas the
# archive holds. A relation made after the backup, by the migrations of a
# later release for instance, is in no archive, so pg_restore --clean never
# dropped it: it stayed, and the release that had made it then failed to
# migrate again on `relation ... already exists`; one that depended on a
# restored table (a view on it, a foreign key to it) made the restore fail.
# They are now dropped in the transaction of the restore, with what depends
# on them (DROP ... CASCADE; PostgreSQL's notices name it), and the script
# lists them. It does not touch:
#
#   - what an extension owns;
#   - the relations of a schema the archive does not hold, one made after
#     the backup for instance. If one depends on a restored table, or would
#     go with a relation made after the backup, the restore fails and names
#     it. A foreign key or a column default there that refers to a relation
#     made after the backup goes with that relation;
#   - what is not a relation: a function or a type made after the backup
#     stays, unless it depends on a relation that goes;
#   - a database restored with --into-suffix: one that is already there
#     keeps what the archive does not hold, as before.
#
# What a failed restore leaves (#740):
#
#   - Every archive is read to the end of its table of contents before any
#     database is touched, so an unreadable archive stops the run with
#     nothing restored.
#   - Each database is restored in one transaction. If anything in it fails,
#     PostgreSQL rolls the whole database back to what it was, the relations
#     made after the backup included. It used to run statement by statement
#     and carry on after an error, which left a database with some tables
#     dropped, some reloaded and some rows twice.
#   - The transaction is one stream to psql: BEGIN, the removal above, the
#     archive as SQL, COMMIT. pg_restore first writes that SQL to a file, and
#     the file is used only if pg_restore succeeded and it ends where a
#     complete dump ends, so the stream is whole before the database sees
#     its first statement. A stream that ends early for any other reason has
#     no COMMIT, and a session that ends inside a transaction commits
#     nothing. The script reports a database as restored only when the
#     server has answered after the COMMIT.
#   - The databases are restored one after the other, each in a transaction
#     of its own: PostgreSQL has no transaction that spans databases. If the
#     second of three fails, the first is restored and the other two are as
#     they were. The script says which is which; running the same command
#     again restores all of them, and restoring a database twice is safe.
#
# Room: the work directory, made under TMPDIR (/tmp by default) and removed
# at exit, holds every archive without its outer gzip, which is about the
# size of the backup files, and the SQL of one database at a time, gzipped,
# which is about the size of that database's archive again. Set TMPDIR to a
# disk with room for the backup files plus the largest of them.
#
# Like the backup, it runs pg_restore and psql inside the stack's postgres
# container by default (compose mode) and connects directly with
# BACKUP_MODE=host; see scripts/lib/db_access.sh and backup_postgres.sh for
# the variables (BACKUP_MODE, BACKUP_DIR, DATABASES, POSTGRES_*, ENV_FILE).
# Archives encrypted with GPG_RECIPIENT are decrypted with the local gpg key.
#
# Redis is restored from the redis_<timestamp>.rdb.gz snapshot by
# scripts/restore_redis.sh.

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
OVERWRITE_LIVE=false

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
    --overwrite-live-databases) OVERWRITE_LIVE=true; shift ;;
    -h|--help) sed -n '2,105p' "$0"; exit 0 ;;
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
if [ -n "$INTO_SUFFIX" ] && [ "$OVERWRITE_LIVE" = true ]; then
  echo "ERROR: --into-suffix and --overwrite-live-databases name two different targets; pass one." >&2
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

# The timestamps of the archives of the database $1, oldest first. They are
# read from the file names, which the backup writes, not from modification
# times, which a copy to or from another disk changes.
stamps_of() {
  local file
  for file in "${BACKUP_DIR}/${1}_"[0-9]*.sql.gz*; do
    [ -e "$file" ] || continue
    file="${file##*/"${1}"_}"
    file="${file%%.sql.gz*}"
    [[ "$file" =~ ^[0-9]{8}_[0-9]{6}$ ]] && echo "$file"
  done | sort -u
}

# --latest: one backup run, the newest, for every database asked for.
if [ "$USE_LATEST" = true ]; then
  NEWEST=$(for db in "${DB_ARRAY[@]}"; do stamps_of "$db"; done | sort -u | tail -n 1)
  [ -n "$NEWEST" ] || wb_die "no backup found for ${DB_ARRAY[*]} in $BACKUP_DIR"
  MISSING=()
  for db in "${DB_ARRAY[@]}"; do
    grep -qx "$NEWEST" <<< "$(stamps_of "$db")" || MISSING+=("$db")
  done
  if [ "${#MISSING[@]}" -gt 0 ]; then
    # The newest run that does hold all of them, if there is one.
    COMPLETE=$(stamps_of "${DB_ARRAY[0]}")
    for db in "${DB_ARRAY[@]}"; do
      COMPLETE=$(comm -12 <(printf '%s\n' "$COMPLETE") <(stamps_of "$db"))
    done
    COMPLETE=$(printf '%s\n' "$COMPLETE" | tail -n 1)
    {
      echo "REFUSING --latest: the newest backup run, $NEWEST, does not hold every"
      echo "database asked for."
      echo ""
      for db in "${DB_ARRAY[@]}"; do
        if grep -qx "$NEWEST" <<< "$(stamps_of "$db")"; then
          printf '    %-12s %s\n' "$db" "${db}_${NEWEST}"
        else
          own=$(stamps_of "$db" | tail -n 1)
          if [ -n "$own" ]; then
            printf '    %-12s not in this run; its newest archive is from %s\n' "$db" "$own"
          else
            printf '    %-12s not in this run, and in no other\n' "$db"
          fi
        fi
      done
      echo ""
      echo "--latest restores one run, so that the databases are from the same"
      echo "moment; the newest archive of each would mix runs. Nothing was changed."
      echo "Name what to restore:"
      echo ""
      if [ -n "$COMPLETE" ]; then
        echo "    --timestamp $COMPLETE   the newest run that holds all of them"
      else
        echo "    (no run in $BACKUP_DIR holds all of them)"
      fi
      echo "    --databases <list>            only the databases the newest run holds"
      echo "    --timestamp <stamp> --databases <database>, once per database,"
      echo "                                  to mix runs on purpose"
    } >&2
    exit 1
  fi
  TIMESTAMP="$NEWEST"
fi

# Which archive each database would be restored from, before anything else:
# a refusal names them, and a missing one stops the run before the first
# database is touched.
ARCHIVES=()
for db in "${DB_ARRAY[@]}"; do
  # shellcheck disable=SC2012
  ARCHIVE=$(ls "${BACKUP_DIR}/${db}_${TIMESTAMP}.sql.gz"* 2>/dev/null | head -1 || true)
  if [ -z "$ARCHIVE" ]; then
    echo "ERROR: no backup found for '$db' in $BACKUP_DIR" >&2
    exit 1
  fi
  ARCHIVES+=("$ARCHIVE")
done

# Restoring over the live databases is the one form that destroys data, so
# it is never what a missing option means.
if [ -z "$INTO_SUFFIX" ] && [ "$DRY_RUN" != true ] && [ "$OVERWRITE_LIVE" != true ]; then
  {
    echo "REFUSING to restore over the live databases without --overwrite-live-databases."
    echo ""
    echo "This would restore into the databases the services use"
    echo "(${WB_MODE_LABEL}):"
    echo ""
    for i in "${!DB_ARRAY[@]}"; do
      printf '    %-12s from %s\n' "${DB_ARRAY[$i]}" "$(basename "${ARCHIVES[$i]}")"
    done
    echo ""
    echo "It drops every object an archive holds and loads it as it was when the"
    echo "backup was taken, and drops the tables, views and sequences made since:"
    echo "everything written to these databases since then is lost."
    echo "Nothing was changed. Name the target:"
    echo ""
    echo "    --into-suffix _check         restore into ${DB_ARRAY[0]}_check and so on,"
    echo "                                 next to the live databases"
    echo "    --dry-run                    only read the archives"
    echo "    --overwrite-live-databases   restore over the live databases; stop"
    echo "                                 the services that use them first"
  } >&2
  exit 2
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
elif [ "$OVERWRITE_LIVE" = true ]; then
  echo "Target:     the LIVE databases (--overwrite-live-databases)"
else
  echo "Target:     none (dry run)"
fi
[ "$DRY_RUN" = true ] && echo "MODE:       dry run, nothing will be written"
echo ""

wb_require_postgres

# First every archive, then every database: an archive that is not a
# readable pg_dump stops the run before the first database is touched. This
# is also the check `gzip -t` could not make.
for i in "${!DB_ARRAY[@]}"; do
  db="${DB_ARRAY[$i]}"
  ARCHIVE="${ARCHIVES[$i]}"
  STAGED="$WORKDIR/${db}.dump"
  if [[ "$ARCHIVE" == *.gpg ]]; then
    gpg --batch --yes --decrypt "$ARCHIVE" > "${STAGED}.gz"
    gunzip -f "${STAGED}.gz"
  else
    gunzip -c "$ARCHIVE" > "$STAGED"
  fi
  if ! wb_pg_stdin pg_restore --list < "$STAGED" > "$WORKDIR/${db}.toc" 2>"$WORKDIR/${db}.err"; then
    echo "FAILED: $(basename "$ARCHIVE") is not a readable pg_dump custom archive" >&2
    cat "$WORKDIR/${db}.err" >&2
    echo "No database was touched." >&2
    exit 1
  fi
  echo "$(basename "$ARCHIVE"): archive readable, $(grep -c '^[0-9]' "$WORKDIR/${db}.toc" || true) objects"
  if [ "$DRY_RUN" = true ]; then
    echo "  dry run: would restore into '${db}${INTO_SUFFIX}'"
  fi
done
if [ "$DRY_RUN" = true ]; then
  echo ""
  echo "=== Dry run complete: nothing was written ==="
  exit 0
fi

# Which databases came out how, for the operator when one fails.
RESTORED=()
report_failure() {
  local failed="$1" i seen=false left=()
  for i in "${!DB_ARRAY[@]}"; do
    if [ "$seen" = true ]; then
      left+=("${DB_ARRAY[$i]}${INTO_SUFFIX}")
    elif [ "${DB_ARRAY[$i]}${INTO_SUFFIX}" = "$failed" ]; then
      seen=true
    fi
  done
  {
    echo ""
    echo "=== Restore FAILED ==="
    echo "  restored from the backup: ${RESTORED[*]:-none}"
    echo "  failed, as it was before: $failed"
    echo "  not attempted, unchanged: ${left[*]:-none}"
    echo "Each database is restored in a transaction of its own; no transaction"
    echo "spans them. Fix the cause and run the same command again: it restores"
    echo "all of them, and restoring a database twice is safe."
  } >&2
}

# archive_as_sql DB: write the staged archive of DB as SQL, gzipped, to
# $WORKDIR/DB.sql.gz. It fails unless pg_restore succeeded AND the file ends
# where a complete dump ends: an exit status alone would let through a file
# that was cut short on its way to the disk.
archive_as_sql() {
  local sql="$WORKDIR/${1}.sql.gz" last
  wb_pg_stdin pg_restore --no-owner --no-privileges --clean --if-exists -f - \
    < "$WORKDIR/${1}.dump" | gzip -1 > "$sql" || return 1
  last=$(gunzip -c "$sql" | tail -n 12) || return 1
  grep -qx -- '-- PostgreSQL database dump complete' <<< "$last"
}

# removal_sql DB: the statements that drop the relations of the database
# the archive of DB does not hold (#773). The archive's table of contents
# goes to the server as data, and the server compares it with its catalog and
# quotes the names: no identifier is put together in this shell.
#
# A relation is one the archive holds when the table of contents has an
# entry of its kind, schema and name; a schema is one the archive holds when
# the table of contents has the schema itself or a relation in it. What an
# extension owns is left alone, and so is a sequence that belongs to a
# column, which goes with its table.
#
# DROP ... CASCADE takes what depends on a relation with it. That is wanted
# for a restored table that came to refer to a later one, and it must not
# reach a schema the archive does not hold: if a relation of such a schema
# is gone after the drops, the transaction fails and names it.
removal_sql() {
  cat <<'SQL' || return 1
CREATE TEMP TABLE wildbox_restore_toc (entry text) ON COMMIT DROP;
COPY pg_temp.wildbox_restore_toc (entry) FROM STDIN;
SQL
  # COPY's text format: a backslash and a tab are written escaped.
  sed -e '/^[0-9]/!d' -e 's/\\/\\\\/g' -e $'s/\t/\\\\t/g' "$WORKDIR/${1}.toc" || return 1
  cat <<'SQL' || return 1
\.
-- The relations the archive does not hold: to drop where it holds their
-- schema, to keep where it does not.
CREATE TEMP TABLE wildbox_restore_relation ON COMMIT DROP AS
WITH toc AS (
  -- An entry reads "<id>; <catalog> <oid> <KIND> <schema> <name> <owner>":
  -- without its three numbers it begins with the kind, the schema, the name.
  SELECT pg_catalog.regexp_replace(entry, '^[0-9]+; [0-9]+ [0-9]+ ', '') AS entry
  FROM pg_temp.wildbox_restore_toc
), relation AS (
  SELECT c.oid AS relid, n.nspname, c.relname,
         CASE c.relkind
           WHEN 'v' THEN 'VIEW'
           WHEN 'm' THEN 'MATERIALIZED VIEW'
           WHEN 'S' THEN 'SEQUENCE'
           WHEN 'f' THEN 'FOREIGN TABLE'
           ELSE 'TABLE'
         END AS kind
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
    AND n.nspname !~ '^pg_'
    AND n.nspname <> 'information_schema'
    AND NOT EXISTS (
      SELECT FROM pg_catalog.pg_depend d
      WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
        AND d.objid = c.oid
        AND (d.deptype = 'e'
             OR (c.relkind = 'S' AND d.deptype IN ('a', 'i')
                 AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass)))
)
SELECT r.relid, r.kind, r.nspname, r.relname,
       EXISTS (
         SELECT FROM toc, pg_catalog.unnest(ARRAY[
           'SCHEMA -', 'TABLE', 'VIEW', 'MATERIALIZED VIEW', 'SEQUENCE', 'FOREIGN TABLE'
         ]) AS held (kind)
         WHERE pg_catalog.strpos(toc.entry, held.kind || ' ' || r.nspname || ' ') = 1
       ) AS schema_held
FROM relation r
WHERE NOT EXISTS (
        SELECT FROM toc
        WHERE pg_catalog.strpos(
          toc.entry, r.kind || ' ' || r.nspname || ' ' || r.relname || ' ') = 1);
DO $wildbox$
DECLARE
  extra record;
  lost text;
BEGIN
  FOR extra IN
    SELECT * FROM pg_temp.wildbox_restore_relation WHERE schema_held
  LOOP
    -- One dropped with another before its turn is not there any more.
    IF EXISTS (SELECT FROM pg_catalog.pg_class c WHERE c.oid = extra.relid) THEN
      EXECUTE pg_catalog.format(
        'DROP %s %I.%I CASCADE', extra.kind, extra.nspname, extra.relname);
    END IF;
  END LOOP;
  SELECT pg_catalog.string_agg(
           pg_catalog.format('%s %I.%I', r.kind, r.nspname, r.relname), ', ')
  INTO lost
  FROM pg_temp.wildbox_restore_relation r
  WHERE NOT r.schema_held
    AND NOT EXISTS (SELECT FROM pg_catalog.pg_class c WHERE c.oid = r.relid);
  IF lost IS NOT NULL THEN
    RAISE EXCEPTION
      'removing the relations made after the backup would also drop, from a schema the archive does not hold: %', lost
      USING HINT = 'A restore leaves such a schema alone. Drop what is named, or its schema, and run the restore again.';
  END IF;
END
$wildbox$;
SELECT 'wildbox-restore: removed ' || kind || ' '
       || pg_catalog.format('%I.%I', nspname, relname)
FROM pg_temp.wildbox_restore_relation
WHERE schema_held
ORDER BY 1;
SQL
}

# What psql prints last when the transaction of a restore has committed. It
# is read from a setting made inside the transaction, which the session
# keeps only if the transaction commits: a COMMIT that ended a failed
# transaction is a rollback, and prints nothing of the kind.
COMMITTED="wildbox-restore: committed"

# restore_stream DB: the one transaction that restores DB, for psql's stdin.
# The COMMIT is written only after the SQL of the archive has been written
# to its end.
restore_stream() {
  printf 'BEGIN;\n' || return 1
  if [ "$OVERWRITE_LIVE" = true ]; then
    removal_sql "$1" || return 1
  fi
  gunzip -c "$WORKDIR/${1}.sql.gz" || return 1
  printf '%s\n' \
    "SET wildbox.restore = 'committed';" \
    "COMMIT;" \
    "SELECT 'wildbox-restore: ' || pg_catalog.current_setting('wildbox.restore', true);"
}

echo ""
for i in "${!DB_ARRAY[@]}"; do
  db="${DB_ARRAY[$i]}"
  TARGET_DB="${db}${INTO_SUFFIX}"
  echo "Restoring $db from $(basename "${ARCHIVES[$i]}")"

  # The whole archive as SQL, before the database is touched: an archive
  # whose data cannot be read stops here.
  if ! archive_as_sql "$db"; then
    echo "  FAILED: $(basename "${ARCHIVES[$i]}") could not be read to its end; '$TARGET_DB' was not touched" >&2
    report_failure "$TARGET_DB"
    exit 1
  fi

  created=false
  exists=$(wb_psql postgres "SELECT 1 FROM pg_database WHERE datname = '${TARGET_DB}'")
  if [ "$exists" = "1" ]; then
    echo "  database '$TARGET_DB' already exists, restoring into it"
  else
    wb_psql postgres "CREATE DATABASE \"${TARGET_DB}\""
    created=true
  fi

  # One transaction: everything that is dropped and loaded, or nothing.
  # ON_ERROR_STOP ends psql at the first error instead of carrying on with
  # the statements after it. psql is not given --single-transaction: it
  # would send a COMMIT of its own when its input ends, wherever that is.
  # Its exit status is not enough either: it is 0 for an input that ended
  # before the COMMIT.
  OUT="$WORKDIR/${db}.out"
  if ! restore_stream "$db" \
        | wb_pg_stdin psql -d "$TARGET_DB" -v ON_ERROR_STOP=1 -X -q -tA > "$OUT" \
      || ! grep -qx -- "$COMMITTED" "$OUT"; then
    echo "  FAILED: the restore of '$TARGET_DB' was rolled back" >&2
    if [ "$created" = true ]; then
      # It did not exist before this run, and it holds nothing.
      wb_psql postgres "DROP DATABASE IF EXISTS \"${TARGET_DB}\"" >/dev/null 2>&1 || true
    fi
    report_failure "$TARGET_DB"
    exit 1
  fi
  RESTORED+=("$TARGET_DB")
  rm -f "$WORKDIR/${db}.sql.gz"

  REMOVED=$(sed -n 's/^wildbox-restore: removed /    /p' "$OUT")
  if [ -n "$REMOVED" ]; then
    echo "  removed, made after the backup (the archive does not hold them):"
    printf '%s\n' "$REMOVED"
  fi

  COUNT=$(wb_psql "$TARGET_DB" \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
  echo "  restored into '$TARGET_DB': $COUNT tables"
done

echo ""
echo "=== Restore complete ==="
