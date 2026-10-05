#!/usr/bin/env bash
#
# Secret rotation for the Wildbox Security Suite.
#
# SECURITY.md advises rotating JWT_SECRET_KEY every 90 days and rotating API keys
# on security events, and nothing implemented either: no script, no runbook, no
# re-key path, and no way to rotate GATEWAY_INTERNAL_SECRET without a window in
# which half the services hold the old value and reject the other half
# (WILDBO-SEC-04).
#
# It also matters WHICH secret you rotate. Stored API-key digests are HMACs
# keyed by API_KEY_HASH_SECRET, and identity used to fall back to
# JWT_SECRET_KEY because compose never passed API_KEY_HASH_SECRET to it, so
# rotating the JWT key invalidated every API key in the database
# (WILDBO-SEC-01, #648). This script refuses to rotate the JWT key until
# identity actually receives a separate API_KEY_HASH_SECRET: .env sets it,
# `docker compose config` passes it to identity, and the running identity
# container (if any) has it.
#
# On an existing deployment, seed API_KEY_HASH_SECRET with the current
# JWT_SECRET_KEY ONCE, before identity starts with it (`--init`, or
# `make init-api-key-hash`). The digests stored so far were keyed by that
# value, so they keep matching.
#
# POSTGRES_PASSWORD is the one secret that lives in two places: in the
# running PostgreSQL server, and in .env, where every service's connection
# string embeds it. Rotating it changes both or neither (#649): the script
# needs the stack running, sets the new password in the server, rewrites
# POSTGRES_PASSWORD and every connection string in .env that points at the
# stack's postgres service, and checks that the server accepts the new
# password. If a step fails it restores .env and the server's old password.
#
# Usage:
#   ./scripts/rotate_secrets.sh --list
#   ./scripts/rotate_secrets.sh --secret GATEWAY_INTERNAL_SECRET
#   ./scripts/rotate_secrets.sh --secret JWT_SECRET_KEY
#   ./scripts/rotate_secrets.sh --secret POSTGRES_PASSWORD
#   ./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET --init
#
# The compose checks use the files docker compose would use by default; set
# COMPOSE_FILE to match how you start the stack, for example
# COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml. ENV_FILE names the
# env file (default .env); POSTGRES_SERVICE the compose service that runs
# PostgreSQL (default postgres). No secret value is ever printed, and none is
# passed in an argument list.

set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE="${ENV_FILE:-.env}"
PG_SERVICE="${POSTGRES_SERVICE:-postgres}"
SECRET=""
INIT=false
LIST=false

while [ $# -gt 0 ]; do
  case "$1" in
    --secret) SECRET="$2"; shift 2 ;;
    --secret=*) SECRET="${1#*=}"; shift ;;
    --init) INIT=true; shift ;;
    --list) LIST=true; shift ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

ROTATABLE="JWT_SECRET_KEY GATEWAY_INTERNAL_SECRET API_KEY API_KEY_HASH_SECRET CSPM_CREDENTIAL_KEY REDIS_PASSWORD POSTGRES_PASSWORD NEXTAUTH_SECRET"

if [ "$LIST" = true ]; then
  cat <<'LIST'
Rotatable secrets, what reads each one, and what rotating it costs:

  GATEWAY_INTERNAL_SECRET  The gateway sends it and every backend compares it
                           with its own value. Recreate them together: until
                           all hold the new value, requests between a
                           recreated and a not-yet-recreated container get
                           403.
  JWT_SECRET_KEY           identity signs session tokens with it. Every
                           session ends (users log in again). Refused until
                           identity receives a separate API_KEY_HASH_SECRET.
  API_KEY_HASH_SECRET      identity keys stored API-key digests with it.
                           Rotating it invalidates every stored API key. On
                           an existing deployment seed it ONCE with --init
                           (copies the current JWT_SECRET_KEY) before identity
                           uses it.
  API_KEY                  The tools containers (api, tools-worker,
                           tools-flower) refuse to start without it. It is
                           not accepted as a credential, so no client is
                           affected.
  CSPM_CREDENTIAL_KEY      cspm and cspm-worker encrypt the cloud credentials
                           of pending scans with it. Scans in flight can no
                           longer be decrypted and must be submitted again.
  REDIS_PASSWORD           Redis and every service that uses it are recreated
                           together; the data survives. A Redis URL you
                           override in .env is not rewritten.
  POSTGRES_PASSWORD        Changed in the running server and in every
                           connection string in .env, together. Needs the
                           stack running. Services keep their open
                           connections and must be recreated to open new ones.
  NEXTAUTH_SECRET          Passed to the dashboard container; nothing reads
                           it. Rotating it has no effect.
LIST
  exit 0
fi

if [ -z "$SECRET" ]; then
  echo "ERROR: pass --secret <NAME>, or --list to see the options" >&2
  exit 2
fi
if ! echo "$ROTATABLE" | tr ' ' '\n' | grep -qx "$SECRET"; then
  echo "ERROR: '$SECRET' is not a rotatable secret. Try --list." >&2
  exit 2
fi
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Run 'make generate-secrets' first." >&2
  exit 1
fi

if [ "$INIT" = true ] && [ "$SECRET" != "API_KEY_HASH_SECRET" ]; then
  echo "ERROR: --init applies to API_KEY_HASH_SECRET only" >&2
  exit 2
fi

compose() {
  docker compose --env-file "$ENV_FILE" "$@"
}

# Exit 0 when the variable named by $1 is non-empty in the environment of
# identity as `docker compose config` renders it. The rendered config holds
# every secret, so it goes straight into python and is never printed.
compose_passes_to_identity() {
  compose config --format json 2>/dev/null \
    | VAR="$1" python3 -c '
import json, os, sys
try:
    env = json.load(sys.stdin)["services"]["identity"].get("environment") or {}
except (ValueError, KeyError, TypeError):
    sys.exit(1)
if isinstance(env, list):
    env = dict(item.split("=", 1) for item in env if "=" in item)
sys.exit(0 if (env.get(os.environ["VAR"]) or "").strip() else 1)
'
}

# Exit 0 when the identity container is not running, or when it is and has
# the variable named by $1 set. Checked inside the container; nothing is
# printed.
running_identity_has() {
  local id
  id=$(compose ps --status running -q identity 2>/dev/null || true)
  if [ -z "$id" ]; then
    echo "identity is not running; checked the compose configuration only."
    return 0
  fi
  compose exec -T identity python -c \
    "import os, sys; sys.exit(0 if os.environ.get('$1', '').strip() else 1)" \
    >/dev/null 2>&1
}

refuse_jwt_rotation() {
  cat >&2 <<MSG
REFUSING to rotate JWT_SECRET_KEY: $1

Unless identity receives a separate API_KEY_HASH_SECRET, it keys stored
API-key digests with JWT_SECRET_KEY, so rotating the JWT key now would
silently invalidate every API key in the database with no way to bring them
back (WILDBO-SEC-01, #648).

On an existing deployment, seed it with the current JWT key, then recreate
identity with the release that passes it (see UPGRADING.md):

    ./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET --init
    docker compose up -d identity

Existing API keys keep working, and the two secrets can then be rotated
independently. Set COMPOSE_FILE if you start the stack with an overlay.
MSG
  exit 1
}

# Guard the coupling described above. Trusting .env alone is not enough:
# generate_secrets.py always writes API_KEY_HASH_SECRET, while identity did
# not receive it, so a check of .env passed on every deployment (#648).
if [ "$SECRET" = "JWT_SECRET_KEY" ]; then
  if ! grep -qE '^API_KEY_HASH_SECRET=.+' "$ENV_FILE"; then
    refuse_jwt_rotation "API_KEY_HASH_SECRET is not set in $ENV_FILE."
  fi
  if ! command -v docker >/dev/null 2>&1; then
    refuse_jwt_rotation "docker is not available, so it cannot be verified that identity receives API_KEY_HASH_SECRET."
  fi
  if ! compose_passes_to_identity API_KEY_HASH_SECRET; then
    refuse_jwt_rotation "the compose configuration does not pass API_KEY_HASH_SECRET to identity."
  fi
  if ! running_identity_has API_KEY_HASH_SECRET; then
    refuse_jwt_rotation "the running identity container does not have API_KEY_HASH_SECRET; recreate it first (docker compose up -d identity)."
  fi
fi

if [ "$SECRET" = "API_KEY_HASH_SECRET" ] && [ "$INIT" = true ]; then
  # Read without echoing; compared and written by python, never printed.
  if ENV_FILE="$ENV_FILE" python3 - <<'PY'
import os, re, sys
values = {}
for line in open(os.environ["ENV_FILE"], encoding="utf-8"):
    m = re.match(r"^(JWT_SECRET_KEY|API_KEY_HASH_SECRET)=(.*)$", line.rstrip("\n"))
    if m and m.group(1) not in values:
        values[m.group(1)] = m.group(2)
jwt = values.get("JWT_SECRET_KEY", "")
sys.exit(0 if jwt and values.get("API_KEY_HASH_SECRET") == jwt else 1)
PY
  then
    echo "API_KEY_HASH_SECRET already equals JWT_SECRET_KEY in $ENV_FILE; nothing to do."
    exit 0
  fi
fi

# --- PostgreSQL --------------------------------------------------------------

refuse_postgres_rotation() {
  cat >&2 <<MSG
REFUSING to rotate POSTGRES_PASSWORD: $1

The password lives in the running PostgreSQL server and in the connection
strings in $ENV_FILE. Changing only one of them locks every service out at
its next restart (#649), so this rotation changes both or neither, and it
needs the '$PG_SERVICE' service running. Nothing was changed.

Start the stack and run this again. Set COMPOSE_FILE (and
COMPOSE_PROJECT_NAME, if you use one) the way you start the stack, and
POSTGRES_SERVICE if PostgreSQL runs under another service name.
MSG
  exit 1
}

# SQL on stdin, run as the postgres container's own superuser over its local
# socket. psql reads the statements from stdin, so they are in no argument
# list; -q and no echo flag keep them out of the output.
pg_sql() {
  # shellcheck disable=SC2016
  compose exec -T "$PG_SERVICE" sh -c \
    'PGPASSWORD="${POSTGRES_PASSWORD:-}" exec psql -U "${POSTGRES_USER:-postgres}" -d postgres -v ON_ERROR_STOP=1 -X -q -tA -f -'
}

# Exit 0 when the server accepts the password on stdin for role $1 over TCP.
# The connection goes to the container's own network address, not to
# 127.0.0.1 or the socket, which the image's pg_hba.conf trusts without a
# password.
pg_accepts_password() {
  # shellcheck disable=SC2016
  [ "$(compose exec -T "$PG_SERVICE" sh -c '
    IFS= read -r PGPASSWORD
    export PGPASSWORD
    exec psql -h "$(hostname -i | cut -d" " -f1)" -U "$1" -d postgres -w -X -q -tA -c "SELECT 1"
  ' sh "$1" 2>/dev/null)" = "1" ]
}

# ALTER ROLE for role $1 on stdout. The password is sent as a SCRAM-SHA-256
# verifier computed here ($2 = "new": from VALUE in the environment), or as
# the verifier the server held before ($2 = "old": from OLD_VERIFIER), so the
# plaintext is never in a statement the server could log.
alter_role_sql() {
  # shellcheck disable=SC2016
  ROLE="$1" MODE="$2" python3 -c '
import base64, hashlib, hmac, os

role = os.environ["ROLE"]
if os.environ["MODE"] == "new":
    password = os.environ["VALUE"].encode()
    salt, rounds = os.urandom(16), 4096
    salted = hashlib.pbkdf2_hmac("sha256", password, salt, rounds)
    stored = hashlib.sha256(hmac.new(salted, b"Client Key", hashlib.sha256).digest()).digest()
    server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda raw: base64.b64encode(raw).decode()
    verifier = f"SCRAM-SHA-256${rounds}:{b64(salt)}${b64(stored)}:{b64(server)}"
else:
    verifier = os.environ["OLD_VERIFIER"]
literal = "NULL" if not verifier else "\x27" + verifier.replace("\x27", "\x27\x27") + "\x27"
print(f"ALTER ROLE \"{role}\" PASSWORD {literal};")
'
}

PG_ROLE=""
OLD_VERIFIER=""
postgres_preflight() {
  command -v docker >/dev/null 2>&1 \
    || refuse_postgres_rotation "docker is not available."
  local id
  id=$(compose ps --status running -q "$PG_SERVICE" 2>/dev/null || true)
  [ -n "$id" ] \
    || refuse_postgres_rotation "the '$PG_SERVICE' service is not running in this Compose project."

  PG_ROLE=$(sed -n 's/^POSTGRES_USER=//p' "$ENV_FILE" | tail -n 1)
  PG_ROLE="${PG_ROLE:-postgres}"
  [[ "$PG_ROLE" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
    || refuse_postgres_rotation "POSTGRES_USER in $ENV_FILE is not a plain role name."

  # What the server holds now, to put back if a later step fails. It is a
  # verifier, not a password, and it stays in this variable.
  local current
  current=$(printf "SELECT 'role:' || coalesce(rolpassword, '') FROM pg_authid WHERE rolname = '%s';\n" "$PG_ROLE" \
    | pg_sql 2>/dev/null) \
    || refuse_postgres_rotation "could not query PostgreSQL in the '$PG_SERVICE' container."
  case "$current" in
    role:*) OLD_VERIFIER="${current#role:}" ;;
    *) refuse_postgres_rotation "the role '$PG_ROLE' (POSTGRES_USER in $ENV_FILE) does not exist in the server." ;;
  esac
}

if [ "$SECRET" = "POSTGRES_PASSWORD" ]; then
  postgres_preflight
fi

# --- new value ---------------------------------------------------------------

backup="${ENV_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
cp "$ENV_FILE" "$backup"
chmod 600 "$backup"
echo "Backed up $ENV_FILE to $backup"

if [ "$SECRET" = "API_KEY_HASH_SECRET" ] && [ "$INIT" = true ]; then
  # Seed it with the current JWT key so existing API-key digests still verify.
  NEW=$(grep -E '^JWT_SECRET_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2-)
  if [ -z "$NEW" ]; then
    echo "ERROR: JWT_SECRET_KEY not found in $ENV_FILE" >&2; exit 1
  fi
  echo "Seeding API_KEY_HASH_SECRET with the current JWT_SECRET_KEY."
  echo "Existing API keys keep working; the two secrets are now independent."
else
  # The same generators, and so the same shapes, as a fresh install. They
  # refuse a random value a validator downstream would reject: the tools
  # service does not start with an API_KEY that is not wsk_<prefix>.<hex>
  # or that happens to contain "abc", and `make start` validates .env first.
  NEW=$(NAME="$SECRET" python3 - <<'PY'
import importlib.util, os

spec = importlib.util.spec_from_file_location("generate_secrets", "scripts/generate_secrets.py")
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
GENERATORS = {
    "JWT_SECRET_KEY": lambda: gen.generate_hex(32),
    "GATEWAY_INTERNAL_SECRET": lambda: gen.generate_hex(32),
    "API_KEY": lambda: gen.generate_api_key("prod"),
    "API_KEY_HASH_SECRET": lambda: gen.generate_hex(32),
    "CSPM_CREDENTIAL_KEY": lambda: gen.generate_base64(32),
    "REDIS_PASSWORD": lambda: gen.generate_password(24),
    "POSTGRES_PASSWORD": lambda: gen.generate_base64(32),
    "NEXTAUTH_SECRET": lambda: gen.generate_base64(32),
}
print(GENERATORS[os.environ["NAME"]]())
PY
)
fi
[ -n "$NEW" ] || { echo "ERROR: could not generate a new value" >&2; exit 1; }

# --- write .env --------------------------------------------------------------

# Replace NAME= in the env file, or append it. For POSTGRES_PASSWORD, also
# replace the password component of every connection string that points at
# the stack's PostgreSQL with the same user; nothing else in them changes.
# Prints "updated NAME" / "skipped NAME: reason" lines, never a value. The
# values travel in the environment, not in argv, where any local user could
# read them with ps. The file is replaced in one step, with mode 600.
write_env() {
  ENV_FILE="$ENV_FILE" NAME="$SECRET" VALUE="$NEW" PG_ROLE="$PG_ROLE" \
    PG_HOSTS="$PG_SERVICE wildbox-postgres" python3 - <<'PY'
import os, re
from urllib.parse import quote, unquote

path, name, value = os.environ["ENV_FILE"], os.environ["NAME"], os.environ["VALUE"]
role, hosts = os.environ["PG_ROLE"], os.environ["PG_HOSTS"].split()
dsn = re.compile(r"^(postgres(?:ql)?(?:\+[a-z0-9]+)?://)([^/?#]*)@([^/?#@]*)(.*)$", re.I)

lines = open(path, encoding="utf-8").read().split("\n")
out, seen = [], False
for line in lines:
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
    if not m:
        out.append(line)
        continue
    key, raw = m.group(1), m.group(2)
    if key == name:
        # Inserted literally: a backslash in the value is not a group reference.
        out.append(f"{name}={value}")
        if not seen:
            print(f"updated {name}")
        seen = True
        continue
    quote_char = raw[:1] if len(raw) >= 2 and raw[:1] in "\"'" and raw[-1:] == raw[:1] else ""
    body = raw[1:-1] if quote_char else raw
    url = dsn.match(body) if name == "POSTGRES_PASSWORD" else None
    if not url or ":" not in url.group(2):
        out.append(line)
        continue
    scheme, userinfo, hostport, rest = url.groups()
    user = userinfo.split(":", 1)[0]
    host = hostport.rsplit(":", 1)[0] if not hostport.startswith("[") else hostport
    if host not in hosts:
        print(f"skipped {key}: host '{host}' is not this stack's PostgreSQL service")
        out.append(line)
    elif unquote(user) != role:
        print(f"skipped {key}: it connects as another user")
        out.append(line)
    else:
        out.append(f"{key}={quote_char}{scheme}{user}:{quote(value, safe='')}@{hostport}{rest}{quote_char}")
        print(f"updated {key}")
if not seen:
    if out and out[-1] == "":
        out.pop()
    out += [f"{name}={value}", ""]
    print(f"updated {name}")

tmp = path + ".rotate.tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write("\n".join(out))
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
}

ENV_CHANGED=false
SERVER_CHANGED=false

# Put .env and the server back the way they were, and say which of the two
# could be confirmed. Called when a step of the PostgreSQL rotation fails.
rollback_postgres() {
  trap - INT TERM
  echo "" >&2
  echo "ROTATION FAILED: $1" >&2
  if [ "$ENV_CHANGED" = true ]; then
    cp "$backup" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "Restored $ENV_FILE from $backup." >&2
  fi
  local server_ok=true
  if [ "$SERVER_CHANGED" = true ]; then
    if OLD_VERIFIER="$OLD_VERIFIER" alter_role_sql "$PG_ROLE" old | pg_sql >/dev/null 2>&1; then
      echo "Restored the previous password of '$PG_ROLE' in the server." >&2
    else
      server_ok=false
    fi
  fi
  if [ "$server_ok" = true ]; then
    echo "$ENV_FILE and the server hold the old password again: nothing was rotated." >&2
    exit 1
  fi
  cat >&2 <<MSG

INCONSISTENT: $ENV_FILE holds the old password again, but the server could
not be reached to put its old password back, so it may hold either. When
PostgreSQL answers, set the password from POSTGRES_PASSWORD in $ENV_FILE by
hand (the prompt keeps it off the command line), then check the services:

    docker compose exec $PG_SERVICE psql -U $PG_ROLE -c '\\password $PG_ROLE'

The backup $backup holds the same old password.
MSG
  exit 3
}

if [ "$SECRET" = "POSTGRES_PASSWORD" ]; then
  trap 'rollback_postgres "interrupted."' INT TERM
  ENV_CHANGED=true
  REPORT=$(write_env) || rollback_postgres "could not rewrite $ENV_FILE."
  # From here the server may hold the new password even if the command that
  # set it reports a failure, so every failure puts the old one back.
  SERVER_CHANGED=true
  VALUE="$NEW" alter_role_sql "$PG_ROLE" new | pg_sql >/dev/null 2>&1 \
    || rollback_postgres "PostgreSQL did not accept the password change."
  printf '%s\n' "$NEW" | pg_accepts_password "$PG_ROLE" \
    || rollback_postgres "the server does not accept the new password after the change."
  trap - INT TERM
else
  REPORT=$(write_env)
fi

if [ "$SECRET" = "API_KEY_HASH_SECRET" ] && [ "$INIT" = true ]; then
  # Seeding is an upgrade step: identity reads the variable only once the
  # new images run, so there is nothing to restart yet.
  echo "Seeded API_KEY_HASH_SECRET in $ENV_FILE"
  echo ""
  echo "NEXT: continue the upgrade (UPGRADING.md): build and start the new"
  echo "images. Do not restart the running stack for this change."
  exit 0
fi

# --- what to do next ---------------------------------------------------------

# The services whose rendered compose configuration carries the new value:
# exactly the containers that have to be recreated. Names only.
services_holding_new_value() {
  command -v docker >/dev/null 2>&1 || return 0
  { compose --profile '*' config --format json 2>/dev/null \
      || compose config --format json 2>/dev/null || true; } \
    | VALUE="$NEW" SKIP="$1" python3 -c '
import json, os, sys
from urllib.parse import quote
try:
    services = json.load(sys.stdin)["services"]
except (ValueError, KeyError, TypeError):
    sys.exit(0)
value = os.environ["VALUE"]
needles = {value, quote(value, safe="")}
names = [
    name for name, service in services.items()
    if name != os.environ["SKIP"]
    and any(needle in json.dumps(service) for needle in needles)
]
print(" ".join(names))
'
}

echo "Rotated $SECRET in $ENV_FILE"
if [ "$SECRET" = "POSTGRES_PASSWORD" ]; then
  echo "The role '$PG_ROLE' in the running server has the new password, and the"
  echo "server accepted it."
  echo ""
  echo "Changed in $ENV_FILE:"
  printf '%s\n' "$REPORT" | sed -n 's/^updated /    /p'
  if printf '%s\n' "$REPORT" | grep -q '^skipped '; then
    echo "NOT changed (update these by hand if they use this server and user):"
    printf '%s\n' "$REPORT" | sed -n 's/^skipped /    /p'
  fi
  SERVICES=$(services_holding_new_value "$PG_SERVICE")
else
  SERVICES=$(services_holding_new_value "")
fi

echo ""
case "$SECRET" in
  POSTGRES_PASSWORD)
    echo "NEXT: the services below still hold the old password in their"
    echo "environment. They keep their open connections, and every new"
    echo "connection fails until they are recreated:"
    ;;
  GATEWAY_INTERNAL_SECRET)
    echo "NEXT: recreate the gateway and every backend together. Each compares"
    echo "the header with its own value, so requests between a recreated and a"
    echo "not-yet-recreated container get 403 until all of them are done:"
    ;;
  JWT_SECRET_KEY)
    echo "NEXT: recreate identity. Every session ends; users log in again."
    echo "API keys keep working:"
    ;;
  API_KEY_HASH_SECRET)
    echo "NEXT: recreate identity. Every stored API key stops working; users"
    echo "and teams create new ones:"
    ;;
  API_KEY)
    echo "NEXT: recreate the tools containers. They only require the variable"
    echo "at start; it is not accepted as a credential, so no client changes:"
    ;;
  CSPM_CREDENTIAL_KEY)
    echo "NEXT: recreate cspm and its worker. Scans submitted before this"
    echo "can no longer be decrypted and must be submitted again:"
    ;;
  REDIS_PASSWORD)
    echo "NEXT: recreate Redis and every service that uses it, together. The"
    echo "data survives. A Redis URL overridden in $ENV_FILE (variables like"
    echo "IDENTITY_REDIS_URL) was not rewritten: edit it by hand first:"
    ;;
  NEXTAUTH_SECRET)
    echo "NEXT: nothing depends on it. The dashboard container receives the"
    echo "variable and no code reads it; recreating it only keeps .env and the"
    echo "container the same:"
    ;;
esac
echo ""
if [ -n "$SERVICES" ]; then
  echo "    docker compose up -d --no-deps $SERVICES"
else
  echo "    docker compose up -d"
  echo ""
  echo "(The compose configuration could not be read to name the services;"
  echo "this recreates every container whose configuration changed.)"
fi
echo ""
if [ "$SECRET" = "POSTGRES_PASSWORD" ]; then
  echo "The '$PG_SERVICE' container itself keeps running: PostgreSQL reads"
  echo "POSTGRES_PASSWORD only when it creates an empty data directory. If you"
  echo "run the backup profile, recreate that container too."
  echo ""
fi
echo "Use the compose files you start the stack with. Then verify:  make health"
echo "Then delete $backup: it holds the old value."
