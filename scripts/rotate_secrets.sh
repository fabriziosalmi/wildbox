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
# Usage:
#   ./scripts/rotate_secrets.sh --list
#   ./scripts/rotate_secrets.sh --secret GATEWAY_INTERNAL_SECRET
#   ./scripts/rotate_secrets.sh --secret JWT_SECRET_KEY
#   ./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET --init
#
# The compose checks use the files docker compose would use by default; set
# COMPOSE_FILE to match how you start the stack, for example
# COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml. No secret value is
# ever printed.

set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE="${ENV_FILE:-.env}"
SECRET=""
INIT=false
LIST=false

while [ $# -gt 0 ]; do
  case "$1" in
    --secret) SECRET="$2"; shift 2 ;;
    --secret=*) SECRET="${1#*=}"; shift ;;
    --init) INIT=true; shift ;;
    --list) LIST=true; shift ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

ROTATABLE="JWT_SECRET_KEY GATEWAY_INTERNAL_SECRET API_KEY API_KEY_HASH_SECRET CSPM_CREDENTIAL_KEY REDIS_PASSWORD POSTGRES_PASSWORD NEXTAUTH_SECRET"

if [ "$LIST" = true ]; then
  echo "Rotatable secrets and what rotating each one costs:"
  echo ""
  echo "  GATEWAY_INTERNAL_SECRET  All services must restart together. Every"
  echo "                           service compares its own env value, so a"
  echo "                           rolling restart produces 403s between"
  echo "                           already-restarted and not-yet-restarted"
  echo "                           services. Stop-the-world; window is one restart."
  echo "  JWT_SECRET_KEY           Invalidates every active session (users must"
  echo "                           log in again). Refused until identity receives"
  echo "                           a separate API_KEY_HASH_SECRET."
  echo "  API_KEY_HASH_SECRET      Invalidates every stored API key. On an existing"
  echo "                           deployment seed it ONCE with --init (copies the"
  echo "                           current JWT_SECRET_KEY) before identity uses it."
  echo "  API_KEY                  The tools service's static key. Restart the"
  echo "                           api and tools-worker containers together."
  echo "  CSPM_CREDENTIAL_KEY      In-flight scan credentials become undecryptable;"
  echo "                           affected scans must be re-submitted."
  echo "  REDIS_PASSWORD           All services restart; queued work survives."
  echo "  POSTGRES_PASSWORD        Must be changed in Postgres first, then here."
  echo "  NEXTAUTH_SECRET          Dashboard sessions are invalidated."
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

# Exit 0 when the variable named by $1 is non-empty in the environment of
# identity as `docker compose config` renders it. The rendered config holds
# every secret, so it goes straight into python and is never printed.
compose_passes_to_identity() {
  docker compose --env-file "$ENV_FILE" config --format json 2>/dev/null \
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
  id=$(docker compose --env-file "$ENV_FILE" ps --status running -q identity 2>/dev/null || true)
  if [ -z "$id" ]; then
    echo "identity is not running; checked the compose configuration only."
    return 0
  fi
  docker compose --env-file "$ENV_FILE" exec -T identity python -c \
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
  NEW=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
fi

# The value travels in the environment, not in argv, where any local user
# could read it with ps.
if grep -qE "^${SECRET}=" "$ENV_FILE"; then
  ENV_FILE="$ENV_FILE" NAME="$SECRET" VALUE="$NEW" python3 - <<'PY'
import os, re
path, name, value = os.environ["ENV_FILE"], os.environ["NAME"], os.environ["VALUE"]
lines = open(path).read().split('\n')
# A function replacement: the value is inserted literally, so a backslash
# in it is not read as a group reference.
out = [re.sub(rf'^{re.escape(name)}=.*$', lambda _m: f'{name}={value}', l) for l in lines]
open(path, 'w').write('\n'.join(out))
PY
else
  printf '\n%s=%s\n' "$SECRET" "$NEW" >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

echo "Rotated $SECRET in $ENV_FILE"
echo ""
echo "NEXT: restart the affected services. For GATEWAY_INTERNAL_SECRET this must"
echo "be all of them at once, because each compares its own environment value:"
echo ""
echo "    docker compose up -d --force-recreate"
echo ""
echo "Then verify:  make health"
