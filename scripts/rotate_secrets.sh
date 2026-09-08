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
# It also matters WHICH secret you rotate. Until API_KEY_HASH_SECRET is set,
# stored API-key digests are HMACs keyed by JWT_SECRET_KEY, so rotating the JWT
# key invalidates every API key in the database (WILDBO-SEC-01). This script
# refuses to rotate the JWT key until that decoupling is in place.
#
# Usage:
#   ./scripts/rotate_secrets.sh --list
#   ./scripts/rotate_secrets.sh --secret GATEWAY_INTERNAL_SECRET
#   ./scripts/rotate_secrets.sh --secret JWT_SECRET_KEY
#   ./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET --init

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
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
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
  echo "                           log in again). ALSO invalidates every stored"
  echo "                           API key unless API_KEY_HASH_SECRET is set."
  echo "  API_KEY_HASH_SECRET      Invalidates every stored API key. Set it ONCE"
  echo "                           (--init) before it diverges from the JWT key."
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

# Guard the coupling described above.
if [ "$SECRET" = "JWT_SECRET_KEY" ]; then
  if ! grep -qE '^API_KEY_HASH_SECRET=.+' "$ENV_FILE"; then
    cat >&2 <<'MSG'
REFUSING to rotate JWT_SECRET_KEY.

Stored API-key digests are HMACs keyed by JWT_SECRET_KEY until
API_KEY_HASH_SECRET is set, so rotating the JWT key now would silently
invalidate every API key in the database with no way to bring them back
(WILDBO-SEC-01).

Decouple them first:

    ./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET --init

That sets API_KEY_HASH_SECRET to the CURRENT JWT_SECRET_KEY, so existing API
keys keep working, and the two can then be rotated independently.
MSG
    exit 1
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

if grep -qE "^${SECRET}=" "$ENV_FILE"; then
  python3 - "$ENV_FILE" "$SECRET" "$NEW" <<'PY'
import sys, re
path, name, value = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path).read().split('\n')
out = [re.sub(rf'^{re.escape(name)}=.*$', f'{name}={value}', l) for l in lines]
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
