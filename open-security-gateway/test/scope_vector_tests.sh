#!/usr/bin/env bash
# The scope hierarchy, against the table the services are tested with (#637)
# -- run against the Dockerfile.test gateway wired to test/mock_identity.py
# (see .github/workflows/gateway-tests.yml).
#
# The gateway decides whether an API key's scopes satisfy the scope a
# request requires (scopes_satisfy in auth_handler.lua), and the services
# decide again on the scopes the gateway forwards (scope_satisfied in
# open-security-shared/scopes.py). Two implementations of one rule drift:
# a service stricter than the gateway refuses a key the gateway let
# through, and a looser one is no second check.
#
# test/scope_vectors.txt is the rule written out, one line for each pair of
# granted scopes and required scope. tests/shared/test_scopes.py checks the
# Python against it; this script checks the Lua, on the wire: for each line
# it sends a request that requires the scope, with a key the mock mints
# holding exactly the granted ones (wsk_scoped~<id>~<scopes>), and expects
# 200 for "allow" and 403 insufficient_scope for "deny".

set -u

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VECTORS="${SCOPE_VECTORS:-$HERE/scope_vectors.txt}"

PASS=0
FAIL=0
SKIPPED=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }

echo "== Scope vectors ($VECTORS) against $GATEWAY_URL =="

# A request that requires each scope: the method and the path, as
# required_scope_for_request maps them.
request_requiring() {
    case "$1" in
        read)          METHOD=GET;    ROUTE=/api/v1/data/sources ;;
        write)         METHOD=POST;   ROUTE=/api/v1/data/sources ;;
        data:ingest)   METHOD=POST;   ROUTE=/api/v1/data/ingest ;;
        tools:read)    METHOD=GET;    ROUTE=/api/v1/tools/echo ;;
        tools:execute) METHOD=POST;   ROUTE=/api/v1/tools/echo ;;
        tools:admin)   METHOD=GET;    ROUTE=/api/v1/automations/rest/workflows ;;
        data:read)     METHOD=GET;    ROUTE=/api/v1/guardian/assets/ ;;
        data:write)    METHOD=POST;   ROUTE=/api/v1/guardian/assets/ ;;
        data:delete)   METHOD=DELETE; ROUTE=/api/v1/guardian/assets/7/ ;;
        # A route the scope map has no row for requires admin (#647).
        admin)         METHOD=GET;    ROUTE=/api/v1/auth/me ;;
        *) return 1 ;;
    esac
}

LINE=0
ROWS=0
while read -r granted required verdict extra; do
    LINE=$((LINE + 1))
    case "$granted" in '' | '#'*) continue ;; esac
    ROWS=$((ROWS + 1))
    if [ -n "$extra" ] || { [ "$verdict" != allow ] && [ "$verdict" != deny ]; }; then
        fail "line $LINE is not '<granted> <required> <allow|deny>': $granted $required $verdict $extra"
        continue
    fi
    if ! request_requiring "$required"; then
        # No route requires it. The shared package's tests cover the row;
        # the count below fails if a row of the table goes unchecked here.
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    scopes="$granted"
    [ "$granted" = "-" ] && scopes=""
    # One key, and one team, for each line: no rate limit, no shared cache.
    status=$(curl -s -o "$WORK/body" -w "%{http_code}" -X "$METHOD" \
        -H "X-API-Key: wsk_scoped~vector-$LINE~$scopes" "$GATEWAY_URL$ROUTE")
    if [ "$verdict" = allow ]; then
        if [ "$status" = 200 ]; then
            PASS=$((PASS + 1))
        else
            fail "[$granted] must satisfy $required: $METHOD $ROUTE answered $status — $(head -c 160 "$WORK/body")"
        fi
    else
        if [ "$status" = 403 ] && [ "$(jq -r '.error' "$WORK/body" 2>/dev/null)" = insufficient_scope ] \
                && [ "$(jq -r '.required_scope' "$WORK/body" 2>/dev/null)" = "$required" ]; then
            PASS=$((PASS + 1))
        else
            fail "[$granted] must not satisfy $required: $METHOD $ROUTE answered $status — $(head -c 160 "$WORK/body")"
        fi
    fi
done < "$VECTORS"

if [ "$ROWS" -lt 200 ]; then
    fail "only $ROWS rows read from $VECTORS: the table has 200"
fi
if [ "$PASS" -lt 200 ]; then
    fail "only $PASS rows were checked on the wire: every row of the table has a route"
fi

echo "✅ $PASS rows agree with the gateway ($SKIPPED without a route here)"
echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
