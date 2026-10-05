#!/usr/bin/env bash
# The API-key scope each route requires (#647) -- run against the PRODUCTION
# image (Dockerfile, nginx/conf.d/wildbox_gateway.conf) wired to
# test/mock_identity.py, which answers on every upstream's name and port
# (see .github/workflows/gateway-tests.yml).
#
# ci_auth_tests.sh runs a configuration written for the tests, with a few
# locations copied by hand. Its tools location is a prefix one, so it never
# had the exact /api/v1/tools location production has, and the scope map's
# mistake there went out unnoticed. This script reads the locations from the
# configuration that ships:
#
#   * every location that calls authenticate() must have a pin below, so a
#     route added without one fails here instead of silently getting whatever
#     the gateway's map gives it;
#   * each pin is checked on the wire, per method: a key with no scope is
#     refused and told the pinned scope, and a key holding exactly that scope
#     is let through to the upstream path the location maps to, and the
#     service is told the credential: X-Wildbox-Auth-Type api_key and
#     the key's scopes in X-Wildbox-Scopes (#637);
#   * the paths around the locations (no trailing slash, asset-like
#     extensions, unknown services) reach no service.
#
# The mock mints the keys: wsk_scoped~<id>~<scope>,<scope> holds exactly the
# scopes it names, in a team of its own.

set -u

GATEWAY_PROD_URL="${GATEWAY_PROD_URL:-https://localhost:8443}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_CONF="${GATEWAY_CONF:-$HERE/../nginx/conf.d/wildbox_gateway.conf}"

PASS=0
FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

# A key holding exactly the scopes named ("" for none). One key per scope
# set: the id is derived from the scopes, so the gateway caches one decision
# for each.
key_for() {
    local scopes="$1"
    printf 'wsk_scoped~route-%s~%s' "$(printf '%s' "${scopes:-none}" | tr -c 'a-z0-9' '-')" "$scopes"
}

# call <method> <path> <scopes> ; status in $STATUS, body in $BODY.
# --path-as-is: the path is sent as written, trailing slashes and all.
call() {
    local method="$1" path="$2" scopes="$3"
    STATUS=$(curl -sk --path-as-is -o "$WORK/body" -w "%{http_code}" -X "$method" \
        -H "X-API-Key: $(key_for "$scopes")" "$GATEWAY_PROD_URL$path")
    BODY=$(cat "$WORK/body")
}

field() { printf '%s' "$BODY" | jq -r "$1" 2>/dev/null; }

# requires <method> <path> <scope> <upstream path>: the request needs exactly
# <scope>. A key without any scope is refused and told so; a key holding the
# scope reaches the upstream, on the path the location maps to.
requires() {
    local method="$1" path="$2" scope="$3" upstream="$4" name
    name="$method $path requires $scope"

    call "$method" "$path" ""
    if [ "$STATUS" = 403 ] && [ "$(field .error)" = insufficient_scope ] \
            && [ "$(field .required_scope)" = "$scope" ]; then
        pass "$name"
    else
        fail "$name: a key with no scope got HTTP $STATUS, required_scope '$(field .required_scope)' — $(head -c 200 "$WORK/body")"
    fi

    call "$method" "$path" "$scope"
    if [ "$STATUS" = 200 ] && [ "$(field .path)" = "$upstream" ] && [ "$(field .method)" = "$method" ]; then
        pass "$method $path with $scope reaches $upstream"
    else
        fail "$method $path with $scope: HTTP $STATUS, upstream '$(field .method) $(field .path)', expected '$method $upstream' — $(head -c 200 "$WORK/body")"
    fi
    # Every location of the production configuration forwards what the
    # gateway decided on, so the service can check the scope again (#637).
    if [ "$(field '.headers["x-wildbox-auth-type"]')" = api_key ] \
            && [ "$(field '.headers["x-wildbox-scopes"]')" = "$scope" ]; then
        pass "$method $path tells the service the key holds $scope"
    else
        fail "$method $path: the service was told auth type '$(field '.headers["x-wildbox-auth-type"]')', scopes '$(field '.headers["x-wildbox-scopes"]')', expected api_key and '$scope'"
    fi
}

PINNED="$WORK/pinned"
: > "$PINNED"

# pin <location> <path> <upstream path> <read> <write> <delete>
#
# <location> is the location as wildbox_gateway.conf writes it, <path> a
# request it serves and <upstream path> where that request lands. GET needs
# <read>, POST, PUT and PATCH <write>, DELETE <delete>. HEAD has no body to
# read the required scope from: it is refused without a scope and served
# with <read>.
pin() {
    local location="$1" path="$2" upstream="$3" read="$4" write="$5" delete="$6" method
    printf '%s\n' "$location" >> "$PINNED"
    echo "-- $path ($location)"
    requires GET "$path" "$read" "$upstream"
    for method in POST PUT PATCH; do
        requires "$method" "$path" "$write" "$upstream"
    done
    requires DELETE "$path" "$delete" "$upstream"

    call HEAD "$path" ""
    local refused="$STATUS"
    call HEAD "$path" "$read"
    if [ "$refused" = 403 ] && [ "$STATUS" = 200 ]; then
        pass "HEAD $path is a read: refused without a scope, served with $read"
    else
        fail "HEAD $path: HTTP $refused without a scope, HTTP $STATUS with $read"
    fi
}

echo "== Route scopes against $GATEWAY_PROD_URL =="

# --- The pins ---------------------------------------------------------------
# Tools: the collection, with and without the trailing slash, and a tool.
pin '= /api/v1/tools'           /api/v1/tools               /api/tools               tools:read tools:execute tools:execute
pin '~ ^/api/v1/tools/(.*)$'    /api/v1/tools/              /api/tools/              tools:read tools:execute tools:execute
pin '~ ^/api/v1/tools/(.*)$'    /api/v1/tools/whois/info    /api/tools/whois/info    tools:read tools:execute tools:execute
# Asynchronous tool tasks.
pin '= /api/v1/tasks'           /api/v1/tasks               /api/tasks               tools:read tools:execute tools:execute
pin '^~ /api/v1/tasks/'         /api/v1/tasks/              /api/tasks/              tools:read tools:execute tools:execute
pin '^~ /api/v1/tasks/'         /api/v1/tasks/1f0c4ea6      /api/tasks/1f0c4ea6      tools:read tools:execute tools:execute
# Agents.
pin '= /api/v1/agents/stats'    /api/v1/agents/stats        /stats                   tools:read tools:execute tools:execute
pin '~ ^/api/v1/agents/(.*)$'   /api/v1/agents/             /v1/                     tools:read tools:execute tools:execute
pin '~ ^/api/v1/agents/(.*)$'   /api/v1/agents/analyze      /v1/analyze              tools:read tools:execute tools:execute
# Automations (n8n): administrative whatever the method, and whatever the
# path after the prefix looks like.
pin '/api/v1/automations/'      /api/v1/automations/        /                        tools:admin tools:admin tools:admin
pin '/api/v1/automations/'      /api/v1/automations/rest/workflows /rest/workflows   tools:admin tools:admin tools:admin
pin '/api/v1/automations/'      /api/v1/automations/api/v1/tools/whois /api/v1/tools/whois tools:admin tools:admin tools:admin
# Guardian: deleting needs its own scope.
pin '/api/v1/guardian/'         /api/v1/guardian/           /api/v1/                 data:read data:write data:delete
pin '/api/v1/guardian/'         /api/v1/guardian/assets/7/  /api/v1/assets/7/        data:read data:write data:delete
# Data: generic scopes, except the sensor's ingest route.
pin '= /api/v1/data/health'     /api/v1/data/health         /health                  read write write
pin '/api/v1/data/'             /api/v1/data/               /api/v1/                 read write write
pin '/api/v1/data/'             /api/v1/data/telemetry/events /api/v1/telemetry/events read write write
pin '/api/v1/data/'             /api/v1/data/ingest         /api/v1/ingest           read data:ingest data:ingest
pin '/api/v1/data/'             /api/v1/data/ingest/        /api/v1/ingest/          read write write
pin '/api/v1/data/'             /api/v1/data/ingest/batch   /api/v1/ingest/batch     read write write
# CSPM, responder and identity's health probe: generic scopes.
pin '/api/v1/cspm/'             /api/v1/cspm/               /api/v1/                 read write write
pin '/api/v1/cspm/'             /api/v1/cspm/scans          /api/v1/scans            read write write
pin '/api/v1/responder/'        /api/v1/responder/          /v1/                     read write write
pin '/api/v1/responder/'        /api/v1/responder/playbooks /v1/playbooks            read write write
pin '= /api/v1/identity/health' /api/v1/identity/health     /health                  read write write

# --- Every authenticating location is pinned --------------------------------
echo "== Locations =="
LOCATIONS="$WORK/locations"
if ! python3 "$HERE/authenticated_locations.py" "$GATEWAY_CONF" > "$LOCATIONS"; then
    fail "could not read the locations of $GATEWAY_CONF"
fi
if [ -s "$LOCATIONS" ]; then
    pass "read $(wc -l < "$LOCATIONS" | tr -d ' ') authenticating locations from $(basename "$GATEWAY_CONF")"
else
    fail "no authenticating location found in $GATEWAY_CONF"
fi
while IFS= read -r location; do
    if grep -Fxq -- "$location" "$PINNED"; then
        pass "location $location is pinned"
    else
        fail "location $location authenticates but no scope is pinned for it: add its row to ROUTE_SCOPES in auth_handler.lua and a pin above"
    fi
done < "$LOCATIONS"
sort -u "$PINNED" | while IFS= read -r location; do
    grep -Fxq -- "$location" "$LOCATIONS" || echo "$location"
done > "$WORK/stale"
if [ -s "$WORK/stale" ]; then
    fail "pinned but not an authenticating location of $(basename "$GATEWAY_CONF"): $(tr '\n' ';' < "$WORK/stale")"
else
    pass "every pin names a location of $(basename "$GATEWAY_CONF")"
fi

# --- #647, as reported ------------------------------------------------------
echo "== GET /api/v1/tools (#647) =="
for scopes in tools:read tools:execute tools:admin; do
    call GET /api/v1/tools "$scopes"
    if [ "$STATUS" = 200 ]; then
        pass "a $scopes key lists the tools"
    else
        fail "a $scopes key lists the tools: HTTP $STATUS — $(head -c 200 "$WORK/body")"
    fi
done
for scopes in data:read data:write data:ingest; do
    call GET /api/v1/tools "$scopes"
    if [ "$STATUS" = 403 ] && [ "$(field .required_scope)" = tools:read ]; then
        pass "a $scopes key cannot list the tools"
    else
        fail "a $scopes key cannot list the tools: HTTP $STATUS — $(head -c 200 "$WORK/body")"
    fi
done
# The generic scopes satisfy the resource ones of the same level, on the
# collection as on every other tools route: unchanged.
call GET /api/v1/tools read
if [ "$STATUS" = 200 ]; then
    pass "a read key lists the tools, as it reads a tool"
else
    fail "a read key lists the tools: HTTP $STATUS"
fi
call POST /api/v1/tools read
if [ "$STATUS" = 403 ] && [ "$(field .required_scope)" = tools:execute ]; then
    pass "a read key cannot POST to the tools collection"
else
    fail "a read key cannot POST to the tools collection: HTTP $STATUS — $(head -c 200 "$WORK/body")"
fi

# --- Automations: the scope of the route, not of the rewritten path ---------
echo "== Automations =="
for scopes in read write tools:read tools:execute data:write; do
    for method in GET POST; do
        call "$method" /api/v1/automations/rest/workflows "$scopes"
        if [ "$STATUS" = 403 ] && [ "$(field .required_scope)" = tools:admin ]; then
            pass "a $scopes key cannot $method an automation"
        else
            fail "a $scopes key cannot $method an automation: HTTP $STATUS — $(head -c 200 "$WORK/body")"
        fi
    done
done

# --- Paths that reach no service --------------------------------------------
echo "== Around the locations =="

# not_served <method> <path> <expected status>: the answer is the gateway's
# own, whatever the key holds; nothing was proxied.
not_served() {
    local method="$1" path="$2" expected="$3"
    call "$method" "$path" "*"
    if [ "$STATUS" = "$expected" ] && [ "$(field '.headers | type')" != object ]; then
        pass "$method $path answers $expected and reaches no service"
    else
        fail "$method $path: expected HTTP $expected from the gateway, got $STATUS — $(head -c 200 "$WORK/body")"
    fi
}

# A prefix location without its trailing slash: nginx redirects to the
# slash, and the redirected request is authenticated like any other.
for service in data cspm responder guardian automations identity; do
    not_served GET "/api/v1/$service" 301
done
# No location at all.
not_served GET /api/v1/agents 404
not_served GET /api/v1/toolsmith 404
not_served POST /api/v1/sensor/events 404
not_served GET /api/tools/whois 404

# Asset-like names under /api/ stay with their route: the static-asset
# location, which authenticates nobody, used to take them.
for path in /api/v1/tools/x.js /api/v1/data/report.png /api/v1/guardian/x.css \
        /api/v1/cspm/x.svg /api/v1/responder/x.ico /api/v1/automations/x.js \
        /api/v1/agents/x.woff2; do
    STATUS=$(curl -sk --path-as-is -o "$WORK/body" -w "%{http_code}" "$GATEWAY_PROD_URL$path")
    BODY=$(cat "$WORK/body")
    if [ "$STATUS" = 401 ] && [ "$(field .error)" = authentication_required ]; then
        pass "$path needs a credential"
    else
        fail "$path without a credential: HTTP $STATUS — $(head -c 200 "$WORK/body")"
    fi
    call GET "$path" ""
    if [ "$STATUS" = 403 ] && [ "$(field .error)" = insufficient_scope ]; then
        pass "$path needs a scope ($(field .required_scope))"
    else
        fail "$path with a key that has no scope: HTTP $STATUS — $(head -c 200 "$WORK/body")"
    fi
done
not_served GET /api/v1/unknown/x.js 404
# The dashboard's own assets are still served without a credential.
STATUS=$(curl -sk -o "$WORK/body" -w "%{http_code}" "$GATEWAY_PROD_URL/_next/static/chunks/main.js")
BODY=$(cat "$WORK/body")
if [ "$STATUS" = 200 ] && [ "$(field .path)" = /_next/static/chunks/main.js ]; then
    pass "a dashboard asset is served without a credential"
else
    fail "dashboard asset: HTTP $STATUS — $(head -c 200 "$WORK/body")"
fi

# A path is mapped as nginx normalizes it, the way the location was chosen.
# mapped_as <path> <scope> <what>: POSTing to <path> requires <scope>.
mapped_as() {
    local path="$1" scope="$2" what="$3"
    call POST "$path" ""
    if [ "$STATUS" = 403 ] && [ "$(field .required_scope)" = "$scope" ]; then
        pass "$what ($path requires $scope)"
    else
        fail "$what: POST $path got HTTP $STATUS, required_scope '$(field .required_scope)', expected $scope"
    fi
}
mapped_as /api/v1/data//ingest data:ingest "doubled slashes are merged before mapping"
mapped_as /api/v1/tools/../data/ingest data:ingest "dot segments are resolved before mapping"
mapped_as '/api/v1/tools/..%2fdata/sources' write "an encoded slash is decoded before mapping"

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
