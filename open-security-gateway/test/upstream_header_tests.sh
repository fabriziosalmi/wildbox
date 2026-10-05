#!/usr/bin/env bash
# Which of Wildbox's own headers each upstream receives (#711) -- run against
# the PRODUCTION image (Dockerfile, nginx/conf.d/wildbox_gateway.conf) wired
# to test/mock_identity.py, which answers on every upstream's name and port
# and echoes the headers it received (see .github/workflows/gateway-tests.yml).
#
# The gateway vouches for a caller with X-Gateway-Secret and the X-Wildbox-*
# headers. A Wildbox service checks the secret and trusts the rest, so it is
# sent them; whoever else holds the secret can state any user, team and role
# to every service. The automations location proxied to n8n and included
# the same proxy settings as a backend, so n8n -- not a Wildbox service,
# and able to hand a request's headers to a workflow -- was sent the secret,
# the caller's identity and, from a browser, the session JWT in a cookie.
# That location is gone (#714): the gateway proxies to Wildbox's own
# services and to nothing else.
#
# So every location of wildbox_gateway.conf that proxies is classified here
# by what its upstream is, and what that kind may receive is checked on the
# wire with a request that carries everything a client can send: a session
# token, an API key, the dashboard's session cookie, and forged copies of
# the gateway's own headers.
#
#   backend      a Wildbox service behind authenticate(): the gateway's
#                secret and the caller's identity and credential type, as
#                the gateway states them; none of the client's credentials
#   identity     identity's own routes, which validate the bearer token
#                themselves: the client's Authorization, and nothing the
#                gateway vouches with
#   dashboard    the dashboard: its own session cookie, nothing else
#
# There is no kind for anything else, on purpose: an upstream that is not
# Wildbox's has no line to be written with. The locations are read from the
# configuration: one that proxies and has no line below fails, so a location
# added later must be classified, and tests/scripts checks that each kind
# names an upstream that is that kind of service.

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

if [ -z "${CI_GATEWAY_SECRET:-}" ]; then
    fail "CI_GATEWAY_SECRET is not set: the proof of origin cannot be compared"
fi

SESSION="prod-harness-session-token"
SESSION_COOKIE="auth_token=eyJhbGciOiJIUzI1NiJ9.session.fixture"
# Everything a client can send: both credentials, the dashboard's cookies,
# and forged copies of every header the gateway sets itself.
CLIENT=(
    -H "Authorization: Bearer $SESSION"
    -H "X-API-Key: wsk_client_supplied_fixture"
    -H "Cookie: theme=dark; $SESSION_COOKIE; lang=it"
    -H "X-Gateway-Secret: forged-by-the-client"
    -H "X-Wildbox-User-ID: forged-user"
    -H "X-Wildbox-Team-ID: forged-team"
    -H "X-Wildbox-Role: owner"
    -H "X-Wildbox-Auth-Type: service"
    -H "X-Wildbox-Scopes: *"
)

# The Wildbox headers the echoed request carried, sorted, one name each:
# the gateway's secret, any X-Wildbox-*, Authorization, X-API-Key, and
# "cookie:auth_token" when the Cookie header holds the session cookie.
wildbox_headers() {
    jq -r '
        (.headers // {}) as $h
        | [ $h | keys[] | select(test("^(x-gateway-secret|x-wildbox-.*|authorization|x-api-key)$")) ]
          + (if (($h.cookie // "") | test("(^|; *)auth_token=")) then ["cookie:auth_token"] else [] end)
        | sort | join(" ")' "$WORK/body" 2>/dev/null
}

header() { jq -r --arg name "$1" '.headers[$name] // "absent"' "$WORK/body" 2>/dev/null; }

secret_state() {
    jq -r --arg s "${CI_GATEWAY_SECRET:-}" \
        '.headers["x-gateway-secret"] | if . == null then "absent" elif . == $s then "match" else "mismatch" end' \
        "$WORK/body" 2>/dev/null
}

# What each kind of upstream receives of the request above.
BACKEND_HEADERS="x-gateway-secret x-wildbox-auth-type x-wildbox-role x-wildbox-team-id x-wildbox-user-id"
IDENTITY_HEADERS="authorization cookie:auth_token"
DASHBOARD_HEADERS="cookie:auth_token"

CLASSIFIED="$WORK/classified"
: > "$CLASSIFIED"

# upstream <location> <kind> <port> <method> <path>
#
# <location> is the location as wildbox_gateway.conf writes it, <path> a
# request it serves, <port> the port of the service it proxies to (the mock
# says which port a request arrived on), <kind> one of the three above.
upstream() {
    local location="$1" kind="$2" port="$3" method="$4" path="$5" expected status got name
    printf '%s\n' "$location" >> "$CLASSIFIED"
    name="$method $path ($location, $kind)"

    status=$(curl -sk --path-as-is -o "$WORK/body" -w "%{http_code}" -X "$method" "${CLIENT[@]}" "$GATEWAY_PROD_URL$path")
    if [ "$status" != 200 ] || [ "$(jq -r '.port' "$WORK/body" 2>/dev/null)" != "$port" ]; then
        fail "$name: expected the upstream on port $port to answer, got HTTP $status from port '$(jq -r '.port' "$WORK/body" 2>/dev/null)' — $(head -c 160 "$WORK/body")"
        return
    fi

    case "$kind" in
        backend) expected="$BACKEND_HEADERS" ;;
        identity) expected="$IDENTITY_HEADERS" ;;
        dashboard) expected="$DASHBOARD_HEADERS" ;;
        *) fail "$name: unknown kind '$kind'"; return ;;
    esac
    got=$(wildbox_headers)
    if [ "$got" = "$expected" ]; then
        pass "$name receives exactly: ${expected:-no Wildbox header}"
    else
        fail "$name: expected exactly '${expected:-nothing}', the upstream received '$got'"
    fi

    # And the values are the gateway's, never the client's.
    case "$kind" in
        backend)
            if [ "$(secret_state)" = match ] && [ "$(header x-wildbox-user-id)" = user-1616 ] \
                    && [ "$(header x-wildbox-team-id)" = team-1616 ] && [ "$(header x-wildbox-role)" = admin ] \
                    && [ "$(header x-wildbox-auth-type)" = session ]; then
                pass "$name: the secret and the identity are the gateway's own"
            else
                fail "$name: secret $(secret_state), user '$(header x-wildbox-user-id)', team '$(header x-wildbox-team-id)', role '$(header x-wildbox-role)', auth type '$(header x-wildbox-auth-type)'"
            fi
            if [ "$(header cookie)" = "theme=dark; lang=it" ]; then
                pass "$name: the other cookies are kept"
            else
                fail "$name: Cookie is '$(header cookie)', expected the cookies without auth_token"
            fi
            ;;
        identity)
            if [ "$(header authorization)" = "Bearer $SESSION" ]; then
                pass "$name: identity reads the client's bearer token itself"
            else
                fail "$name: Authorization is '$(header authorization)'"
            fi
            ;;
        dashboard)
            if [ "$(header cookie)" = "theme=dark; $SESSION_COOKIE; lang=it" ]; then
                pass "$name: the dashboard gets its cookies as the browser sent them"
            else
                fail "$name: Cookie is '$(header cookie)'"
            fi
            ;;
    esac
}

echo "== Upstream headers against $GATEWAY_PROD_URL =="

# --- The classification -------------------------------------------------------
# The dashboard (port 3000): pages, assets, WebSockets.
upstream '/'                         dashboard 3000 GET  /dashboard
upstream '= /auth/login'             dashboard 3000 GET  /auth/login
upstream '= /auth/signup'            dashboard 3000 GET  /auth/signup
upstream '= /auth/logout'            dashboard 3000 GET  /auth/logout
upstream '~ ^/(login|register|signup)/' dashboard 3000 GET /login/
upstream '^~ /_next/hmr'             dashboard 3000 GET  /_next/hmr
upstream '~ ^/(?!api/)(_next|favicon\.ico|.*\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico))$' \
                                     dashboard 3000 GET  /assets/app.js
upstream '/ws/'                      dashboard 3000 GET  /ws/events

# Identity's own routes (port 8001): identity validates the bearer token.
# The auth routes share a 5-a-second limit with a small burst: one request
# each, spaced.
upstream '/api/v1/identity/'         identity 8001 GET  /api/v1/identity/users/me
upstream '/api/v1/identity/auth/'    identity 8001 POST /api/v1/identity/auth/jwt/login
upstream '^~ /auth/users/'           identity 8001 GET  /auth/users/me
upstream '= /api/v1/auth/logout'     identity 8001 POST /auth/logout
sleep 1
upstream '^~ /auth/jwt/'             identity 8001 POST /auth/jwt/login
sleep 1
upstream '^~ /auth/register'         identity 8001 POST /auth/register
sleep 1
upstream '^~ /auth/forgot-password'  identity 8001 POST /auth/forgot-password
upstream '^~ /auth/reset-password'   identity 8001 POST /auth/reset-password

# Wildbox services behind authenticate().
upstream '= /api/v1/identity/health' backend 8001 GET  /api/v1/identity/health
upstream '= /api/v1/data/health'     backend 8002 GET  /api/v1/data/health
upstream '/api/v1/data/'             backend 8002 POST /api/v1/data/ingest
upstream '/api/v1/cspm/'             backend 8019 GET  /api/v1/cspm/scans
upstream '/api/v1/responder/'        backend 8018 GET  /api/v1/responder/playbooks
upstream '/api/v1/guardian/'         backend 8013 GET  /api/v1/guardian/assets/assets/
upstream '= /api/v1/agents/stats'    backend 8006 GET  /api/v1/agents/stats
upstream '~ ^/api/v1/agents/(.*)$'   backend 8006 POST /api/v1/agents/analyze
upstream '= /api/v1/tools'           backend 8000 GET  /api/v1/tools
upstream '~ ^/api/v1/tools/(.*)$'    backend 8000 POST /api/v1/tools/whois
upstream '= /api/v1/tasks'           backend 8000 GET  /api/v1/tasks
upstream '^~ /api/v1/tasks/'         backend 8000 GET  /api/v1/tasks/1f0c4ea6

# --- Every proxying location is classified -----------------------------------
echo "== Locations =="
LOCATIONS="$WORK/locations"
if ! python3 "$HERE/authenticated_locations.py" --proxying "$GATEWAY_CONF" > "$LOCATIONS"; then
    fail "could not read the locations of $GATEWAY_CONF"
fi
if [ -s "$LOCATIONS" ]; then
    pass "read $(wc -l < "$LOCATIONS" | tr -d ' ') proxying locations from $(basename "$GATEWAY_CONF")"
else
    fail "no proxying location found in $GATEWAY_CONF"
fi
while IFS= read -r location; do
    if grep -Fxq -- "$location" "$CLASSIFIED"; then
        pass "location $location is classified"
    else
        fail "location $location proxies but is not classified: say above what its upstream is, and what it may be sent"
    fi
done < "$LOCATIONS"
sort -u "$CLASSIFIED" | while IFS= read -r location; do
    grep -Fxq -- "$location" "$LOCATIONS" || echo "$location"
done > "$WORK/stale"
if [ -s "$WORK/stale" ]; then
    fail "classified but not a proxying location of $(basename "$GATEWAY_CONF"): $(tr '\n' ';' < "$WORK/stale")"
else
    pass "every classification names a location of $(basename "$GATEWAY_CONF")"
fi

# --- n8n is not behind the gateway (#714) -------------------------------------
echo "== Automations =="
# The mock still answers where n8n would be (open-security-automations:5678),
# so a location that proxied there again would be seen to reach it.
#
# not_routed <name> <method> <path> <curl args...>: the gateway's own 404,
# whoever asks; nothing was proxied.
not_routed() {
    local name="$1" method="$2" path="$3" status
    shift 3
    status=$(curl -sk --path-as-is -o "$WORK/body" -w "%{http_code}" -X "$method" "$@" "$GATEWAY_PROD_URL$path")
    if [ "$status" = 404 ] && [ "$(jq -r '.error' "$WORK/body" 2>/dev/null)" = endpoint_not_found ] \
            && [ "$(jq -r '.headers | type' "$WORK/body" 2>/dev/null)" != object ]; then
        pass "$method $path, $name: 404, nothing is reached"
    else
        fail "$method $path, $name: HTTP $status, port '$(jq -r '.port' "$WORK/body" 2>/dev/null)' — $(head -c 160 "$WORK/body")"
    fi
}
# The editor, the REST API (the owner setup among it), a webhook, the public
# API, and the prefix itself with and without its slash.
for target in "GET /api/v1/automations/" "GET /api/v1/automations" \
        "GET /api/v1/automations/rest/workflows" "POST /api/v1/automations/rest/owner/setup" \
        "GET /api/v1/automations/rest/settings" "POST /api/v1/automations/webhook/incident" \
        "POST /api/v1/automations/webhook-test/incident" "GET /api/v1/automations/api/v1/workflows" \
        "GET /api/v1/automations/healthz"; do
    method="${target%% *}"
    path="${target#* }"
    not_routed "without a credential" "$method" "$path"
    not_routed "a session" "$method" "$path" -H "Authorization: Bearer $SESSION"
    not_routed "a session with its cookie" "$method" "$path" -H "Authorization: Bearer $SESSION" -H "Cookie: $SESSION_COOKIE"
    not_routed "a tools:admin key" "$method" "$path" -H "X-API-Key: wsk_scoped~upstream-admin~tools:admin"
    not_routed "an admin key" "$method" "$path" -H "X-API-Key: wsk_scoped~upstream-full~admin"
    not_routed "an unlimited key" "$method" "$path" -H "X-API-Key: wsk_scoped~upstream-star~*"
done
# And n8n's own credentials open nothing either.
not_routed "n8n's own API key and cookie" GET /api/v1/automations/api/v1/workflows \
    -H "X-N8N-API-KEY: n8n-own-key" -H "Cookie: n8n-auth=n8n-own-session"

# No proxying location names n8n: the inventory the classification above was
# checked against holds Wildbox's services only.
if grep -Eq 'automations|n8n|5678' "$LOCATIONS"; then
    fail "a proxying location names n8n: $(grep -E 'automations|n8n|5678' "$LOCATIONS" | tr '\n' ';')"
else
    pass "no proxying location names n8n"
fi
if grep -Ev '^[[:space:]]*#' "$GATEWAY_CONF" | grep -Eq 'automations|n8n|:5678'; then
    fail "$(basename "$GATEWAY_CONF") still names n8n outside its comments"
else
    pass "$(basename "$GATEWAY_CONF") names n8n in comments only"
fi

# --- The session cookie, in the shapes a browser sends it ---------------------
echo "== Session cookie =="
# cookie_reaching_backend <sent> <expected or "absent">
cookie_reaching_backend() {
    local sent="$1" expected="$2" got
    curl -sk -o "$WORK/body" -H "Authorization: Bearer $SESSION" -H "Cookie: $sent" \
        "$GATEWAY_PROD_URL/api/v1/tools/whois" > /dev/null
    got=$(header cookie)
    if [ "$got" = "$expected" ]; then
        pass "Cookie '$sent' reaches a backend as '$expected'"
    else
        fail "Cookie '$sent': the backend received '$got', expected '$expected'"
    fi
}
cookie_reaching_backend "$SESSION_COOKIE" absent
cookie_reaching_backend "auth_token=a.b.c; theme=dark" "theme=dark"
cookie_reaching_backend "theme=dark;auth_token=a.b.c" "theme=dark"
cookie_reaching_backend "theme=dark;  auth_token=a.b.c ;lang=it" "theme=dark; lang=it"
cookie_reaching_backend "auth_token=a.b.c; auth_token=d.e.f" absent
# Only that cookie: a name that merely contains or extends it is another one.
cookie_reaching_backend "my_auth_token=1; auth_token_hint=2" "my_auth_token=1; auth_token_hint=2"
cookie_reaching_backend "theme=dark" "theme=dark"

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
