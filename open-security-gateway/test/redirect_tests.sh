#!/usr/bin/env bash
# What a client is told when guardian redirects (#665) -- run against the
# PRODUCTION image (Dockerfile, nginx/conf.d/wildbox_gateway.conf) wired to
# test/mock_identity.py, which answers on guardian's name and port and
# redirects the paths in its REDIRECT_FIXTURES as a Django service does (see
# .github/workflows/gateway-tests.yml).
#
# The gateway serves guardian's /api/v1/<x> as /api/v1/guardian/<x>, and
# presents guardian its own name as Host. A Location guardian writes
# therefore names a path, and sometimes a host, that mean nothing to the
# client: the gateway has to write it back to the address the client used.
#
# It did for an absolute Location (http://open-security-guardian/...), and
# not for the one a client meets most: Django's APPEND_SLASH answers a
# request without its trailing slash with the path alone,
# "/api/v1/assets/assets/". That went to the client as it was, and following
# it led to the gateway's own 404 for a path under /api/ that no location
# serves.

set -u

GATEWAY_PROD_URL="${GATEWAY_PROD_URL:-https://localhost:8443}"

PASS=0
FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

SESSION="prod-harness-session-token"

# location_of <method> <path>: prints "<status> <Location>" of one request,
# without following the redirect.
location_of() {
    local method="$1" path="$2" status
    status=$(curl -sk --path-as-is -o /dev/null -D "$WORK/headers" -w "%{http_code}" \
        -X "$method" -H "Authorization: Bearer $SESSION" "$GATEWAY_PROD_URL$path")
    printf '%s %s\n' "$status" \
        "$(tr -d '\r' < "$WORK/headers" | awk 'tolower($1) == "location:" { print $2 }')"
}

# The gateway answers with an absolute Location: nginx completes the path it
# rewrote with the scheme and the name the client used, and leaves out the
# port it listens on (443).
HOST="${GATEWAY_PROD_URL#*://}"
HOST="${HOST%%[:/]*}"

# redirected <name> <method> <path> <expected path>
redirected() {
    local name="$1" method="$2" path="$3" expected="$4" got
    got=$(location_of "$method" "$path")
    if [ "$got" = "301 https://$HOST$expected" ] || [ "$got" = "301 $expected" ]; then
        pass "$method $path ($name): Location is ${got#301 }"
    else
        fail "$method $path ($name): expected a 301 to $expected on $HOST, got '$got'"
    fi
}

echo "== Guardian redirects against $GATEWAY_PROD_URL =="

# The redirect of a path without its trailing slash: a path alone.
redirected "APPEND_SLASH, a path alone" GET \
    /api/v1/guardian/redirect-fixture/append-slash \
    /api/v1/guardian/redirect-fixture/append-slash/
redirected "APPEND_SLASH, a path alone" POST \
    /api/v1/guardian/redirect-fixture/append-slash \
    /api/v1/guardian/redirect-fixture/append-slash/

# An absolute Location on the name the gateway presents to guardian.
redirected "absolute, https" GET \
    /api/v1/guardian/redirect-fixture/absolute-https \
    /api/v1/guardian/redirect-fixture/absolute-https/
redirected "absolute, http" GET \
    /api/v1/guardian/redirect-fixture/absolute-http \
    /api/v1/guardian/redirect-fixture/absolute-http/

# And the path the client is sent to is one the gateway serves: asked for,
# it reaches guardian again, on its path with the slash. (The harness
# publishes the gateway on another port than the one nginx names, so the
# path is taken from the Location and asked for here.)
target=$(location_of GET /api/v1/guardian/redirect-fixture/append-slash)
target="${target#301 }"
target="${target#https://"$HOST"}"
status=$(curl -sk --path-as-is -o "$WORK/body" -w "%{http_code}" -H "Authorization: Bearer $SESSION" \
    "$GATEWAY_PROD_URL$target")
if [ "$status" = 200 ] && [ "$(jq -r '.port' "$WORK/body" 2>/dev/null)" = 8013 ] \
        && [ "$(jq -r '.path' "$WORK/body" 2>/dev/null)" = /api/v1/redirect-fixture/append-slash/ ]; then
    pass "the redirect's path ($target) reaches guardian on its path with the slash"
else
    fail "the redirect's path ($target): HTTP $status, port '$(jq -r '.port' "$WORK/body" 2>/dev/null)', path '$(jq -r '.path' "$WORK/body" 2>/dev/null)' — $(head -c 160 "$WORK/body")"
fi

# No internal name reaches the client in any of them.
for path in append-slash absolute-https absolute-http; do
    got=$(location_of GET "/api/v1/guardian/redirect-fixture/$path")
    case "$got" in
        *open-security-guardian*) fail "$path: the Location names the internal host: $got" ;;
        *) pass "$path: the Location names no internal host" ;;
    esac
done

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
