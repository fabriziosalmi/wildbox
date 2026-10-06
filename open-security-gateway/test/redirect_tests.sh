#!/usr/bin/env bash
# What a client is told when guardian redirects (#665, #776) -- run against
# the PRODUCTION image (Dockerfile, nginx/conf.d/wildbox_gateway.conf) wired
# to test/mock_identity.py, which answers on guardian's name and port and
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
# serves (#665).
#
# And the address the client used has a port. nginx completed the path the
# gateway wrote into an absolute URL with the port it listens on, 443, which
# it leaves out: a client that called https://<host>:8443 was sent to
# https://<host>/..., where nothing of the gateway answers (#776). The
# harness publishes the gateway on a port that is not 443, so every check
# below is that case; the Location is resolved as a client resolves it,
# against the URL that was asked for, and must stay on its host and port.

set -u

GATEWAY_PROD_URL="${GATEWAY_PROD_URL:-https://localhost:8443}"

PASS=0
FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

SESSION="prod-harness-session-token"

# location_of <method> <path> [curl option...]: prints "<status> <Location>"
# of one request, without following the redirect.
location_of() {
    local method="$1" path="$2" status
    shift 2
    status=$(curl -sk --path-as-is -o /dev/null -D "$WORK/headers" -w "%{http_code}" \
        -X "$method" -H "Authorization: Bearer $SESSION" "$@" "$GATEWAY_PROD_URL$path")
    printf '%s %s\n' "$status" \
        "$(tr -d '\r' < "$WORK/headers" | awk 'tolower($1) == "location:" { print $2 }')"
}

# resolved <origin> <Location>: where a client that asked <origin> goes. A
# Location that is a path is taken on the scheme, host and port of the
# request (RFC 9110, section 10.2.2); an absolute one is taken as it is.
resolved() {
    case "$2" in
        /*) printf '%s%s\n' "$1" "$2" ;;
        *) printf '%s\n' "$2" ;;
    esac
}

# redirected <name> <method> <path> <expected path> [origin] [curl option...]
#
# The origin is what the client called: scheme, host and port. The default is
# the address the harness publishes the gateway on; a case that sends a Host
# header of its own names the origin that header stands for.
redirected() {
    local name="$1" method="$2" path="$3" expected="$4" origin="${5:-$GATEWAY_PROD_URL}" got location
    shift 4
    [ "$#" -gt 0 ] && shift
    got=$(location_of "$method" "$path" "$@")
    location="${got#* }"
    if [ "${got%% *}" = 301 ] && [ "$(resolved "$origin" "$location")" = "$origin$expected" ]; then
        pass "$method $path ($name): Location '$location' leads to $origin$expected"
    else
        fail "$method $path ($name): expected a 301 leading to $origin$expected, got '$got'"
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

# The redirect nginx writes itself, for the location's path without its
# slash: it is completed the same way, and stays on the client's port too.
redirected "the location without its slash" GET \
    /api/v1/guardian \
    /api/v1/guardian/

# The same over HTTP/1.1: nginx writes the header of each protocol with
# code of its own.
redirected "APPEND_SLASH, HTTP/1.1" GET \
    /api/v1/guardian/redirect-fixture/append-slash \
    /api/v1/guardian/redirect-fixture/append-slash/ "$GATEWAY_PROD_URL" --http1.1
redirected "absolute, HTTP/1.1" GET \
    /api/v1/guardian/redirect-fixture/absolute-https \
    /api/v1/guardian/redirect-fixture/absolute-https/ "$GATEWAY_PROD_URL" --http1.1

# A gateway reached by another name and port than the harness's: behind a
# balancer or a NAT, the Host header is all the gateway sees of the address
# the client called. Whatever it names, the client stays there.
for origin in https://gateway.example.test:9443 https://gateway.example.test https://203.0.113.7:8443; do
    for fixture in append-slash absolute-https absolute-http; do
        redirected "called as ${origin#https://}" GET \
            "/api/v1/guardian/redirect-fixture/$fixture" \
            "/api/v1/guardian/redirect-fixture/$fixture/" \
            "$origin" -H "Host: ${origin#https://}"
    done
done

# And a client that follows the redirect arrives: curl is given the path
# without its slash and nothing else, and reaches guardian on the path with
# it, through the gateway it called, in one redirect.
followed=$(curl -sk --path-as-is -L --max-redirs 3 --max-time 20 -o "$WORK/body" \
    -w '%{http_code} %{num_redirects} %{url_effective}' -H "Authorization: Bearer $SESSION" \
    "$GATEWAY_PROD_URL/api/v1/guardian/redirect-fixture/append-slash")
if [ "$followed" = "200 1 $GATEWAY_PROD_URL/api/v1/guardian/redirect-fixture/append-slash/" ] \
        && [ "$(jq -r '.port' "$WORK/body" 2>/dev/null)" = 8013 ] \
        && [ "$(jq -r '.path' "$WORK/body" 2>/dev/null)" = /api/v1/redirect-fixture/append-slash/ ]; then
    pass "a client that follows the redirect reaches guardian on its path with the slash ($followed)"
else
    fail "a client that follows the redirect: '$followed', port '$(jq -r '.port' "$WORK/body" 2>/dev/null)', path '$(jq -r '.path' "$WORK/body" 2>/dev/null)' — $(head -c 160 "$WORK/body" 2>/dev/null)"
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
