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
#
# That was fixed for guardian's location alone. Every other redirect the
# HTTPS server writes lost the port the same way, and they are all asked for
# here (#788): nginx's own 301 for each proxied prefix location asked
# without its trailing slash, read from the configuration so that a new
# location is asked too, and a Location an upstream writes on its own name,
# which the location's default proxy_redirect turns into a path. What the
# server does not write is checked as well: a Location no proxy_redirect
# matches leaves as the upstream wrote it.
#
# Last, the two plain-HTTP listeners (80 and 8080), asked inside the
# container: they redirect to HTTPS on the name the client called when it is
# one of the gateway's own, and on the first of those names for any other
# Host, so that nothing a client sends chooses where the redirect leads.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_PROD_URL="${GATEWAY_PROD_URL:-https://localhost:8443}"
GATEWAY_PROD_CONTAINER="${GATEWAY_PROD_CONTAINER:-gateway-prod}"
GATEWAY_CONF="${GATEWAY_CONF:-$HERE/../nginx/conf.d/wildbox_gateway.conf}"

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
echo "== The redirect nginx writes for a location asked without its slash =="

# Every prefix location of the configuration that ends with a slash, asked
# without it. nginx answers 301 when the location proxies, and then the
# Location must keep the client where it is; a location that does not
# redirect (it does not proxy, or an exact location answers the path) has
# nothing to check. The ones that redirect are then compared with the list
# below, so that a redirect that stops, or a location added without being
# looked at, fails here.
PREFIX_LOCATIONS=$(awk '
    /^[[:space:]]*location[[:space:]]+(\^~[[:space:]]+)?\/[^[:space:]]*\/[[:space:]]*\{/ {
        print $(NF - 1)
    }' "$GATEWAY_CONF" | sort -u)
EXPECTED_REDIRECTING="/api/v1/cspm/ /api/v1/data/ /api/v1/guardian/ /api/v1/identity/ /api/v1/identity/auth/ /api/v1/responder/ /auth/jwt/ /auth/users/ /ws/"
REDIRECTING=""
for location in $PREFIX_LOCATIONS; do
    bare="${location%/}"
    got=$(location_of GET "$bare")
    [ "${got%% *}" = 301 ] || continue
    REDIRECTING="$REDIRECTING $location"
    redirected "the location without its slash" GET "$bare" "$location"
    redirected "the location without its slash, HTTP/1.1" GET "$bare" "$location" \
        "$GATEWAY_PROD_URL" --http1.1
    redirected "the location without its slash, called as gateway.example.test:9443" GET \
        "$bare" "$location" https://gateway.example.test:9443 -H "Host: gateway.example.test:9443"
done
REDIRECTING="${REDIRECTING# }"
if [ "$REDIRECTING" = "$EXPECTED_REDIRECTING" ]; then
    pass "the locations that redirect a path without its slash are the nine known ones"
else
    fail "the locations that redirect are '$REDIRECTING', expected '$EXPECTED_REDIRECTING'"
fi

# A client that follows one arrives, as for guardian above: the data service
# on its /api/v1/ tree, through the gateway it called, in one redirect.
followed=$(curl -sk --path-as-is -L --max-redirs 3 --max-time 20 -o "$WORK/body" \
    -w '%{http_code} %{num_redirects} %{url_effective}' -H "Authorization: Bearer $SESSION" \
    "$GATEWAY_PROD_URL/api/v1/data")
if [ "$followed" = "200 1 $GATEWAY_PROD_URL/api/v1/data/" ] \
        && [ "$(jq -r '.port' "$WORK/body" 2>/dev/null)" = 8002 ] \
        && [ "$(jq -r '.path' "$WORK/body" 2>/dev/null)" = /api/v1/ ]; then
    pass "a client that follows /api/v1/data reaches the data service ($followed)"
else
    fail "a client that follows /api/v1/data: '$followed', port '$(jq -r '.port' "$WORK/body" 2>/dev/null)', path '$(jq -r '.path' "$WORK/body" 2>/dev/null)' — $(head -c 160 "$WORK/body" 2>/dev/null)"
fi

echo
echo "== A Location an upstream writes on its own name =="

# The default proxy_redirect of a location rewrites the upstream's own URL,
# http://<upstream>/<its path>, to the location's path; nginx completed that
# path as it did guardian's. The mock answers with such a Location on the
# ports of these three services.
for service in identity data cspm; do
    for origin in "$GATEWAY_PROD_URL" https://gateway.example.test:9443; do
        redirected "the upstream's own URL, called as ${origin#https://}" GET \
            "/api/v1/$service/redirect-fixture/upstream-name" \
            "/api/v1/$service/redirect-fixture/upstream-name/" \
            "$origin" -H "Host: ${origin#https://}"
    done
    got=$(location_of GET "/api/v1/$service/redirect-fixture/upstream-name")
    case "$got" in
        *_service*) fail "$service: the Location names the upstream: $got" ;;
        *) pass "$service: the Location does not name the upstream" ;;
    esac
done

# What the server does not write. A Location that no proxy_redirect matches
# leaves as the upstream wrote it, a path or an absolute URL: only the
# guardian location rewrites a path, and only for guardian's name.
unchanged() {
    local name="$1" path="$2" expected="$3" got
    got=$(location_of GET "$path")
    if [ "$got" = "301 $expected" ]; then
        pass "GET $path ($name): the Location is the upstream's, '$expected'"
    else
        fail "GET $path ($name): expected the upstream's Location '$expected', got '$got'"
    fi
}
unchanged "a path no proxy_redirect matches" \
    /api/v1/data/redirect-fixture/append-slash /api/v1/redirect-fixture/append-slash/
unchanged "an absolute URL no proxy_redirect matches" \
    /api/v1/data/redirect-fixture/absolute-http \
    http://open-security-guardian/api/v1/redirect-fixture/absolute-http/

echo
echo "== The plain-HTTP listeners of $GATEWAY_PROD_CONTAINER redirect to HTTPS =="

# http_redirected <port> <Host> <expected host>: one request to the listener,
# from inside the container (the harness publishes the HTTPS port only). The
# path and the query string are kept.
http_redirected() {
    local port="$1" host="$2" expected="https://$3/api/v1/data/x?y=1" got
    got=$(docker exec "$GATEWAY_PROD_CONTAINER" curl -s -o /dev/null -D - \
        -H "Host: $host" "http://127.0.0.1:$port/api/v1/data/x?y=1" | tr -d '\r' \
        | awk 'NR == 1 { status = $2 } tolower($1) == "location:" { location = $2 }
               END { print status, location }')
    if [ "$got" = "301 $expected" ]; then
        pass "port $port, Host '$host': redirected to $expected"
    else
        fail "port $port, Host '$host': expected a 301 to $expected, got '$got'"
    fi
}

# The names of the listener, from its server_name: each is kept, a name
# under the wildcard included.
NAMES=$(awk '/^[[:space:]]*server_name[[:space:]]/ {
        for (i = 2; i <= NF; i++) { sub(/;$/, "", $i); print $i }
        exit
    }' "$GATEWAY_CONF")
FIRST_NAME=$(printf '%s\n' "$NAMES" | head -1)
if [ -n "$FIRST_NAME" ] && [ "$(printf '%s\n' "$NAMES" | wc -l)" -ge 2 ]; then
    pass "the configuration names the gateway ($(printf '%s' "$NAMES" | tr '\n' ' '))"
else
    fail "no server_name with two names or more was read from $GATEWAY_CONF"
fi
for port in 80 8080; do
    for name in $NAMES; do
        case "$name" in
            \*.*) called="any-name.${name#\*.}" ;;
            *) called="$name" ;;
        esac
        http_redirected "$port" "$called" "$called"
    done
    # As nginx reads a Host: without its port, in lower case.
    http_redirected "$port" "$(printf '%s' "$FIRST_NAME" | tr '[:lower:]' '[:upper:]'):8080" "$FIRST_NAME"
    # A Host that is none of them is not written: the first name, as before.
    # The last two only look like one of the names.
    for other in gateway.example.test evil.example localhost 203.0.113.7 \
            "$FIRST_NAME.evil.example" evilwildbox.local; do
        http_redirected "$port" "$other" "$FIRST_NAME"
    done
done

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
