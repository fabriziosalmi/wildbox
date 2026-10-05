#!/usr/bin/env bash
# CORS at the gateway (#712) -- run against the PRODUCTION image (Dockerfile,
# nginx/conf.d/wildbox_gateway.conf) and against the Dockerfile.test gateway,
# both wired to test/mock_identity.py and both started with
#
#   CORS_ORIGINS="https://dashboard.example.test, http://localhost:3000"
#
# (see .github/workflows/gateway-tests.yml).
#
# A dashboard served from another origin, and the dashboard's development
# server on http://localhost:3000, call the API cross-origin. The production
# configuration answered 405 to every OPTIONS request before any location
# ran, so no preflight was ever answered and such a page could log in and do
# nothing else. The CORS cases of the harness did not see it: they ran
# against the test configuration, which had no such rule. They are here now,
# against the configuration that ships, and the same checks are repeated on
# the test configuration so that the two cannot drift apart again.
#
# What is pinned:
#   * a preflight from a listed origin is answered 204 on every kind of API
#     route, without credentials and without reaching a service;
#   * from any other origin, and for any OPTIONS that is not a preflight,
#     the answer is 405 with no Access-Control-* header;
#   * a response to a listed origin names that origin and allows
#     credentials, the gateway's own refusals included; never "*", never
#     two values, whatever the service behind says;
#   * a response to another origin names nobody, whatever the service says;
#   * the dashboard's pages are not labelled;
#   * the allowlist is CORS_ORIGINS and nothing else: localhost on another
#     port is no longer allowed by itself.

set -u

GATEWAY_PROD_URL="${GATEWAY_PROD_URL:-https://localhost:8443}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"

LISTED="https://dashboard.example.test"
LISTED_DEV="http://localhost:3000"

PASS=0
FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

# send <curl args...>: status in $STATUS, headers in $WORK/headers (CR removed).
send() {
    STATUS=$(curl -sk --path-as-is -o "$WORK/body" -D "$WORK/raw" -w "%{http_code}" "$@")
    tr -d '\r' < "$WORK/raw" > "$WORK/headers"
}

# header <name>: the value of a response header; lines <name>: how many.
# varies_on_origin: whether any Vary line names Origin (nginx adds a Vary of
# its own, for Accept-Encoding, on a line of its own).
header() { awk -F': ' -v h="$1" 'tolower($1)==h{sub(/^[^:]*: /, ""); print; exit}' "$WORK/headers"; }
varies_on_origin() { grep -i '^vary:' "$WORK/headers" | grep -qiw origin; }
lines() { awk -F': ' -v h="$1" 'tolower($1)==h{n++} END{print n+0}' "$WORK/headers"; }
cors_headers() { grep -ci '^access-control-' "$WORK/headers"; }

# preflight <base url> <origin> <method> <path>
preflight() {
    send -X OPTIONS -H "Origin: $2" -H "Access-Control-Request-Method: $3" \
        -H "Access-Control-Request-Headers: authorization, content-type" "$1$4"
}

# allowed <name>: the last response is a preflight answered for $ORIGIN.
allowed() {
    local name="$1"
    if [ "$STATUS" = 204 ] && [ "$(header access-control-allow-origin)" = "$ORIGIN" ] \
            && [ "$(lines access-control-allow-origin)" = 1 ] \
            && [ "$(header access-control-allow-credentials)" = true ] \
            && header access-control-allow-methods | grep -qw "$METHOD" \
            && header access-control-allow-headers | grep -qi 'authorization' \
            && header access-control-allow-headers | grep -qi 'content-type' \
            && [ -n "$(header access-control-max-age)" ] \
            && varies_on_origin \
            && [ ! -s "$WORK/body" ]; then
        pass "$name: preflight answered for $ORIGIN"
    else
        fail "$name: expected a 204 preflight for $ORIGIN, got HTTP $STATUS — $(grep -i '^access-control\|^vary' "$WORK/headers" | tr '\n' ';')"
    fi
}

# refused <name>: the last response is a 405 that names nobody.
refused() {
    local name="$1"
    if [ "$STATUS" = 405 ] && [ "$(cors_headers)" = 0 ]; then
        pass "$name: 405, no Access-Control-* header"
    else
        fail "$name: expected 405 without CORS headers, got HTTP $STATUS — $(grep -i '^access-control' "$WORK/headers" | tr '\n' ';')"
    fi
}

# labelled <name> <expected status>: the last response names $ORIGIN, once.
labelled() {
    local name="$1" expected="$2"
    if [ "$STATUS" = "$expected" ] && [ "$(header access-control-allow-origin)" = "$ORIGIN" ] \
            && [ "$(lines access-control-allow-origin)" = 1 ] \
            && [ "$(header access-control-allow-credentials)" = true ] \
            && [ "$(lines access-control-allow-credentials)" = 1 ] \
            && varies_on_origin; then
        pass "$name: HTTP $STATUS names $ORIGIN"
    else
        fail "$name: expected HTTP $expected naming $ORIGIN, got HTTP $STATUS — $(grep -i '^access-control\|^vary' "$WORK/headers" | tr '\n' ';')"
    fi
}

# unlabelled <name> <expected status>: the last response names nobody.
unlabelled() {
    local name="$1" expected="$2"
    if [ "$STATUS" = "$expected" ] && [ "$(cors_headers)" = 0 ]; then
        pass "$name: HTTP $STATUS names nobody"
    else
        fail "$name: expected HTTP $expected without CORS headers, got HTTP $STATUS — $(grep -i '^access-control' "$WORK/headers" | tr '\n' ';')"
    fi
}

# --- What both configurations must do alike ----------------------------------
# agree <label> <base url> <authenticated API path> <login path>
agree() {
    local label="$1" base="$2" api="$3" login="$4"
    echo "== $label ($base) =="

    for ORIGIN in "$LISTED" "$LISTED_DEV"; do
        for METHOD in GET POST DELETE; do
            preflight "$base" "$ORIGIN" "$METHOD" "$api"
            allowed "$label: $METHOD $api from $ORIGIN"
        done
        METHOD=POST
        preflight "$base" "$ORIGIN" POST "$login"
        allowed "$label: POST $login from $ORIGIN"
    done

    for origin in "https://evil.example" "http://localhost:3001" "http://127.0.0.1:3000" \
            "https://dashboard.example.test.evil.example" "https://dashboard.example.test/" \
            "http://dashboard.example.test" "null"; do
        preflight "$base" "$origin" POST "$api"
        refused "$label: preflight from $origin"
    done

    send -X OPTIONS "$base$api"
    refused "$label: OPTIONS without an Origin"
    # Not a preflight: no method is asked for. It is refused like any other
    # OPTIONS, and the refusal says nothing a preflight's answer would.
    send -X OPTIONS -H "Origin: $LISTED" "$base$api"
    if [ "$STATUS" = 405 ] && [ -z "$(header access-control-allow-methods)" ]; then
        pass "$label: OPTIONS from a listed origin that asks for no method: 405"
    else
        fail "$label: OPTIONS without Access-Control-Request-Method: HTTP $STATUS — $(grep -i '^access-control' "$WORK/headers" | tr '\n' ';')"
    fi

    # The methods no location is given.
    for method in PROPFIND MKCOL PURGE; do
        send -X "$method" -H "Authorization: Bearer prod-harness-session-token" "$base$api"
        if [ "$STATUS" = 405 ]; then
            pass "$label: $method refused (405)"
        else
            fail "$label: $method answered $STATUS, expected 405"
        fi
    done

    # A request, not a preflight: the gateway's own refusal is readable by
    # the page that is allowed to ask, and by no other.
    ORIGIN="$LISTED"
    send -H "Origin: $LISTED" "$base$api"
    labelled "$label: 401 without a credential" 401
    send -H "Origin: https://evil.example" "$base$api"
    unlabelled "$label: 401 to an unlisted origin" 401
    send -H "Origin: $LISTED" -H "Authorization: Bearer prod-harness-session-token" "$base$api"
    labelled "$label: 200 with a session" 200
    send -H "Authorization: Bearer prod-harness-session-token" "$base$api"
    unlabelled "$label: 200 to a request with no Origin" 200
    if varies_on_origin; then
        pass "$label: an API response varies on Origin even without one"
    else
        fail "$label: no Vary: Origin on an API response — Vary: '$(header vary)'"
    fi
}

agree "production configuration" "$GATEWAY_PROD_URL" /api/v1/tools/whois /auth/jwt/login
agree "test configuration" "$GATEWAY_URL" /api/v1/tools/echo /auth/jwt/login

# --- The production configuration, route by route ----------------------------
echo "== Every kind of API route, production configuration =="
ORIGIN="$LISTED"
METHOD=POST
for path in /api/v1/identity/users/me /api/v1/identity/auth/jwt/login /api/v1/identity/health \
        /auth/users/me /auth/register /auth/forgot-password /auth/reset-password /auth/logout \
        /api/v1/data/ingest /api/v1/data/health /api/v1/cspm/scans /api/v1/responder/playbooks \
        /api/v1/guardian/assets/assets/ /api/v1/agents/analyze /api/v1/agents/stats \
        /api/v1/tools /api/v1/tools/whois /api/v1/tasks /api/v1/tasks/1f0c4ea6 \
        /api/v1/no-such-service/x; do
    preflight "$GATEWAY_PROD_URL" "$LISTED" POST "$path"
    allowed "POST $path"
done

# The gateway's own answers, each readable by the listed origin.
send -H "Origin: $LISTED" "$GATEWAY_PROD_URL/api/v1/no-such-service/x"
labelled "404 from the catch-all" 404
send -H "Origin: $LISTED" -H "X-API-Key: wsk_scoped~cors-ingest~data:ingest" "$GATEWAY_PROD_URL/api/v1/tools/whois"
labelled "403 insufficient_scope" 403
send -H "Origin: $LISTED" -H "Authorization: Bearer not-a-real-token" "$GATEWAY_PROD_URL/api/v1/tools/whois"
labelled "401 invalid_token" 401
send -X POST -H "Origin: $LISTED" "$GATEWAY_PROD_URL/auth/jwt/login"
labelled "identity's login route" 200
send -H "Origin: $LISTED" -H "Authorization: Bearer prod-harness-session-token" "$GATEWAY_PROD_URL/api/v1/guardian/assets/assets/"
labelled "a route the gateway authenticates" 200
if header access-control-expose-headers | grep -qi 'x-ratelimit-remaining'; then
    pass "a page may read the rate limit headers"
else
    fail "Access-Control-Expose-Headers: '$(header access-control-expose-headers)'"
fi

# --- One authority: what the service behind says about CORS is replaced ------
echo "== A service with CORS headers of its own =="
# The mock answers with the Access-Control-Allow-Origin it is asked for in
# X-Mock-Allow-Origin, as a service with its own CORS middleware would.
for said in "*" "https://evil.example" "$LISTED"; do
    ORIGIN="$LISTED"
    send -H "Origin: $LISTED" -H "Authorization: Bearer prod-harness-session-token" \
        -H "X-Mock-Allow-Origin: $said" "$GATEWAY_PROD_URL/api/v1/tools/whois"
    labelled "the service says '$said', listed origin" 200
    if grep -i '^vary:' "$WORK/headers" | grep -qiw 'accept-encoding'; then
        pass "the service's own Vary is kept beside Origin"
    else
        fail "the service's Vary was lost: '$(grep -i '^vary:' "$WORK/headers" | tr '\n' ';')'"
    fi
    send -H "Origin: https://evil.example" -H "Authorization: Bearer prod-harness-session-token" \
        -H "X-Mock-Allow-Origin: $said" "$GATEWAY_PROD_URL/api/v1/tools/whois"
    unlabelled "the service says '$said', unlisted origin" 200
done

# --- The dashboard is not the API ---------------------------------------------
echo "== Dashboard pages =="
for path in / /dashboard /auth/login /auth/logout /assets/app.js; do
    send -H "Origin: $LISTED" "$GATEWAY_PROD_URL$path"
    unlabelled "GET $path from a listed origin" 200
    preflight "$GATEWAY_PROD_URL" "$LISTED" GET "$path"
    refused "preflight for $path"
done
# POST /auth/logout is identity's; the page of the same path is not.
ORIGIN="$LISTED"
send -X POST -H "Origin: $LISTED" -H "Authorization: Bearer prod-harness-session-token" "$GATEWAY_PROD_URL/auth/logout"
labelled "POST /auth/logout" 200

# --- Never a wildcard ----------------------------------------------------------
echo "== Wildcard =="
for origin in "$LISTED" "https://evil.example" "*"; do
    send -H "Origin: $origin" -H "Authorization: Bearer prod-harness-session-token" \
        -H "X-Mock-Allow-Origin: *" "$GATEWAY_PROD_URL/api/v1/tools/whois"
    if [ "$(header access-control-allow-origin)" = "*" ]; then
        fail "Origin '$origin': the response allows every origin"
    else
        pass "Origin '$origin': the response does not allow every origin"
    fi
done

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
