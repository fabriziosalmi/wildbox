#!/usr/bin/env bash
# Gateway auth-logic tests (#108) — run against the Dockerfile.test gateway
# wired to test/mock_identity.py (see .github/workflows/gateway-tests.yml).
#
# Covers the auth boundary end-to-end through real OpenResty + auth_handler.lua:
#   * unauthenticated / invalid-token rejection
#   * X-Wildbox-* header injection stripping (anti-spoofing)
#   * Authorization / X-API-Key stripping before proxying upstream
#   * API-key scope enforcement (tools:read / tools:execute mapping + hierarchy)
#   * X-Gateway-Secret proof-of-origin propagation (wrong secret -> 403)
#   * auth-cache short-circuit (one /internal/authorize call for N requests)

set -u

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
GATEWAY_WRONG_URL="${GATEWAY_WRONG_URL:-http://localhost:8081}"
MOCK_URL="${MOCK_URL:-http://localhost:8001}"

PASS=0
FAIL=0

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

# request <name> <expected_status> <curl args...> ; body left in $BODY
request() {
    local name="$1" expected="$2"
    shift 2
    BODY=$(curl -s -o /tmp/body.json -w "%{http_code}" "$@")
    local status="$BODY"
    BODY=$(cat /tmp/body.json)
    if [ "$status" = "$expected" ]; then
        pass "$name (HTTP $status)"
        return 0
    else
        fail "$name: expected HTTP $expected, got $status — body: $(head -c 300 /tmp/body.json)"
        return 1
    fi
}

json_field() { echo "$BODY" | jq -r "$1"; }

assert_json() {
    local name="$1" filter="$2" expected="$3"
    local actual
    actual=$(json_field "$filter")
    if [ "$actual" = "$expected" ]; then
        pass "$name ($filter = $expected)"
    else
        fail "$name: expected $filter = '$expected', got '$actual'"
    fi
}

echo "== Gateway auth tests against $GATEWAY_URL =="

# 1. Health endpoint is public
request "health endpoint" 200 "$GATEWAY_URL/health"

# 2. No credentials -> 401 authentication_required
request "no token rejected" 401 "$GATEWAY_URL/api/v1/auth/me"
assert_json "no-token error code" '.error' 'authentication_required'

# 3. Invalid bearer token -> 401 invalid_token (mock returns 401)
request "invalid bearer rejected" 401 \
    -H "Authorization: Bearer not-a-real-token" "$GATEWAY_URL/api/v1/auth/me"
assert_json "invalid-token error code" '.error' 'invalid_token'

# 4. Valid bearer -> proxied; backend sees validated X-Wildbox-* and no
#    client credential headers
request "valid bearer accepted" 200 \
    -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_URL/api/v1/auth/me"
assert_json "X-Wildbox-User-ID injected" '.headers["x-wildbox-user-id"]' 'user-1111'
assert_json "X-Wildbox-Team-ID injected" '.headers["x-wildbox-team-id"]' 'team-2222'
assert_json "X-Wildbox-Role injected" '.headers["x-wildbox-role"]' 'admin'
assert_json "Authorization stripped upstream" '.headers.authorization // "absent"' 'absent'
assert_json "X-API-Key stripped upstream" '.headers["x-api-key"] // "absent"' 'absent'

# 5. Header injection: forged X-Wildbox-* must be replaced by validated values
request "header-injection attempt proxied" 200 \
    -H "Authorization: Bearer valid-bearer-token" \
    -H "X-Wildbox-User-ID: attacker" \
    -H "X-Wildbox-Team-ID: attacker-team" \
    -H "X-Wildbox-Role: superadmin" \
    "$GATEWAY_URL/api/v1/auth/me"
assert_json "forged user-id overwritten" '.headers["x-wildbox-user-id"]' 'user-1111'
assert_json "forged team-id overwritten" '.headers["x-wildbox-team-id"]' 'team-2222'
assert_json "forged role overwritten" '.headers["x-wildbox-role"]' 'admin'

# 6/7. Read-only API key: GET allowed (generic read satisfies tools:read),
#      POST requires tools:execute -> 403 insufficient_scope
request "read-only key GET allowed" 200 \
    -H "X-API-Key: wsk_readonly_ci_fixture" "$GATEWAY_URL/api/v1/tools/echo"
request "read-only key POST blocked" 403 \
    -X POST -H "X-API-Key: wsk_readonly_ci_fixture" "$GATEWAY_URL/api/v1/tools/echo"
assert_json "scope error code" '.error' 'insufficient_scope'
assert_json "required scope surfaced" '.required_scope' 'tools:execute'

# 8/9. tools:execute key: POST allowed, and execute satisfies tools:read
request "tools:execute key POST allowed" 200 \
    -X POST -H "X-API-Key: wsk_toolsexec_ci_fixture" "$GATEWAY_URL/api/v1/tools/echo"
request "tools:execute key GET allowed" 200 \
    -H "X-API-Key: wsk_toolsexec_ci_fixture" "$GATEWAY_URL/api/v1/tools/echo"

# 10. Auth cache: the two valid-bearer requests above (tests 4 and 5) must
#     have produced exactly ONE /internal/authorize call
request "mock call counts readable" 200 "$MOCK_URL/__mock/counts"
assert_json "auth cache short-circuits revalidation" '."valid-bearer-token"' '1'

# 11. Proof-of-origin: a gateway configured with the wrong
#     GATEWAY_INTERNAL_SECRET is rejected by identity (403) and must NOT
#     let the request through
request "wrong gateway secret -> forbidden" 403 \
    -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_WRONG_URL/api/v1/auth/me"

# 12. Oversized token rejected (nginx header limits or the Lua >4096 guard —
#     either layer must refuse it)
BIGTOKEN=$(printf 'a%.0s' $(seq 1 5000))
request "oversized token rejected" 400 \
    -H "Authorization: Bearer $BIGTOKEN" "$GATEWAY_URL/api/v1/auth/me"

# --- CORS (dashboard on a separate origin) ---------------------------------
echo "== CORS =="
# 13. Preflight from an ALLOWED origin (localhost): echoed origin.
ACAO=$(curl -sk -o /dev/null -D - -X OPTIONS \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    "$GATEWAY_URL/auth/jwt/login" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}')
if [ "$ACAO" = "http://localhost:3000" ]; then
    pass "CORS preflight echoes an allowed origin"
else
    fail "CORS preflight: expected origin echoed, got '$ACAO'"
fi

# 14. Credentials flag present on the preflight.
ACAC=$(curl -sk -o /dev/null -D - -X OPTIONS \
    -H "Origin: http://localhost:3000" "$GATEWAY_URL/auth/jwt/login" 2>/dev/null \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-credentials"{print $2}')
if [ "$ACAC" = "true" ]; then
    pass "CORS allows credentials"
else
    fail "CORS: expected Allow-Credentials true, got '$ACAC'"
fi

# 15. A DISALLOWED origin gets NO Access-Control-Allow-Origin header (the
#     security-critical case: the browser then blocks the response).
EVIL=$(curl -sk -o /dev/null -D - -X OPTIONS \
    -H "Origin: https://evil.example" "$GATEWAY_URL/auth/jwt/login" 2>/dev/null \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}')
if [ -z "$EVIL" ]; then
    pass "CORS does not echo a disallowed origin"
else
    fail "CORS LEAK: echoed disallowed origin '$EVIL'"
fi

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
