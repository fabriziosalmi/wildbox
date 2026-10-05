#!/usr/bin/env bash
# Gateway auth-logic tests (#108) — run against the Dockerfile.test gateway
# wired to test/mock_identity.py (see .github/workflows/gateway-tests.yml).
#
# Covers the auth boundary end-to-end through real OpenResty + auth_handler.lua:
#   * unauthenticated / invalid-token rejection
#   * X-Wildbox-* header injection stripping (anti-spoofing)
#   * Authorization / X-API-Key stripping before proxying upstream
#   * API-key scope enforcement (tools:read / tools:execute mapping + hierarchy;
#     a route without a row in the scope map requires admin, #647). The scope
#     of each production route is pinned in route_scope_tests.sh
#   * X-Gateway-Secret proof-of-origin propagation (wrong secret -> 403)
#   * auth-cache short-circuit (one /internal/authorize call for N requests)
#   * the removed standalone tools UI (/tools/ answers 404, #581)
#   * a dropped identity connection is retried once; 503s are JSON with
#     Retry-After (#609)
#   * the agents routes authenticate like every other route: JWT and API
#     key, scopes, must-change-password, cache, retry, rate limit (#630)
#   * the per-team budget is RATE_LIMIT_PER_HOUR, against a second gateway
#     started with a low value (#627)

set -u

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
GATEWAY_WRONG_URL="${GATEWAY_WRONG_URL:-http://localhost:8081}"
# A gateway started with RATE_LIMIT_PER_HOUR=120 (#627).
GATEWAY_LIMIT_URL="${GATEWAY_LIMIT_URL:-http://localhost:8083}"
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

# The whole body must be one JSON document. jq alone reads the first value
# and only complains on stderr about trailing text, which is how error bodies
# ending in "nil" went unnoticed (#571).
assert_strict_json() {
    local name="$1"
    if python3 -c 'import json, sys; json.loads(sys.stdin.read())' < /tmp/body.json 2>/dev/null; then
        pass "$name is strict JSON"
    else
        fail "$name is not strict JSON: $(head -c 300 /tmp/body.json)"
    fi
}

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
assert_strict_json "no-token error body"

# 3. Invalid bearer token -> 401 invalid_token (mock returns 401)
request "invalid bearer rejected" 401 \
    -H "Authorization: Bearer not-a-real-token" "$GATEWAY_URL/api/v1/auth/me"
assert_json "invalid-token error code" '.error' 'invalid_token'
assert_strict_json "invalid-token error body"

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

# 9-ingest. A sensor's data:ingest key (#628) sends telemetry and does nothing
#           else; a key without it cannot send telemetry.
request "data:ingest key posts a batch" 200 \
    -X POST -H "X-API-Key: wsk_ingest_ci_fixture" "$GATEWAY_URL/api/v1/data/ingest"
assert_json "batch reaches the data ingest route" '.path' '/api/v1/data/ingest'
assert_json "batch carries the key's team" '.headers["x-wildbox-team-id"]' 'team-8888'
assert_json "key stripped before the data service" '.headers["x-api-key"] // "absent"' 'absent'
request "data:ingest key cannot read telemetry" 403 \
    -H "X-API-Key: wsk_ingest_ci_fixture" "$GATEWAY_URL/api/v1/data/telemetry/events"
assert_json "reading needs read" '.required_scope' 'read'
request "data:ingest key cannot write other data" 403 \
    -X POST -H "X-API-Key: wsk_ingest_ci_fixture" "$GATEWAY_URL/api/v1/data/sources"
assert_json "other writes need write" '.required_scope' 'write'
request "data:ingest key cannot run tools" 403 \
    -X POST -H "X-API-Key: wsk_ingest_ci_fixture" "$GATEWAY_URL/api/v1/tools/echo"
request "read-only key cannot post a batch" 403 \
    -X POST -H "X-API-Key: wsk_readonly_ci_fixture" "$GATEWAY_URL/api/v1/data/ingest"
assert_json "ingest needs data:ingest" '.required_scope' 'data:ingest'
request "unrestricted session posts a batch" 200 \
    -X POST -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_URL/api/v1/data/ingest"

# 9a-9e. Asynchronous tool tasks (#567): routed to the service's /api/tasks,
#        authenticated, read with tools:read and cancelled with tools:execute.
request "task read without credentials rejected" 401 \
    "$GATEWAY_URL/api/v1/tasks/1f0c4ea6-task"
request "read-only key reads a task" 200 \
    -H "X-API-Key: wsk_readonly_ci_fixture" "$GATEWAY_URL/api/v1/tasks/1f0c4ea6-task"
assert_json "task path mapped upstream" '.path' '/api/tasks/1f0c4ea6-task'
request "read-only key lists tasks" 200 \
    -H "X-API-Key: wsk_readonly_ci_fixture" "$GATEWAY_URL/api/v1/tasks?limit=5"
assert_json "task list path mapped upstream" '.path' '/api/tasks?limit=5'
request "read-only key cannot cancel a task" 403 \
    -X DELETE -H "X-API-Key: wsk_readonly_ci_fixture" "$GATEWAY_URL/api/v1/tasks/1f0c4ea6-task"
assert_json "cancel needs tools:execute" '.required_scope' 'tools:execute'
request "tools:execute key cancels a task" 200 \
    -X DELETE -H "X-API-Key: wsk_toolsexec_ci_fixture" "$GATEWAY_URL/api/v1/tasks/1f0c4ea6-task"
assert_json "cancel reaches the service as DELETE" '.method' 'DELETE'

# 9f-9k. A route the scope map has no row for (#647) is closed to
#        scope-limited keys: it requires "admin", not the generic read or
#        write an unmapped path used to fall back to. /api/v1/auth/ is such a
#        route here (production has none: route_scope_tests.sh pins every
#        location of wildbox_gateway.conf). Sessions are not scope-limited.
UNMAPPED="$GATEWAY_URL/api/v1/auth/me"
request "unmapped route refuses a key with every lesser scope" 403 \
    -H "X-API-Key: wsk_scoped~unmapped-lesser~read,write,tools:admin,data:delete" "$UNMAPPED"
assert_json "unmapped route error code" '.error' 'insufficient_scope'
assert_json "unmapped route requires admin" '.required_scope' 'admin'
assert_strict_json "unmapped route error body"
request "unmapped route refuses a write, too" 403 -X POST \
    -H "X-API-Key: wsk_scoped~unmapped-lesser~read,write,tools:admin,data:delete" "$UNMAPPED"
assert_json "unmapped write requires admin" '.required_scope' 'admin'
request "unmapped route serves an admin key" 200 \
    -H "X-API-Key: wsk_scoped~unmapped-admin~admin" "$UNMAPPED"
request "unmapped route serves an unrestricted key" 200 \
    -H "X-API-Key: wsk_scoped~unmapped-star~*" "$UNMAPPED"
# The map reads the path from $wildbox_route_uri, which the server block
# fills in. Where it is empty the path is unknown, and unknown is unmapped:
# this location empties it and is otherwise a tools route. Its $uri is under
# /api/v1/tools, so a map that fell back to $uri would let these keys by.
UNROUTED="$GATEWAY_URL/api/v1/tools/unrouted/echo"
request "a route whose path the map cannot read is unmapped" 403 \
    -H "X-API-Key: wsk_toolsexec_ci_fixture" "$UNROUTED"
assert_json "unreadable path requires admin" '.required_scope' 'admin'
request "an unreadable path is not mapped by its \$uri" 403 -X POST \
    -H "X-API-Key: wsk_scoped~unmapped-lesser~read,write,tools:admin,data:delete" "$UNROUTED"
assert_json "unreadable path requires admin to write" '.required_scope' 'admin'
request "an unreadable path serves an admin key" 200 \
    -H "X-API-Key: wsk_scoped~unmapped-admin~admin" "$UNROUTED"
assert_json "unreadable path still proxied where the location says" '.path' '/api/v1/tools/echo'

# 10. Auth cache: the two valid-bearer requests above (tests 4 and 5) must
#     have produced exactly ONE /internal/authorize call
request "mock call counts readable" 200 "$MOCK_URL/__mock/counts"
assert_json "auth cache short-circuits revalidation" '."valid-bearer-token"' '1'

# 10b. An account that must change its initial password (#573) is refused
#      every service, on the first request and on the cached decision
#      alike, and nothing reaches the backend.
for attempt in first cached; do
    request "pending password change refused ($attempt)" 403 \
        -H "Authorization: Bearer pending-password-change-token" \
        "$GATEWAY_URL/api/v1/auth/me"
    assert_json "pending password change code ($attempt)" '.error' 'PASSWORD_CHANGE_REQUIRED'
    assert_json "backend not reached ($attempt)" '.headers // "absent"' 'absent'
done
assert_strict_json "pending password change error body"
request "mock call counts readable" 200 "$MOCK_URL/__mock/counts"
assert_json "pending decision cached" '."pending-password-change-token"' '1'

# --- Agents routes (#630) ---------------------------------------------------
# /api/v1/agents/* authenticated with its own inline Lua, which read
# X-API-Key only: a JWT got 401 NO_API_KEY. It now goes through
# authenticate(), with everything that carries.
echo "== agents routes =="
AGENTS="$GATEWAY_URL/api/v1/agents"
TASK="$AGENTS/analyze/1f0c4ea6-agents-task"

request "agents: no credential refused" 401 -X POST "$AGENTS/analyze"
assert_json "agents: no-credential error code" '.error' 'authentication_required'
assert_strict_json "agents: no-credential error body"

# The service reads the caller from X-Wildbox-*: the mock echoes the
# headers it received, so these assert the identity the service gets, set
# by proxy_params.conf from the variables authenticate() fills in, over
# any value the client sent.
request "agents: JWT accepted" 200 -X POST \
    -H "Authorization: Bearer valid-bearer-token" \
    -H "X-Wildbox-User-ID: attacker" -H "X-Wildbox-Team-ID: attacker-team" \
    -H "X-Wildbox-Role: superadmin" "$AGENTS/analyze"
assert_json "agents: path mapped to the service's /v1" '.path' '/v1/analyze'
assert_json "agents: method kept" '.method' 'POST'
assert_json "agents: JWT user forwarded" '.headers["x-wildbox-user-id"]' 'user-1111'
assert_json "agents: JWT team forwarded" '.headers["x-wildbox-team-id"]' 'team-2222'
assert_json "agents: JWT role forwarded" '.headers["x-wildbox-role"]' 'admin'
assert_json "agents: Authorization stripped upstream" '.headers.authorization // "absent"' 'absent'

request "agents: API key accepted" 200 -X POST \
    -H "X-API-Key: wsk_toolsexec_ci_fixture" "$AGENTS/analyze"
assert_json "agents: API-key user forwarded" '.headers["x-wildbox-user-id"]' 'user-5555'
assert_json "agents: API-key team forwarded" '.headers["x-wildbox-team-id"]' 'team-6666'
assert_json "agents: API-key role forwarded" '.headers["x-wildbox-role"]' 'user'
assert_json "agents: X-API-Key stripped upstream" '.headers["x-api-key"] // "absent"' 'absent'

request "agents: read-only key cannot submit" 403 -X POST \
    -H "X-API-Key: wsk_readonly_ci_fixture" "$AGENTS/analyze"
assert_json "agents: submitting needs tools:execute" '.required_scope' 'tools:execute'
request "agents: read-only key reads a task" 200 \
    -H "X-API-Key: wsk_readonly_ci_fixture" "$TASK?verbose=1"
assert_json "agents: task path and query mapped" '.path' '/v1/analyze/1f0c4ea6-agents-task?verbose=1'

request "agents: invalid JWT refused" 401 \
    -H "Authorization: Bearer not-a-real-token" "$TASK"
assert_json "agents: invalid-token error code" '.error' 'invalid_token'

request "agents: pending password change refused" 403 \
    -H "Authorization: Bearer pending-password-change-token" "$TASK"
assert_json "agents: pending password change code" '.error' 'PASSWORD_CHANGE_REQUIRED'
assert_json "agents: backend not reached" '.headers // "absent"' 'absent'

# The decisions above came from the same auth cache as every other route:
# identity was asked once for each token, whichever route it was used on.
request "mock call counts readable" 200 "$MOCK_URL/__mock/counts"
assert_json "agents: JWT decision served from the cache" '."valid-bearer-token"' '1'
assert_json "agents: password-change decision served from the cache" \
    '."pending-password-change-token"' '1'

# The service's /stats is outside its /v1 tree; it was unreachable.
request "agents: stats without credential refused" 401 "$AGENTS/stats"
request "agents: stats with a JWT" 200 \
    -H "Authorization: Bearer valid-bearer-token" "$AGENTS/stats"
assert_json "agents: stats mapped to the service's /stats" '.path' '/stats'
assert_json "agents: stats caller forwarded" '.headers["x-wildbox-user-id"]' 'user-1111'

# --- Proof of origin on authenticated requests only (#664) -----------------
# proxy_params.conf stamped X-Gateway-Secret on every proxied request, so an
# anonymous request through identity's passthrough reached identity carrying
# the secret, and the admin metrics there trusted it. The gateway now sends
# it only on a request authenticate() let through.
echo "== X-Gateway-Secret =="

# secret_forwarded: whether the echoed request carried the gateway's secret
# (match), another value (mismatch) or none (absent). The value itself is
# never printed.
secret_forwarded() {
    echo "$BODY" | jq -r --arg s "${CI_GATEWAY_SECRET:-}" \
        '.headers["x-gateway-secret"] | if . == null then "absent" elif . == $s then "match" else "mismatch" end'
}

assert_secret() {
    local name="$1" expected="$2" actual
    actual=$(secret_forwarded)
    if [ "$actual" = "$expected" ]; then
        pass "$name (X-Gateway-Secret $expected)"
    else
        fail "$name: expected X-Gateway-Secret $expected, got $actual"
    fi
}

if [ -z "${CI_GATEWAY_SECRET:-}" ]; then
    fail "CI_GATEWAY_SECRET is not set: the proof-of-origin checks cannot compare"
fi

request "authenticated route" 200 -X POST \
    -H "Authorization: Bearer valid-bearer-token" "$AGENTS/analyze"
assert_secret "authenticated request carries the proof of origin" match

request "identity passthrough, anonymous" 200 "$GATEWAY_URL/api/v1/identity/admin/metrics"
assert_json "passthrough path mapped" '.path' '/api/v1/admin/metrics'
assert_secret "anonymous passthrough request" absent

request "identity passthrough, forged secret" 200 \
    -H "X-Gateway-Secret: forged-by-the-client" "$GATEWAY_URL/api/v1/identity/admin/metrics"
assert_secret "client-supplied secret dropped on the passthrough" absent

request "identity passthrough, with a session" 200 \
    -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_URL/api/v1/identity/admin/metrics"
assert_secret "a session on the passthrough is not vouched for" absent
assert_json "identity still reads the bearer token itself" '.headers.authorization' 'Bearer valid-bearer-token'

request "authenticated route, forged secret" 200 -X POST \
    -H "Authorization: Bearer valid-bearer-token" \
    -H "X-Gateway-Secret: forged-by-the-client" "$AGENTS/analyze"
assert_secret "client-supplied secret replaced on an authenticated route" match

# A connection identity closed is retried once; an unreachable identity is
# a JSON 503 with Retry-After (#609).
DROP_ONCE_AGENTS="drop-once-agents-$(date +%s)-$$"
request "agents: authorization survives a dropped connection" 200 \
    -H "Authorization: Bearer $DROP_ONCE_AGENTS" "$TASK"
DROP_ALWAYS_AGENTS="drop-always-agents-$(date +%s)-$$"
STATUS=$(curl -s -o /tmp/body.json -D /tmp/headers.txt -w "%{http_code}" \
    -H "Authorization: Bearer $DROP_ALWAYS_AGENTS" "$TASK")
BODY=$(cat /tmp/body.json)
RETRY_AFTER=$(tr -d '\r' < /tmp/headers.txt | awk -F': ' 'tolower($1)=="retry-after"{print $2}')
if [ "$STATUS" = 503 ] && echo "$RETRY_AFTER" | grep -Eq '^[1-9][0-9]*$'; then
    pass "agents: identity unreachable answers 503 with Retry-After ($RETRY_AFTER)"
else
    fail "agents: identity unreachable: HTTP $STATUS, Retry-After '$RETRY_AFTER'"
fi
assert_json "agents: unreachable error code" '.error' 'service_unavailable'
assert_strict_json "agents: unreachable error body"

# The per-team rate limit applies: the gateway started with
# RATE_LIMIT_PER_HOUR=120 refuses the third request in a minute (see the
# RATE_LIMIT_PER_HOUR section below; this team is not used there).
refused=""
for attempt in 1 2 3 4 5; do
    STATUS=$(curl -s -o /tmp/body.json -w "%{http_code}" -X POST \
        -H "X-API-Key: wsk_toolsexec_ci_fixture" "$GATEWAY_LIMIT_URL/api/v1/agents/analyze")
    if [ "$STATUS" = 429 ]; then
        refused=$attempt
        break
    fi
done
BODY=$(cat /tmp/body.json)
if [ -n "$refused" ]; then
    pass "agents: the per-team rate limit applies (request $refused refused with 429)"
    assert_json "agents: rate limit error code" '.error' 'rate_limit_exceeded'
else
    fail "agents: five requests in a row were all served under a 2-a-minute budget (last HTTP $STATUS)"
fi

# 10c-10f. The standalone tools UI is removed (#581): /tools/ is an
#          explicit 404 from the gateway, with or without credentials, the
#          tools API is unaffected, and the auth_token cookie that only the
#          UI's page loads relied on is no longer a credential.
request "standalone tools UI is gone" 404 "$GATEWAY_URL/tools/"
assert_json "removed UI error code" '.error' 'endpoint_not_found'
assert_strict_json "removed UI error body"
if echo "$BODY" | grep -q "standalone tools UI was removed"; then
    pass "removed UI answered by its own location, not a catch-all"
else
    fail "removed UI: expected the /tools/ removal message, got: $(head -c 300 /tmp/body.json)"
fi
request "tool page gone even when authenticated" 404 \
    -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_URL/tools/hash_generator"
assert_json "authenticated tool page error code" '.error' 'endpoint_not_found'
request "tools API still served" 200 \
    -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_URL/api/v1/tools/echo"
assert_json "tools API reaches the service" '.path' '/api/v1/tools/echo'
request "auth_token cookie alone is not a credential" 401 \
    -H "Cookie: auth_token=valid-bearer-token" "$GATEWAY_URL/api/v1/tools/echo"
assert_json "cookie-only error code" '.error' 'authentication_required'

# 10g-10j. A connection identity closes under the gateway (#609). Asking
#          identity is a read, so the gateway sends it again on another
#          connection instead of answering 503; when identity cannot be
#          reached at all, the 503 is JSON and carries Retry-After.
DROP_ONCE="drop-once-$(date +%s)-$$"
request "authorization survives a dropped connection" 200 \
    -H "Authorization: Bearer $DROP_ONCE" "$GATEWAY_URL/api/v1/tools/echo"
assert_json "identity user forwarded after the retry" '.headers["x-wildbox-user-id"]' 'user-9999'
request "mock call counts readable" 200 "$MOCK_URL/__mock/counts"
assert_json "dropped authorization sent exactly twice" ".\"$DROP_ONCE\"" '2'

DROP_ALWAYS="drop-always-$(date +%s)-$$"
STATUS=$(curl -s -o /tmp/body.json -D /tmp/headers.txt -w "%{http_code}" \
    -H "Authorization: Bearer $DROP_ALWAYS" "$GATEWAY_URL/api/v1/tools/echo")
BODY=$(cat /tmp/body.json)
if [ "$STATUS" = 503 ]; then
    pass "identity unreachable answers 503"
else
    fail "identity unreachable: expected 503, got $STATUS — body: $(head -c 300 /tmp/body.json)"
fi
assert_json "unreachable error code" '.error' 'service_unavailable'
assert_strict_json "unreachable error body"
RETRY_AFTER=$(tr -d '\r' < /tmp/headers.txt | awk -F': ' 'tolower($1)=="retry-after"{print $2}')
if echo "$RETRY_AFTER" | grep -Eq '^[1-9][0-9]*$'; then
    pass "unreachable 503 carries Retry-After ($RETRY_AFTER)"
else
    fail "unreachable 503: expected a Retry-After in seconds, got '$RETRY_AFTER'"
fi
request "mock call counts readable" 200 "$MOCK_URL/__mock/counts"
assert_json "an unreachable identity is tried twice, not more" ".\"$DROP_ALWAYS\"" '2'

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

# --- Per-team rate limit (#627) --------------------------------------------
echo "== RATE_LIMIT_PER_HOUR =="

# header <name>: the value of a response header in /tmp/headers.txt.
header() { tr -d '\r' < /tmp/headers.txt | awk -F': ' -v h="$1" 'tolower($1)==h{print $2}'; }

# 16. Unset, the budget is the default: 10000 an hour, 166 a minute.
curl -s -o /tmp/body.json -D /tmp/headers.txt \
    -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_URL/api/v1/tools/echo"
if [ "$(header x-ratelimit-policy)" = "10000;w=3600" ] && [ "$(header x-ratelimit-limit)" = 166 ]; then
    pass "unset RATE_LIMIT_PER_HOUR means 10000 an hour (166 a minute)"
else
    fail "default limit: policy '$(header x-ratelimit-policy)', limit '$(header x-ratelimit-limit)'"
fi

# 17. The gateway started with RATE_LIMIT_PER_HOUR=120 applies 120 an hour:
#     2 requests a minute, so a third one in the same minute is refused. The
#     window is a fixed minute; one that turns between two requests restarts
#     the count once, so five requests always reach the refusal.
curl -s -o /tmp/body.json -D /tmp/headers.txt \
    -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_LIMIT_URL/api/v1/tools/echo"
if [ "$(header x-ratelimit-policy)" = "120;w=3600" ] && [ "$(header x-ratelimit-limit)" = 2 ]; then
    pass "RATE_LIMIT_PER_HOUR=120 is the budget the gateway reports (2 a minute)"
else
    fail "low limit: policy '$(header x-ratelimit-policy)', limit '$(header x-ratelimit-limit)'"
fi
refused=""
for attempt in 2 3 4 5; do
    STATUS=$(curl -s -o /tmp/body.json -D /tmp/headers.txt -w "%{http_code}" \
        -H "Authorization: Bearer valid-bearer-token" "$GATEWAY_LIMIT_URL/api/v1/tools/echo")
    if [ "$STATUS" = 429 ]; then
        refused=$attempt
        break
    fi
done
BODY=$(cat /tmp/body.json)
if [ -n "$refused" ]; then
    pass "RATE_LIMIT_PER_HOUR=120: request $refused in the minute refused with 429"
    assert_json "rate limit error code" '.error' 'rate_limit_exceeded'
    assert_json "rate limit names the hourly budget" '.limit_per_hour' '120'
    assert_strict_json "rate limit error body"
else
    fail "RATE_LIMIT_PER_HOUR=120: five requests in a row were all served (last HTTP $STATUS)"
fi

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
