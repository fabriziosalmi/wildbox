#!/usr/bin/env bash
# What the gateway tells a service about the credential (#637) -- run against
# the Dockerfile.test gateway wired to test/mock_identity.py (see
# .github/workflows/gateway-tests.yml).
#
# The gateway enforces an API key's scopes; it used to forward the user, the
# team and the role alone, so no service could check a scope itself. It now
# forwards
#
#   X-Wildbox-Auth-Type  "session" for a JWT, "api_key" for an API key
#   X-Wildbox-Scopes     the key's scopes, space-separated; "*" for a key
#                        that is not limited; absent for a session
#
# and, as for the identity headers and the gateway secret, they are the
# gateway's to set: a client's own are dropped, on the routes that
# authenticate and on the ones that do not. The mock echoes the headers it
# received, so every assertion below is on what the service would see.
#
# Two kinds of location are covered, because the headers reach the service
# two ways: the agents routes include proxy_params.conf, which sends them
# from nginx variables; the tools and data routes of the test configuration
# do not, and forward the request headers authenticate() rewrote.

set -u

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
MOCK_URL="${MOCK_URL:-http://localhost:8001}"

PASS=0
FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

# request <name> <expected_status> <curl args...> ; body left in $BODY
request() {
    local name="$1" expected="$2" status
    shift 2
    status=$(curl -s -o "$WORK/body" -w "%{http_code}" "$@")
    BODY=$(cat "$WORK/body")
    if [ "$status" = "$expected" ]; then
        pass "$name (HTTP $status)"
    else
        fail "$name: expected HTTP $expected, got $status — body: $(head -c 300 "$WORK/body")"
    fi
}

# forwarded <name> <auth type> <scopes>: the two headers the echoed request
# carried. "absent" stands for a header that was not sent at all.
forwarded() {
    local name="$1" auth_type="$2" scopes="$3" got_type got_scopes
    got_type=$(printf '%s' "$BODY" | jq -r '.headers["x-wildbox-auth-type"] // "absent"')
    got_scopes=$(printf '%s' "$BODY" | jq -r '.headers["x-wildbox-scopes"] // "absent"')
    if [ "$got_type" = "$auth_type" ]; then
        pass "$name: X-Wildbox-Auth-Type is $auth_type"
    else
        fail "$name: expected X-Wildbox-Auth-Type '$auth_type', got '$got_type'"
    fi
    if [ "$got_scopes" = "$scopes" ]; then
        pass "$name: X-Wildbox-Scopes is $scopes"
    else
        fail "$name: expected X-Wildbox-Scopes '$scopes', got '$got_scopes'"
    fi
}

echo "== Scope forwarding against $GATEWAY_URL =="

AGENTS="$GATEWAY_URL/api/v1/agents/analyze/1f0c4ea6-scope-task"
TOOLS="$GATEWAY_URL/api/v1/tools/echo"

# --- A session ---------------------------------------------------------------
# A JWT has no scopes and is not limited by them: the service is told it is
# a session, and gets no scopes header to mistake for a key's.
request "session, proxy_params route" 200 -H "Authorization: Bearer valid-bearer-token" "$AGENTS"
forwarded "session, proxy_params route" session absent
request "session, plain route" 200 -H "Authorization: Bearer valid-bearer-token" "$TOOLS"
forwarded "session, plain route" session absent

# --- An API key: exactly its scopes -----------------------------------------
request "one-scope key, proxy_params route" 200 -H "X-API-Key: wsk_toolsexec_ci_fixture" "$AGENTS"
forwarded "one-scope key, proxy_params route" api_key "tools:execute"
request "one-scope key, plain route" 200 -H "X-API-Key: wsk_toolsexec_ci_fixture" "$TOOLS"
forwarded "one-scope key, plain route" api_key "tools:execute"

# Several scopes: all of them, in identity's order, separated by one space.
request "several scopes, proxy_params route" 200 -H "X-API-Key: wsk_multiscope_ci_fixture" "$AGENTS"
forwarded "several scopes, proxy_params route" api_key "tools:read data:ingest data:read"
request "several scopes, plain route" 200 -H "X-API-Key: wsk_multiscope_ci_fixture" "$TOOLS"
forwarded "several scopes, plain route" api_key "tools:read data:ingest data:read"

# The sensor's key on the ingest route: what the data service checks again.
request "ingest key posts a batch" 200 -X POST -H "X-API-Key: wsk_ingest_ci_fixture" \
    "$GATEWAY_URL/api/v1/data/ingest"
forwarded "ingest key" api_key "data:ingest"

# A key identity reports no scope list for is not limited. That is written
# out as "*", not left for the service to infer from a missing header.
request "unlimited key" 200 -X POST -H "X-API-Key: wsk_unlimited_ci_fixture" "$AGENTS"
forwarded "unlimited key" api_key "*"

# A key whose scope list is empty holds nothing, and no route lets it by.
request "key with an empty scope list is refused" 403 -H "X-API-Key: wsk_noscopes_ci_fixture" "$TOOLS"
if [ "$(printf '%s' "$BODY" | jq -r '.error')" = insufficient_scope ]; then
    pass "empty scope list: insufficient_scope, the service is not reached"
else
    fail "empty scope list: expected insufficient_scope, got: $(head -c 200 "$WORK/body")"
fi

# What identity reports as a scope and is not a scope name -- a space, a
# line break carrying a header of its own -- is not forwarded. The rest is.
request "odd scopes, proxy_params route" 200 -H "X-API-Key: wsk_oddscope_ci_fixture" "$AGENTS"
forwarded "odd scopes, proxy_params route" api_key "tools:read *"
if [ "$(printf '%s' "$BODY" | jq -r '.headers["x-wildbox-role"]')" = member ]; then
    pass "a line break in a scope injects no header (role still member)"
else
    fail "role after a scope with a line break: $(printf '%s' "$BODY" | jq -c '.headers["x-wildbox-role"]')"
fi
request "odd scopes, plain route" 200 -H "X-API-Key: wsk_oddscope_ci_fixture" "$TOOLS"
forwarded "odd scopes, plain route" api_key "tools:read *"
if [ "$(printf '%s' "$BODY" | jq -r '.headers["x-wildbox-role"]')" = member ]; then
    pass "a line break in a scope injects no header on the plain route either"
else
    fail "plain route, role after a scope with a line break: $(printf '%s' "$BODY" | jq -c '.headers["x-wildbox-role"]')"
fi

# The type follows what identity answered, not the header the credential
# came in: a decision that names an API key is a key's.
request "key presented as a bearer token" 200 -H "Authorization: Bearer wsk_multiscope_ci_fixture" "$AGENTS"
forwarded "key presented as a bearer token" api_key "tools:read data:ingest data:read"

# --- A cached decision says the same ----------------------------------------
request "one-scope key again" 200 -H "X-API-Key: wsk_toolsexec_ci_fixture" "$AGENTS"
forwarded "cached decision" api_key "tools:execute"
request "unlimited key again" 200 -X POST -H "X-API-Key: wsk_unlimited_ci_fixture" "$AGENTS"
forwarded "cached unlimited decision" api_key "*"
request "session again" 200 -H "Authorization: Bearer valid-bearer-token" "$AGENTS"
forwarded "cached session decision" session absent
request "mock call counts readable" 200 "$MOCK_URL/__mock/counts"
# Keys no other script uses, so the count is this script's alone.
for token in wsk_unlimited_ci_fixture wsk_oddscope_ci_fixture; do
    if [ "$(printf '%s' "$BODY" | jq -r --arg t "$token" '.[$t]')" = 1 ]; then
        pass "$token: identity was asked once, the repeats came from the cache"
    else
        fail "$token: expected one authorization, got $(printf '%s' "$BODY" | jq -r --arg t "$token" '.[$t]')"
    fi
done

# --- A client's own headers are dropped -------------------------------------
# On routes that authenticate: replaced by the gateway's.
for target in "$AGENTS" "$TOOLS"; do
    request "session forging a scope list" 200 -H "Authorization: Bearer valid-bearer-token" \
        -H "X-Wildbox-Auth-Type: service" -H "X-Wildbox-Scopes: admin" "$target"
    forwarded "session forging a scope list (${target#"$GATEWAY_URL"})" session absent

    request "read-only key forging wider scopes" 200 -H "X-API-Key: wsk_readonly_ci_fixture" \
        -H "X-Wildbox-Auth-Type: session" -H "X-Wildbox-Scopes: * admin tools:execute" "$target"
    forwarded "read-only key forging wider scopes (${target#"$GATEWAY_URL"})" api_key "read"
done

# A forged list does not widen what the gateway itself allows.
request "forged scopes do not pass the gateway's own check" 403 -X POST \
    -H "X-API-Key: wsk_readonly_ci_fixture" -H "X-Wildbox-Scopes: tools:execute" "$TOOLS"

# On a route that authenticates nobody (identity's passthrough): nothing is
# forwarded, the client's own included, as for X-Gateway-Secret (#664).
request "passthrough, anonymous, forged credential headers" 200 \
    -H "X-Wildbox-Auth-Type: service" -H "X-Wildbox-Scopes: *" \
    "$GATEWAY_URL/api/v1/identity/admin/metrics"
forwarded "anonymous passthrough" absent absent
request "passthrough with a session" 200 -H "Authorization: Bearer valid-bearer-token" \
    -H "X-Wildbox-Auth-Type: session" -H "X-Wildbox-Scopes: admin" \
    "$GATEWAY_URL/api/v1/identity/admin/metrics"
forwarded "session on the passthrough" absent absent

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
