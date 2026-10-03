#!/usr/bin/env bash
# Gateway revocation tests (#571) -- run against the Dockerfile.test gateway
# wired to test/mock_identity.py (see .github/workflows/gateway-tests.yml).
#
# The script plays identity's part in a logout: it blacklists the token's jti
# at the mock, then asks the gateway's internal listener to purge, exactly in
# that order. After that, no request carrying the token may be let through.
#
# The race this pins: a request that missed the auth cache is authorized by
# identity *before* the logout blacklists the jti, the logout's purge runs
# while that authorization is still in flight, and the gateway then stores
# the stale "allowed" decision. Every later request was served from that entry
# until AUTH_CACHE_TTL ran out. The mock holds the authorization open with
# delay_ms, so the interleaving is forced rather than hoped for.

set -u

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
GATEWAY_INTERNAL_URL="${GATEWAY_INTERNAL_URL:-http://localhost:8082}"
MOCK_URL="${MOCK_URL:-http://localhost:8001}"
SECRET="${CI_GATEWAY_SECRET:?CI_GATEWAY_SECRET must hold the gateway secret}"
ITERATIONS="${REVOCATION_ITERATIONS:-50}"
# Requests sent after each logout; more than the gateway has workers, so every
# worker is asked at least once in practice.
PROBES="${REVOCATION_PROBES:-12}"
# Not /api/v1/auth/: its 5 r/s zone would answer the probes with 429.
ROUTE="/api/v1/tools/echo"

PASS=0
FAIL=0
RUN_ID="$(date +%s)-$$"

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }

# token <jti> <delay_ms> -- JWT-shaped, unsigned; only the mock reads it.
token() {
    local header payload
    header=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
    payload=$(printf '{"sub":"user-%s","jti":"%s","delay_ms":%s}' "$1" "$1" "$2" | b64url)
    printf '%s.%s.c2ln' "$header" "$payload"
}

# session <jti> <user> <iat> <delay_ms> -- a session of <user> issued at <iat>,
# for the password-change cutoff (#569).
session() {
    local header payload
    header=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
    payload=$(printf '{"sub":"%s","jti":"%s","iat":%s,"delay_ms":%s}' "$2" "$1" "$3" "$4" | b64url)
    printf '%s.%s.c2ln' "$header" "$payload"
}

status_of() {
    curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$GATEWAY_URL$ROUTE"
}

revoke_at_identity() {
    curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
        -d "{\"jti\":\"$1\"}" "$MOCK_URL/__mock/revoke"
}

# purge <json body> -- what identity sends; prints the HTTP status.
purge() {
    curl -s -o /dev/null -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' -H "X-Gateway-Secret: $SECRET" \
        -d "$1" "$GATEWAY_INTERNAL_URL/internal/gateway/purge-auth-cache"
}

# probe <token> -- how many of PROBES requests were let through (200). Any
# answer other than 200 or 401 aborts: it would make the count meaningless.
probe() {
    local leaked=0 i code
    for i in $(seq 1 "$PROBES"); do
        code=$(status_of "$1")
        case "$code" in
            401) ;;
            200) leaked=$((leaked + 1)) ;;
            *) echo "unexpected HTTP $code from $ROUTE" >&2; exit 2 ;;
        esac
    done
    echo "$leaked"
}

# race <label> <purge body template, JTI replaced> <iterations>
# One authorization in flight across each logout. Reports how many logouts
# left the token usable.
race() {
    local label="$1" template="$2" n="$3" failed=0 i jti tok body code inflight
    for i in $(seq 1 "$n"); do
        jti="race-$label-$RUN_ID-$i"
        tok=$(token "$jti" 400)
        status_of "$tok" >/dev/null &
        inflight=$!
        sleep 0.15                     # identity has passed its blacklist check
        revoke_at_identity "$jti"
        body=${template//JTI/$jti}
        body=${body//TOKEN/$tok}
        code=$(purge "$body")
        if [ "$code" != 200 ]; then
            fail "$label: purge answered $code"
            return
        fi
        wait "$inflight"
        [ "$(probe "$tok")" = 0 ] || failed=$((failed + 1))
    done
    if [ "$failed" = 0 ]; then
        pass "$label: revoked token refused on every worker after $n/$n logouts"
    else
        fail "$label: revoked token still accepted after $failed/$n logouts"
    fi
}

echo "== Gateway revocation tests against $GATEWAY_URL =="

# 1. Plain logout, no race: a cached decision is dropped.
jti="plain-$RUN_ID"
tok=$(token "$jti" 0)
if [ "$(status_of "$tok")" = 200 ] && [ "$(status_of "$tok")" = 200 ]; then
    revoke_at_identity "$jti"
    purge "{\"jtis\":[\"$jti\"],\"ttl\":1800}" >/dev/null
    leaked=$(probe "$tok")
    if [ "$leaked" = 0 ]; then
        pass "logout drops the cached decision"
    else
        fail "logout: $leaked/$PROBES requests still accepted"
    fi
else
    fail "logout: a live token was not accepted"
fi

# 2. The race, with the purge identity sends: the token's jti.
race jti '{"jtis":["JTI"],"ttl":1800}' "$ITERATIONS"

# 3. The race, with the purge by raw token older identity versions send.
race token '{"token":"TOKEN","token_type":"bearer"}' 10

# 4. The race, with a full flush (user or API key deactivated): nothing names
#    the token, so only the generation check can stop the stale write.
race flush '{}' 10

# 5. The gateway's own revocation marker holds even when identity still
#    vouches for the token (its blacklist lost, or Redis down and failing
#    open): the jti is refused on a cache hit and after a fresh authorization.
jti="marker-$RUN_ID"
tok=$(token "$jti" 0)
status_of "$tok" >/dev/null
code=$(purge "{\"jtis\":[\"$jti\"],\"ttl\":1800}")
leaked=$(probe "$tok")
if [ "$code" = 200 ] && [ "$leaked" = 0 ]; then
    pass "a revoked jti is refused although identity still accepts it"
else
    fail "revocation marker: purge $code, $leaked/$PROBES requests accepted"
fi

# 6. Revoking one session leaves the others alone.
other=$(token "bystander-$RUN_ID" 0)
if [ "$(status_of "$other")" = 200 ]; then
    pass "an unrelated session is unaffected"
else
    fail "an unrelated session was refused"
fi

# 8. The purge answer is the JSON identity parses: it requires the count of
#    revoked jtis, and a body that is not strict JSON fails every logout.
answer=$(curl -s -X POST -H 'Content-Type: application/json' -H "X-Gateway-Secret: $SECRET" \
    -d '{"jtis":["count-a","count-b"],"ttl":60}' \
    "$GATEWAY_INTERNAL_URL/internal/gateway/purge-auth-cache")
if printf '%s' "$answer" | python3 -c 'import json,sys; sys.exit(json.loads(sys.stdin.read())["revoked"] != 2)' 2>/dev/null; then
    pass "purge answers strict JSON counting the revoked jtis"
else
    fail "purge answer is not what identity parses: $answer"
fi

# 9. A password change ends the user's sessions issued up to its cutoff
#    (#569): identity sends {"users": [{user_id, not_before}]} before it
#    commits the change. Both older sessions are refused although their
#    decisions are cached and the mock still vouches for them; a session
#    issued after the cutoff, and another user's, are not affected.
user="pw-user-$RUN_ID"
cutoff="1800000000.5"
older=$(session "pw-older-$RUN_ID" "$user" 1800000000.25 0)
oldest=$(session "pw-oldest-$RUN_ID" "$user" 1799999000 0)
newer=$(session "pw-newer-$RUN_ID" "$user" 1800000000.75 0)
bystander=$(session "pw-bystander-$RUN_ID" "other-$user" 1700000000 0)
warm=0
for tok in "$older" "$oldest" "$bystander"; do
    [ "$(status_of "$tok")" = 200 ] && warm=$((warm + 1))
done
answer=$(curl -s -X POST -H 'Content-Type: application/json' -H "X-Gateway-Secret: $SECRET" \
    -d "{\"users\":[{\"user_id\":\"$user\",\"not_before\":$cutoff}],\"ttl\":1800}" \
    "$GATEWAY_INTERNAL_URL/internal/gateway/purge-auth-cache")
leaked=$(( $(probe "$older") + $(probe "$oldest") ))
if [ "$warm" = 3 ] && [ "$leaked" = 0 ]; then
    pass "a password change ends the user's earlier sessions, cached or not"
else
    fail "password change: $warm/3 sessions warm, $leaked requests of ended sessions accepted"
fi
if [ "$(probe "$newer")" = "$PROBES" ] && [ "$(probe "$bystander")" = "$PROBES" ]; then
    pass "a session issued after the change, and another user's, still work"
else
    fail "a session issued after the change, or another user's, was refused"
fi
if printf '%s' "$answer" | python3 -c '
import json, sys
body = json.loads(sys.stdin.read())
sys.exit(not (body["revoked"] == 1 and body["scope"] == "users"))' 2>/dev/null; then
    pass "the users purge answers strict JSON counting the users"
else
    fail "users purge answer is not what identity parses: $answer"
fi

# 10. A cutoff never moves back: an earlier one sent later keeps the later.
purge "{\"users\":[{\"user_id\":\"$user\",\"not_before\":1700000000}],\"ttl\":1800}" >/dev/null
if [ "$(probe "$older")" = 0 ]; then
    pass "a later password-change cutoff is kept"
else
    fail "an earlier cutoff reopened a session the later one had ended"
fi

# 11. The race, for a password change: an authorization in flight across the
#     cutoff is not served afterwards, on any worker.
failed=0
for i in $(seq 1 10); do
    race_user="pw-race-$RUN_ID-$i"
    tok=$(session "pw-race-$RUN_ID-$i" "$race_user" 1800000000 400)
    status_of "$tok" >/dev/null &
    inflight=$!
    sleep 0.15
    code=$(purge "{\"users\":[{\"user_id\":\"$race_user\",\"not_before\":1800000001}],\"ttl\":1800}")
    wait "$inflight"
    if [ "$code" != 200 ] || [ "$(probe "$tok")" != 0 ]; then
        failed=$((failed + 1))
    fi
done
if [ "$failed" = 0 ]; then
    pass "password change: an in-flight authorization is not served after it (10/10)"
else
    fail "password change: an ended session was still accepted after $failed/10 changes"
fi

# 12. Malformed user entries are refused, not half-applied.
code=$(purge '{"users":[{"user_id":"x","not_before":"yesterday"}]}')
if [ "$code" = 400 ]; then
    pass "a users purge with an invalid entry is refused"
else
    fail "a users purge with an invalid entry answered $code"
fi

# 7. The purge refuses a caller without the secret.
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d '{"jtis":["x"]}' "$GATEWAY_INTERNAL_URL/internal/gateway/purge-auth-cache")
if [ "$code" = 403 ]; then
    pass "purge without the gateway secret refused"
else
    fail "purge without the gateway secret answered $code"
fi

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
