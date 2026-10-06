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
#
# The last sections check that the agents routes honour the same markers
# (#630).

set -u

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
GATEWAY_INTERNAL_URL="${GATEWAY_INTERNAL_URL:-http://localhost:8082}"
MOCK_URL="${MOCK_URL:-http://localhost:8001}"
SECRET="${CI_GATEWAY_SECRET:?CI_GATEWAY_SECRET must hold the gateway secret}"
ITERATIONS="${REVOCATION_ITERATIONS:-50}"
# Requests sent after each logout; more than the gateway has workers, so every
# worker is asked at least once in practice.
PROBES="${REVOCATION_PROBES:-12}"
# An authenticated route. The test configuration sets no per-address limit
# on it (see wildbox_gateway_test.conf): the probes below are sent one after
# another, faster than a deployment's 100 a second.
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

# ---------------------------------------------------------------------------
# API keys (#593). Identity names a key by the id it reports on every
# authorization it grants for it, sends {"api_keys": [<id>]} before it commits
# the revocation, and needs the count back.

# apikey <id> <delay_ms> <expires_at> -- a key the mock accepts until revoked
# or expired; see dynamic_api_key() in mock_identity.py.
apikey() { printf 'wsk_dyn~%s~%s~%s' "$1" "$2" "$3"; }

key_status_of() {
    curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $1" "$GATEWAY_URL$ROUTE"
}

# How many /internal/authorize calls the mock has had for <token>.
authorize_count() {
    curl -s "$MOCK_URL/__mock/counts" | python3 -c '
import json, sys
print(json.load(sys.stdin).get(sys.argv[1], 0))' "$1"
}

# probe_key <key> -- as probe, with the key in X-API-Key.
probe_key() {
    local leaked=0 i code
    for i in $(seq 1 "$PROBES"); do
        code=$(key_status_of "$1")
        case "$code" in
            401) ;;
            200) leaked=$((leaked + 1)) ;;
            *) echo "unexpected HTTP $code from $ROUTE" >&2; exit 2 ;;
        esac
    done
    echo "$leaked"
}

revoke_key_at_identity() {
    curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
        -d "{\"api_key_id\":\"$1\"}" "$MOCK_URL/__mock/revoke"
}

# 13. A revoked key is refused on the very next request, although its
#     decision is cached; the answer is strict JSON counting the keys.
kid="key-plain-$RUN_ID"
key=$(apikey "$kid" 0 0)
if [ "$(key_status_of "$key")" = 200 ] && [ "$(key_status_of "$key")" = 200 ]; then
    answer=$(curl -s -X POST -H 'Content-Type: application/json' -H "X-Gateway-Secret: $SECRET" \
        -d "{\"api_keys\":[\"$kid\"],\"ttl\":3600}" \
        "$GATEWAY_INTERNAL_URL/internal/gateway/purge-auth-cache")
    revoke_key_at_identity "$kid"
    next=$(key_status_of "$key")
    leaked=$(probe_key "$key")
    if [ "$next" = 401 ] && [ "$leaked" = 0 ]; then
        pass "a revoked API key is refused on the next request and every one after"
    else
        fail "revoked API key: next request $next, then $leaked/$PROBES accepted"
    fi
    if printf '%s' "$answer" | python3 -c '
import json, sys
body = json.loads(sys.stdin.read())
sys.exit(not (body["revoked"] == 1 and body["scope"] == "api_keys"))' 2>/dev/null; then
        pass "the api_keys purge answers strict JSON counting the keys"
    else
        fail "api_keys purge answer is not what identity parses: $answer"
    fi
else
    fail "API key: a live key was not accepted"
fi

# 14. The marker refuses a cached decision by itself: identity still vouches
#     for the key (the revocation is not committed yet), the gateway has the
#     decision cached, and the request is refused without asking identity.
kid="key-cached-$RUN_ID"
key=$(apikey "$kid" 0 0)
key_status_of "$key" >/dev/null
key_status_of "$key" >/dev/null
before=$(authorize_count "$key")
code=$(purge "{\"api_keys\":[\"$kid\"],\"ttl\":3600}")
next=$(key_status_of "$key")
after=$(authorize_count "$key")
if [ "$code" = 200 ] && [ "$before" = 1 ] && [ "$after" = 1 ] && [ "$next" = 401 ]; then
    pass "a cached decision for a revoked key is refused (identity not asked)"
else
    fail "cached decision: purge $code, next request $next, identity asked $before then $after times"
fi
# ... and after a fresh authorization, which identity still grants.
if [ "$(probe_key "$key")" = 0 ] && [ "$(authorize_count "$key")" -gt 1 ]; then
    pass "a fresh decision for a revoked key is refused although identity grants it"
else
    fail "a fresh decision for a revoked key was served"
fi

# 15. Revoking one key leaves another alone.
other=$(apikey "key-bystander-$RUN_ID" 0 0)
if [ "$(probe_key "$other")" = "$PROBES" ]; then
    pass "an unrelated API key is unaffected"
else
    fail "an unrelated API key was refused"
fi

# 16. The race: an authorization in flight across the revocation is not
#     served afterwards, on any worker.
failed=0
for i in $(seq 1 10); do
    kid="key-race-$RUN_ID-$i"
    key=$(apikey "$kid" 400 0)
    key_status_of "$key" >/dev/null &
    inflight=$!
    sleep 0.15
    code=$(purge "{\"api_keys\":[\"$kid\"],\"ttl\":3600}")
    revoke_key_at_identity "$kid"
    wait "$inflight"
    if [ "$code" != 200 ] || [ "$(probe_key "$key")" != 0 ]; then
        failed=$((failed + 1))
    fi
done
if [ "$failed" = 0 ]; then
    pass "API key: an in-flight authorization is not served after the revocation (10/10)"
else
    fail "API key: a revoked key was still accepted after $failed/10 revocations"
fi

# 17. A cached decision does not outlive the key's expiry: the key expires
#     in 3 s, well inside the cache TTL.
expires=$(python3 -c 'import time; print(round(time.time() + 3, 3))')
key=$(apikey "key-expiring-$RUN_ID" 0 "$expires")
first=$(key_status_of "$key")
second=$(key_status_of "$key")
cached=$(authorize_count "$key")
python3 -c "import time; time.sleep(max(0, $expires - time.time()) + 0.5)"
expired=$(key_status_of "$key")
if [ "$first" = 200 ] && [ "$second" = 200 ] && [ "$cached" = 1 ] && [ "$expired" = 401 ]; then
    pass "an expired API key is refused although its decision was cached"
else
    fail "expiry: $first/$second while valid (identity asked $cached times), $expired after"
fi

# 18. A decision that does not name its key cannot be checked against a
#     revocation, and is not served.
code=$(key_status_of "wsk_unnamed_ci_fixture")
if [ "$code" = 401 ]; then
    pass "an API-key decision without the key id is refused"
else
    fail "an API-key decision without the key id answered $code"
fi

# 19. Malformed key lists are refused, not half-applied.
code_a=$(purge '{"api_keys":[]}')
code_b=$(purge '{"api_keys":["ok", 7]}')
if [ "$code_a" = 400 ] && [ "$code_b" = 400 ]; then
    pass "an api_keys purge with an empty list or an invalid id is refused"
else
    fail "malformed api_keys purges answered $code_a and $code_b"
fi

# ---------------------------------------------------------------------------
# Team memberships (#613). Removing a member from a team: identity sends
# {"memberships": [{user_id, team_id, not_before}]} before it commits the
# removal, and needs the count back. The gateway then refuses, in that team
# only, the user's sessions issued up to not_before, cached decision or not;
# once identity has committed, the next fresh authorization resolves the team
# the user still belongs to.

# member_session <jti> <user> <iat> <delay_ms> <team>... -- a session of
# <user>, whose teams the mock resolves in the order given (oldest first).
member_session() {
    local header payload jti="$1" user="$2" iat="$3" delay="$4" teams
    shift 4
    teams=$(printf '"%s",' "$@")
    header=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
    payload=$(printf '{"sub":"%s","jti":"%s","iat":%s,"delay_ms":%s,"teams":[%s]}' \
        "$user" "$jti" "$iat" "$delay" "${teams%,}" | b64url)
    printf '%s.%s.c2ln' "$header" "$payload"
}

# "<status> <team>": the team the gateway authorized the request in, from the
# X-Wildbox-Team-ID header it sets on every request it lets through.
team_status_of() {
    curl -s -o /dev/null -D - -H "Authorization: Bearer $1" "$GATEWAY_URL$ROUTE" \
        | awk 'NR == 1 { code = $2 }
               tolower($1) == "x-wildbox-team-id:" { team = $2 }
               END { gsub("\r", "", team); print code " " team }'
}

remove_member_at_identity() {
    curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
        -d "{\"user_id\":\"$1\",\"team_id\":\"$2\"}" "$MOCK_URL/__mock/remove_member"
}

# 20. A cached decision for the team is refused on the very next request,
#     without asking identity, before identity has committed the removal;
#     a fresh decision identity still grants for that team is refused too.
user="member-$RUN_ID"
team_a="team-a-$RUN_ID"
team_b="team-b-$RUN_ID"
tok=$(member_session "member-$RUN_ID" "$user" 1800000000.25 0 "$team_a" "$team_b")
first=$(team_status_of "$tok")
second=$(team_status_of "$tok")
before=$(authorize_count "$tok")
answer=$(curl -s -X POST -H 'Content-Type: application/json' -H "X-Gateway-Secret: $SECRET" \
    -d "{\"memberships\":[{\"user_id\":\"$user\",\"team_id\":\"$team_a\",\"not_before\":1800000000.5}],\"ttl\":1800}" \
    "$GATEWAY_INTERNAL_URL/internal/gateway/purge-auth-cache")
next=$(team_status_of "$tok")
after=$(authorize_count "$tok")
if [ "$first" = "200 $team_a" ] && [ "$second" = "200 $team_a" ] && [ "$before" = 1 ] \
        && [ "$next" = "403 " ] && [ "$after" = 1 ]; then
    pass "a removed member's cached decision for the team is refused (identity not asked)"
else
    fail "membership, cached: '$first'/'$second' (identity asked $before), then '$next' (asked $after)"
fi
fresh=$(team_status_of "$tok")
if [ "$fresh" = "403 " ] && [ "$(authorize_count "$tok")" -gt 1 ]; then
    pass "a fresh decision for the team left is refused although identity grants it"
else
    fail "membership, fresh: '$fresh' before identity committed the removal"
fi
if printf '%s' "$answer" | python3 -c '
import json, sys
body = json.loads(sys.stdin.read())
sys.exit(not (body["revoked"] == 1 and body["scope"] == "memberships"))' 2>/dev/null; then
    pass "the memberships purge answers strict JSON counting the memberships"
else
    fail "memberships purge answer is not what identity parses: $answer"
fi

# 21. The marker names one user in one team: another member of that team is
#     not refused, nor is a session of the user issued after the cutoff
#     (a new login once the user is added back to the team).
other=$(member_session "member-other-$RUN_ID" "other-$user" 1700000000 0 "$team_a")
later=$(member_session "member-later-$RUN_ID" "$user" 1800000000.75 0 "$team_a")
if [ "$(team_status_of "$other")" = "200 $team_a" ] \
        && [ "$(team_status_of "$later")" = "200 $team_a" ]; then
    pass "another member, and a session issued after the cutoff, still work in the team"
else
    fail "the membership marker refused a session it does not name"
fi

# 22. Once identity has committed the removal, the same session works again,
#     in the team its user still belongs to, on every worker.
remove_member_at_identity "$user" "$team_a"
moved=0
for i in $(seq 1 "$PROBES"); do
    [ "$(team_status_of "$tok")" = "200 $team_b" ] && moved=$((moved + 1))
done
if [ "$moved" = "$PROBES" ]; then
    pass "after the removal the session works in the team its user still belongs to"
else
    fail "after the removal only $moved/$PROBES requests were served in the remaining team"
fi

# 23. A member of one team only: refused at once, then refused by identity.
solo="member-solo-$RUN_ID"
solo_team="team-solo-$RUN_ID"
tok=$(member_session "$solo" "$solo" 1800000000 0 "$solo_team")
warm_code=$(team_status_of "$tok")
code=$(purge "{\"memberships\":[{\"user_id\":\"$solo\",\"team_id\":\"$solo_team\",\"not_before\":1800000001}],\"ttl\":1800}")
next=$(team_status_of "$tok")
remove_member_at_identity "$solo" "$solo_team"
final=$(team_status_of "$tok")
if [ "$warm_code" = "200 $solo_team" ] && [ "$code" = 200 ] && [ "$next" = "403 " ] \
        && [ "$final" = "401 " ]; then
    pass "a member of one team only is refused at once, then has no team"
else
    fail "single-team removal: '$warm_code', purge $code, then '$next', then '$final'"
fi

# 24. The race: an authorization in flight across the removal -- identity
#     resolved the team before the commit -- is neither served nor cached:
#     every later request is served in the remaining team.
failed=0
for i in $(seq 1 10); do
    race_user="member-race-$RUN_ID-$i"
    race_a="team-race-a-$RUN_ID-$i"
    race_b="team-race-b-$RUN_ID-$i"
    tok=$(member_session "$race_user" "$race_user" 1800000000 400 "$race_a" "$race_b")
    inflight_out="$(mktemp)"
    team_status_of "$tok" >"$inflight_out" &
    inflight=$!
    sleep 0.15
    code=$(purge "{\"memberships\":[{\"user_id\":\"$race_user\",\"team_id\":\"$race_a\",\"not_before\":1800000001}],\"ttl\":1800}")
    remove_member_at_identity "$race_user" "$race_a"
    wait "$inflight"
    inflight_answer=$(cat "$inflight_out")
    rm -f "$inflight_out"
    moved=0
    for _ in $(seq 1 "$PROBES"); do
        [ "$(team_status_of "$tok")" = "200 $race_b" ] && moved=$((moved + 1))
    done
    if [ "$code" != 200 ] || [ "$inflight_answer" != "403 " ] || [ "$moved" != "$PROBES" ]; then
        echo "  race $i: purge $code, in flight '$inflight_answer', $moved/$PROBES in the remaining team"
        failed=$((failed + 1))
    fi
done
if [ "$failed" = 0 ]; then
    pass "membership: an in-flight authorization for the team left is not served (10/10)"
else
    fail "membership: a decision for the team left was served after $failed/10 removals"
fi

# 25. A cutoff never moves back, and malformed entries are refused.
kept_user="member-kept-$RUN_ID"
kept_team="team-kept-$RUN_ID"
purge "{\"memberships\":[{\"user_id\":\"$kept_user\",\"team_id\":\"$kept_team\",\"not_before\":1800000000.5}],\"ttl\":1800}" >/dev/null
purge "{\"memberships\":[{\"user_id\":\"$kept_user\",\"team_id\":\"$kept_team\",\"not_before\":1700000000}],\"ttl\":1800}" >/dev/null
early=$(member_session "member-early-$RUN_ID" "$kept_user" 1800000000.25 0 "$kept_team")
if [ "$(team_status_of "$early")" = "403 " ]; then
    pass "a later membership cutoff is kept"
else
    fail "an earlier membership cutoff reopened a session the later one had ended"
fi
code_a=$(purge '{"memberships":[]}')
code_b=$(purge '{"memberships":[{"user_id":"u","not_before":1800000000}]}')
if [ "$code_a" = 400 ] && [ "$code_b" = 400 ]; then
    pass "a memberships purge with an empty list or an invalid entry is refused"
else
    fail "malformed memberships purges answered $code_a and $code_b"
fi

# ---------------------------------------------------------------------------
# The agents routes (#630). They authenticated with inline Lua that cached
# nothing and checked no marker but an API key's; they now go through
# authenticate(), so every revocation above holds there too. Identity still
# vouches for each credential below: only the gateway's marker refuses it.
AGENTS_ROUTE="/api/v1/agents/analyze/1f0c4ea6-agents-task"

agents_status_of() {
    curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$GATEWAY_URL$AGENTS_ROUTE"
}
agents_key_status_of() {
    curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $1" "$GATEWAY_URL$AGENTS_ROUTE"
}

# 26. A revoked API key.
kid="key-agents-$RUN_ID"
key=$(apikey "$kid" 0 0)
before=$(agents_key_status_of "$key")
code=$(purge "{\"api_keys\":[\"$kid\"],\"ttl\":3600}")
after=$(agents_key_status_of "$key")
if [ "$before" = 200 ] && [ "$code" = 200 ] && [ "$after" = 401 ]; then
    pass "agents: a revoked API key is refused"
else
    fail "agents: API key $before, purge $code, then $after"
fi

# 27. A session ended by logout (its jti).
jti="agents-$RUN_ID"
tok=$(token "$jti" 0)
before=$(agents_status_of "$tok")
code=$(purge "{\"jtis\":[\"$jti\"],\"ttl\":1800}")
after=$(agents_status_of "$tok")
if [ "$before" = 200 ] && [ "$code" = 200 ] && [ "$after" = 401 ]; then
    pass "agents: a session ended by logout is refused"
else
    fail "agents: logout $before, purge $code, then $after"
fi

# 28. A session issued before its user's password change.
user="agents-pw-$RUN_ID"
tok=$(session "agents-pw-$RUN_ID" "$user" 1800000000 0)
before=$(agents_status_of "$tok")
code=$(purge "{\"users\":[{\"user_id\":\"$user\",\"not_before\":1800000001}],\"ttl\":1800}")
after=$(agents_status_of "$tok")
if [ "$before" = 200 ] && [ "$code" = 200 ] && [ "$after" = 401 ]; then
    pass "agents: a session older than its user's password change is refused"
else
    fail "agents: password change $before, purge $code, then $after"
fi

# 29. A session of a member removed from the team.
user="agents-member-$RUN_ID"
team="team-agents-$RUN_ID"
tok=$(member_session "agents-member-$RUN_ID" "$user" 1800000000 0 "$team")
before=$(agents_status_of "$tok")
code=$(purge "{\"memberships\":[{\"user_id\":\"$user\",\"team_id\":\"$team\",\"not_before\":1800000001}],\"ttl\":1800}")
after=$(agents_status_of "$tok")
if [ "$before" = 200 ] && [ "$code" = 200 ] && [ "$after" = 403 ]; then
    pass "agents: a member removed from the team is refused in it"
else
    fail "agents: team removal $before, purge $code, then $after"
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
