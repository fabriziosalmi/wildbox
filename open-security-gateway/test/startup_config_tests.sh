#!/usr/bin/env bash
# Gateway start-up configuration tests (#627, #712) -- run against the
# Dockerfile.test image (see .github/workflows/gateway-tests.yml).
#
# RATE_LIMIT_PER_HOUR used to go through `tonumber(...) or 10000`, so a value
# that was not a number became the default without a word. The gateway now
# refuses to start with a value that is not a positive integer; this starts
# one gateway per bad value and checks that each exits, non-zero, naming the
# variable. A good value, started the same way, must keep running: without
# that control a gateway that could not start for any reason would pass.
#
# The per-address limits (#756) are settings too: GATEWAY_RATE_LIMIT_PER_SECOND,
# GATEWAY_AUTH_RATE_LIMIT_PER_SECOND and GATEWAY_STATIC_RATE_LIMIT_PER_SECOND.
# scripts/render_rate_limits.sh writes them into the limit_req zones before
# nginx starts, and refuses a value that is not a whole number from 1 to
# 100000. The production image runs it from its entrypoint and the test image
# from its command, so the cases run against both when the production image
# is named.
#
# Usage: startup_config_tests.sh <image> <docker network> [production image]
# The network must resolve identity-test (the mock identity), which the test
# configuration names in an upstream and nginx resolves before Lua runs; for
# the production image it must resolve every service's name, as the mock's
# aliases in .github/workflows/gateway-tests.yml do.

set -u

IMAGE="${1:?image}"
NETWORK="${2:?docker network}"
PROD_IMAGE="${3:-}"
SECRET="${CI_GATEWAY_SECRET:-startup-config-test-secret}"
PREFIX="gw-startup-$$"

PASS=0
FAIL=0
fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

# start <name> <value>: a gateway with RATE_LIMIT_PER_HOUR=<value>.
start() {
    docker run -d --name "$1" --network "$NETWORK" \
        -e GATEWAY_INTERNAL_SECRET="$SECRET" \
        -e IDENTITY_SERVICE_URL=http://identity-test:8001 \
        -e RATE_LIMIT_PER_HOUR="$2" \
        "$IMAGE" >/dev/null
}

# state <name>: "running", or "exited <code>" once the container has stopped.
state() {
    docker inspect -f '{{if .State.Running}}running{{else}}exited {{.State.ExitCode}}{{end}}' "$1"
}

# settle <name>: wait up to 20 s for the container to stop; print its state.
settle() {
    local i s
    for i in $(seq 1 40); do
        s=$(state "$1")
        [ "$s" != running ] && break
        sleep 0.5
    done
    echo "$s"
}

echo "== Gateway start-up configuration tests ($IMAGE) =="

i=0
for value in "0" "-5" "abc" "10k" "1.5" " 100" "" "1000000001" "99999999999999999999"; do
    i=$((i + 1))
    name="$PREFIX-bad-$i"
    start "$name" "$value"
    s=$(settle "$name")
    logs=$(docker logs "$name" 2>&1)
    if [ "$s" != running ] && [ "$s" != "exited 0" ] \
            && printf '%s' "$logs" | grep -q "RATE_LIMIT_PER_HOUR must be a whole number"; then
        pass "RATE_LIMIT_PER_HOUR='$value' refused at start-up ($s)"
    else
        fail "RATE_LIMIT_PER_HOUR='$value': state '$s', log: $(printf '%s' "$logs" | tail -3)"
    fi
    docker rm -f "$name" >/dev/null 2>&1
done

# The control: a valid value, and the variable unset, start and stay up.
for value in "120" "UNSET"; do
    name="$PREFIX-good-$value"
    if [ "$value" = UNSET ]; then
        docker run -d --name "$name" --network "$NETWORK" \
            -e GATEWAY_INTERNAL_SECRET="$SECRET" \
            -e IDENTITY_SERVICE_URL=http://identity-test:8001 \
            "$IMAGE" >/dev/null
    else
        start "$name" "$value"
    fi
    sleep 5
    s=$(state "$name")
    if [ "$s" = running ]; then
        pass "RATE_LIMIT_PER_HOUR=$value: the gateway starts"
    else
        fail "RATE_LIMIT_PER_HOUR=$value: the gateway did not start ($s): $(docker logs "$name" 2>&1 | tail -3)"
    fi
    docker rm -f "$name" >/dev/null 2>&1
done

# --- CORS_ORIGINS (#712) ------------------------------------------------------
# The gateway's CORS allowlist. An entry that is not an origin -- a wildcard,
# a path, a bare host name -- is refused with the configuration, like a bad
# rate limit, rather than dropped and found out when a browser is refused,
# or read as more than was meant.

# start_cors <name> <value>: a gateway with CORS_ORIGINS=<value>.
start_cors() {
    docker run -d --name "$1" --network "$NETWORK" \
        -e GATEWAY_INTERNAL_SECRET="$SECRET" \
        -e IDENTITY_SERVICE_URL=http://identity-test:8001 \
        -e CORS_ORIGINS="$2" \
        "$IMAGE" >/dev/null
}

i=0
for value in "*" "https://*.example.com" "dashboard.example.com" "https://dashboard.example.com/" \
        "https://dashboard.example.com/app" "https://a.example.com https://b.example.com" \
        "null" "ftp://dashboard.example.com" '["https://a.example.com", 5]' '{"origin": "https://a.example.com"}' \
        "https://a.example.com,*"; do
    i=$((i + 1))
    name="$PREFIX-cors-bad-$i"
    start_cors "$name" "$value"
    s=$(settle "$name")
    logs=$(docker logs "$name" 2>&1)
    if [ "$s" != running ] && [ "$s" != "exited 0" ] \
            && printf '%s' "$logs" | grep -q "CORS_ORIGINS"; then
        pass "CORS_ORIGINS='$value' refused at start-up ($s)"
    else
        fail "CORS_ORIGINS='$value': state '$s', log: $(printf '%s' "$logs" | tail -3)"
    fi
    docker rm -f "$name" >/dev/null 2>&1
done

# The control: the forms the documentation gives start and stay up.
i=0
for value in "" "https://dashboard.example.com" "https://a.example.com, http://localhost:3000," \
        '["https://a.example.com", "http://localhost:3000"]' "http://[::1]:3000" "HTTPS://Dashboard.Example.com:8443"; do
    i=$((i + 1))
    name="$PREFIX-cors-good-$i"
    start_cors "$name" "$value"
    sleep 5
    s=$(state "$name")
    if [ "$s" = running ]; then
        pass "CORS_ORIGINS='$value': the gateway starts"
    else
        fail "CORS_ORIGINS='$value': the gateway did not start ($s): $(docker logs "$name" 2>&1 | tail -3)"
    fi
    docker rm -f "$name" >/dev/null 2>&1
done

# --- The per-address limits (#756) ---------------------------------------------

# start_with <name> <image> <VARIABLE=value>...: a gateway from <image> with
# those settings.
start_with() {
    local name="$1" image="$2" settings=() setting
    shift 2
    for setting in "$@"; do
        settings+=(-e "$setting")
    done
    docker run -d --name "$name" --network "$NETWORK" \
        -e GATEWAY_INTERNAL_SECRET="$SECRET" \
        -e IDENTITY_SERVICE_URL=http://identity-test:8001 \
        "${settings[@]}" "$image" >/dev/null
}

# refused_rate <image> <setting> <value>: the gateway stops, non-zero, and
# names the setting; nginx is never started with a limit nobody set.
refused_rate() {
    local image="$1" setting="$2" value="$3" name s logs
    RATE_CASE=$((RATE_CASE + 1))
    name="$PREFIX-rate-bad-$RATE_CASE"
    start_with "$name" "$image" "$setting=$value"
    s=$(settle "$name")
    logs=$(docker logs "$name" 2>&1)
    if [ "$s" != running ] && [ "$s" != "exited 0" ] \
            && printf '%s' "$logs" | grep -q "$setting must be a whole number of requests per second between 1 and 100000" \
            && ! printf '%s' "$logs" | grep -q "Per-address request limits"; then
        pass "$image: $setting='$value' refused at start-up ($s)"
    else
        fail "$image: $setting='$value': state '$s', log: $(printf '%s' "$logs" | tail -3)"
    fi
    docker rm -f "$name" >/dev/null 2>&1
}

RATE_CASE=0
RATE_SETTINGS=(GATEWAY_RATE_LIMIT_PER_SECOND GATEWAY_AUTH_RATE_LIMIT_PER_SECOND GATEWAY_STATIC_RATE_LIMIT_PER_SECOND)
RATE_IMAGES=("$IMAGE")
if [ -n "$PROD_IMAGE" ]; then
    RATE_IMAGES+=("$PROD_IMAGE")
fi
for image in "${RATE_IMAGES[@]}"; do
    # Every kind of bad value on one setting: zero, a sign, a word, a unit,
    # a fraction, a space, nothing, a leading zero, past the maximum, a
    # number no shell can hold, and nginx syntax.
    for value in "0" "-5" "abc" "10k" "1.5" " 100" "" "007" "100001" "99999999999999999999" \
            "5r/s; limit_req_zone \$http_x_forwarded_for zone=global:10m rate=1"; do
        refused_rate "$image" GATEWAY_RATE_LIMIT_PER_SECOND "$value"
    done
    # And each of the other two is checked as well, not only the first.
    for setting in GATEWAY_AUTH_RATE_LIMIT_PER_SECOND GATEWAY_STATIC_RATE_LIMIT_PER_SECOND; do
        refused_rate "$image" "$setting" "abc"
        refused_rate "$image" "$setting" "0"
    done

    # The control: the smallest and the largest value start, and the gateway
    # says which limits it runs with.
    for value in "1" "100000"; do
        name="$PREFIX-rate-good-$value"
        settings=()
        for setting in "${RATE_SETTINGS[@]}"; do
            settings+=("$setting=$value")
        done
        start_with "$name" "$image" "${settings[@]}"
        sleep 5
        s=$(state "$name")
        if [ "$s" = running ] && docker logs "$name" 2>&1 \
                | grep -q "Per-address request limits: global $value r/s, auth $value r/s, static assets $value r/s."; then
            pass "$image: the three per-address limits at $value: the gateway starts and reports them"
        else
            fail "$image: the three per-address limits at $value: state '$s', log: $(docker logs "$name" 2>&1 | tail -3)"
        fi
        docker rm -f "$name" >/dev/null 2>&1
    done
done

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
