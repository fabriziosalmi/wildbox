#!/usr/bin/env bash
# Gateway start-up configuration tests (#627) -- run against the Dockerfile.test
# image (see .github/workflows/gateway-tests.yml).
#
# RATE_LIMIT_PER_HOUR used to go through `tonumber(...) or 10000`, so a value
# that was not a number became the default without a word. The gateway now
# refuses to start with a value that is not a positive integer; this starts
# one gateway per bad value and checks that each exits, non-zero, naming the
# variable. A good value, started the same way, must keep running: without
# that control a gateway that could not start for any reason would pass.
#
# Usage: startup_config_tests.sh <image> <docker network>
# The network must resolve identity-test (the mock identity), which the test
# configuration names in an upstream and nginx resolves before Lua runs.

set -u

IMAGE="${1:?image}"
NETWORK="${2:?docker network}"
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

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
