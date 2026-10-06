#!/usr/bin/env bash
# What the gateway writes about a request (#755) -- run against the test
# gateway and the PRODUCTION image, both started by
# .github/workflows/gateway-tests.yml.
#
# The access log used "$request", the request line as the client sent it,
# and "$http_referer": every query string went to the log by value, with
# the search terms, indicators and tokens it held. The log now has the
# method, the path the client asked for, and the status.
#
# Each case sends a request whose query string, Referer, Authorization,
# X-API-Key and Cookie carry a marker made for this run, then reads
# everything the container has written (its output and its log files) and
# looks for the marker. The path must be there, so that a log that simply
# stopped being written does not pass.

set -u

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
GATEWAY_PROD_URL="${GATEWAY_PROD_URL:-https://localhost:8443}"
GATEWAY_CONTAINER="${GATEWAY_CONTAINER:-gateway}"
GATEWAY_PROD_CONTAINER="${GATEWAY_PROD_CONTAINER:-gateway-prod}"

PASS=0
FAIL=0

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

MARKER="marker755$(date +%s)$$"

# Everything the container wrote: stdout and stderr, and the nginx log
# files when they are files of their own and not links to those.
written() {
    local container="$1"
    docker logs "$container" 2>&1
    docker exec "$container" sh -c '
        for log in /var/log/nginx/*.log /usr/local/openresty/nginx/logs/*.log; do
            if [ -f "$log" ] && [ ! -L "$log" ]; then cat "$log"; fi
        done' 2>/dev/null
}

check() {
    local name="$1" url="$2" container="$3"
    local path="/api/v1/tools/log-probe-$MARKER-path"
    local status
    status=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $MARKER-token" \
        -H "X-API-Key: $MARKER-key" \
        -H "Cookie: session=$MARKER-cookie" \
        -H "Referer: https://example.com/page?from=$MARKER-referer" \
        "$url$path?q=$MARKER-query&token=$MARKER-querytoken")
    if [ "$status" = "000" ]; then
        fail "$name: the gateway did not answer"
        return
    fi
    # The log is buffered by nothing here, but give the worker a moment.
    sleep 1
    local log
    log="$(written "$container")"

    if printf '%s' "$log" | grep -q -- "log-probe-$MARKER-path"; then
        pass "$name: the request is in the access log by its path (HTTP $status)"
    else
        fail "$name: the request is not in the access log at all"
        return
    fi
    local part
    for part in query querytoken referer token key cookie; do
        if printf '%s' "$log" | grep -q -- "$MARKER-$part"; then
            fail "$name: the log holds the request's $part: $(printf '%s' "$log" | grep -- "$MARKER-$part" | head -1 | cut -c1-200)"
        else
            pass "$name: the log does not hold the request's $part"
        fi
    done
    # The line keeps what an access log is read for.
    if printf '%s' "$log" | grep -- "log-probe-$MARKER-path" | grep -Eq "\"GET /api/v1/tools/log-probe-$MARKER-path HTTP/[0-9.]+\" $status "; then
        pass "$name: the line has the method, the path, the protocol and the status"
    else
        fail "$name: unexpected access line: $(printf '%s' "$log" | grep -- "log-probe-$MARKER-path" | head -1 | cut -c1-200)"
    fi
}

check "test configuration" "$GATEWAY_URL" "$GATEWAY_CONTAINER"
check "production image" "$GATEWAY_PROD_URL" "$GATEWAY_PROD_CONTAINER"

echo
echo "Access log tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
