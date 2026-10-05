#!/usr/bin/env bash
# The gateway image is correct on its own (#713) -- run against a container
# started from the production image as built (Dockerfile), with nothing
# mounted over /etc/nginx (see .github/workflows/gateway-tests.yml).
#
# The Compose stack mounts open-security-gateway/nginx over /etc/nginx and
# sets a health check of its own, which hid what the image did by itself:
# the base image's default.conf was still in conf.d, answered port 80 for
# Host: localhost with its welcome page, and the image's own HEALTHCHECK
# (curl http://localhost:80/health) got 404, so a container run from the
# image was reported unhealthy.
#
# Usage: production_image_tests.sh [container]   (default: gateway-prod)

set -u

CONTAINER="${1:-${GATEWAY_PROD_CONTAINER:-gateway-prod}}"
# How long to wait for Docker to report the health check's verdict: the
# image probes every 30 seconds.
HEALTH_WAIT_SECONDS="${HEALTH_WAIT_SECONDS:-120}"

PASS=0
FAIL=0

fail() { echo "❌ $1"; FAIL=$((FAIL + 1)); }
pass() { echo "✅ $1"; PASS=$((PASS + 1)); }

inside() { docker exec "$CONTAINER" "$@"; }

echo "== Production image, container $CONTAINER =="

# 1. Only this project's server configuration is loaded.
LOADED=$(inside sh -c 'ls /etc/nginx/conf.d' 2>&1 | tr '\n' ' ' | sed 's/ $//')
if [ "$LOADED" = "wildbox_gateway.conf" ]; then
    pass "conf.d holds wildbox_gateway.conf and nothing else"
else
    fail "conf.d holds '$LOADED': only wildbox_gateway.conf belongs there"
fi

# 2. Port 80, whatever the Host: /health answers, everything else redirects
#    to HTTPS. The base image's server answered Host: localhost.
for host in localhost 127.0.0.1 api.wildbox.local gateway.example.test; do
    STATUS=$(inside curl -s -o /tmp/health.body -w '%{http_code}' -H "Host: $host" http://127.0.0.1:80/health)
    BODY=$(inside cat /tmp/health.body)
    if [ "$STATUS" = 200 ] && [ "$(printf '%s' "$BODY" | jq -r '.service' 2>/dev/null)" = wildbox-gateway ]; then
        pass "port 80, Host $host: /health is the gateway's"
    else
        fail "port 80, Host $host: /health answered $STATUS — $(printf '%s' "$BODY" | head -c 120)"
    fi
    STATUS=$(inside curl -s -o /dev/null -D /tmp/root.headers -w '%{http_code}' -H "Host: $host" http://127.0.0.1:80/)
    LOCATION=$(inside sh -c "tr -d '\r' < /tmp/root.headers | awk -F': ' 'tolower(\$1)==\"location\"{print \$2}'")
    case "$LOCATION" in
        https://*) redirected=yes ;;
        *) redirected=no ;;
    esac
    if [ "$STATUS" = 301 ] && [ "$redirected" = yes ]; then
        pass "port 80, Host $host: / redirects to HTTPS"
    else
        fail "port 80, Host $host: / answered $STATUS, Location '$LOCATION' (expected a 301 to https://)"
    fi
done

# 3. The image's own HEALTHCHECK command succeeds when run as Docker runs it.
HEALTHCHECK=$(docker inspect --format '{{json .Config.Healthcheck.Test}}' "$CONTAINER" 2>/dev/null)
KIND=$(printf '%s' "$HEALTHCHECK" | jq -r '.[0]' 2>/dev/null)
COMMAND=$(printf '%s' "$HEALTHCHECK" | jq -r '.[1]' 2>/dev/null)
if [ "$KIND" = CMD-SHELL ] && [ -n "$COMMAND" ] && [ "$COMMAND" != null ]; then
    pass "the image declares a HEALTHCHECK ($COMMAND)"
    if inside sh -c "$COMMAND" > /dev/null 2>&1; then
        pass "the HEALTHCHECK command succeeds in the container"
    else
        fail "the HEALTHCHECK command fails in the container: $COMMAND"
    fi
else
    fail "the image declares no shell HEALTHCHECK: $HEALTHCHECK"
fi

# 4. And Docker reports the container healthy.
STATE=starting
waited=0
while [ "$waited" -lt "$HEALTH_WAIT_SECONDS" ]; do
    STATE=$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null)
    [ "$STATE" = starting ] || break
    sleep 5
    waited=$((waited + 5))
done
if [ "$STATE" = healthy ]; then
    pass "Docker reports the container healthy"
else
    fail "Docker reports the container '$STATE' after ${waited}s: $(docker inspect --format '{{range .State.Health.Log}}exit {{.ExitCode}}; {{end}}' "$CONTAINER" 2>/dev/null)"
fi

echo
echo "== Results: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
