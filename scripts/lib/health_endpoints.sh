# shellcheck shell=bash
#
# The one table of health URLs for the Wildbox stack, and the one way to
# probe them. Sourced by scripts/shell-scripts/comprehensive_health_check.sh
# (`make health`), scripts/shell-scripts/system_monitor.sh,
# scripts/wait-for-services.sh and tests/test_all_pages.sh, so they cannot
# drift apart again. tests/scripts/test_health_checks.py checks the table
# against docker-compose.yml and docs/guides/ports.md.
#
# A service is healthy when its health URL answers 2xx. Nothing else counts:
#
#   - a redirect is not followed. guardian is a Django service whose route is
#     /health/; /health answers 301, and a script that accepted that reported
#     guardian healthy while /health/ answered 503 (#656);
#   - 4xx and 5xx are unhealthy, whatever the body says;
#   - no answer is unhealthy.

# name|url|profile
#
# One line per Compose service that publishes a port, with the URL its
# healthcheck and docs/guides/ports.md use. The third field names the Compose
# profile of a service that is not part of the default stack.
wb_health_endpoints() {
  cat <<'TABLE'
gateway|http://localhost/health|
identity|http://localhost:8001/health|
api|http://localhost:8000/health|
data|http://localhost:8002/health|
sensor|http://localhost:8004/health|
agents|http://localhost:8006/health|
guardian|http://localhost:8013/health/|
responder|http://localhost:8018/health|
cspm|http://localhost:8019/health|
dashboard|http://localhost:3000/|
tools-flower|http://localhost:5555/healthcheck|
automations|http://localhost:5678/healthz|automations
prometheus|http://localhost:9090/-/healthy|monitoring
TABLE
}

# wb_health_url NAME: the health URL of one service, or exit 1.
wb_health_url() {
  local name url profile
  while IFS='|' read -r name url profile; do
    if [ "$name" = "$1" ]; then
      printf '%s\n' "$url"
      return 0
    fi
  done <<EOF
$(wb_health_endpoints)
EOF
  return 1
}

# wb_http_status URL: print the HTTP status of one GET (000 when there was no
# answer) and return 0 only for 2xx. Redirects are not followed.
wb_http_status() {
  local status
  status=$(curl -sS -o /dev/null -w '%{http_code}' \
    --max-time "${HEALTH_TIMEOUT:-5}" "$1" 2>/dev/null) || true
  case "$status" in
    [0-9][0-9][0-9]) ;;
    *) status=000 ;;
  esac
  printf '%s\n' "$status"
  case "$status" in
    2??) return 0 ;;
    *) return 1 ;;
  esac
}

# Exit 0 when the Compose profile $1 is enabled through COMPOSE_PROFILES.
wb_profile_enabled() {
  case ",${COMPOSE_PROFILES:-}," in
    *",$1,"*|*",*,"*) return 0 ;;
    *) return 1 ;;
  esac
}

# wb_check_stack_health: probe every service in the table, print one line
# each, and return the number of unhealthy services (0 = all healthy).
#
# A service under a Compose profile that is not in COMPOSE_PROFILES is
# skipped when nothing answers on its port; if something does answer there,
# it is held to the same rule as the others.
wb_check_stack_health() {
  local name url profile status unhealthy=0
  while IFS='|' read -r name url profile; do
    [ -n "$name" ] || continue
    if status=$(wb_http_status "$url"); then
      echo "  OK    $name (HTTP $status) $url"
    elif [ -n "$profile" ] && [ "$status" = "000" ] && ! wb_profile_enabled "$profile"; then
      echo "  SKIP  $name: not running (profile '$profile'; set COMPOSE_PROFILES to require it)"
    elif [ "$status" = "000" ]; then
      echo "  FAIL  $name: no answer from $url"
      unhealthy=$((unhealthy + 1))
    else
      echo "  FAIL  $name: HTTP $status from $url (a health check needs 2xx; redirects are not followed)"
      unhealthy=$((unhealthy + 1))
    fi
  done <<EOF
$(wb_health_endpoints)
EOF
  return "$unhealthy"
}
