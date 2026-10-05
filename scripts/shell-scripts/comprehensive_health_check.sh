#!/bin/bash

# Wildbox Security Platform - Health Check
# ========================================
#
# `make health` runs this. It exits non-zero when anything it checks is
# unhealthy, so it can gate a deployment step or a cron alert:
#
#   - every service in scripts/lib/health_endpoints.sh must answer 2xx on
#     its health URL. Redirects are not followed and error statuses are
#     failures: guardian's /health answers 301 and used to count as healthy
#     while /health/ answered 503 (#656);
#   - PostgreSQL must accept connections and hold the three databases;
#   - Redis must answer.
#
# The check only reads. The repairs it used to apply on every run (creating
# a database, restarting the gateway when its log ever held a certain line)
# are under `fix`, where you ask for them.
#
# Usage: comprehensive_health_check.sh [check|services|databases|containers|fix|urls]
#
# Services under a Compose profile (automations, monitoring) are skipped when
# they are not running, unless COMPOSE_PROFILES names the profile.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=scripts/lib/health_endpoints.sh
. "$REPO_ROOT/scripts/lib/health_endpoints.sh"
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARN:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS:${NC} $1"
}

DATABASES="identity data guardian"

# `docker compose` first: the production overlay needs Compose v2, and a
# legacy docker-compose binary would refuse the file.
COMPOSE=()
find_compose() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE=(docker-compose)
    else
        error "Neither docker compose nor docker-compose is available"
        return 1
    fi
}

# Container status. Informational: a container that is down shows up as a
# failed service or database check below.
check_containers() {
    log "Checking container status..."
    find_compose || return 1
    "${COMPOSE[@]}" ps --format "table {{.Name}}\t{{.State}}\t{{.Status}}" 2>/dev/null \
        || warn "Could not list the containers"
}

# PostgreSQL and Redis, from inside their containers. Returns the number of
# failed checks.
check_databases() {
    log "Checking PostgreSQL and Redis..."
    find_compose || return 1
    local failed=0 existing db reply

    # shellcheck disable=SC2016
    if "${COMPOSE[@]}" exec -T postgres sh -c 'pg_isready -q -U "${POSTGRES_USER:-postgres}"' >/dev/null 2>&1; then
        success "PostgreSQL accepts connections"
        # shellcheck disable=SC2016
        existing=$("${COMPOSE[@]}" exec -T postgres sh -c \
            'psql -U "${POSTGRES_USER:-postgres}" -d postgres -X -q -tA -c "SELECT datname FROM pg_database"' \
            2>/dev/null </dev/null || true)
        for db in $DATABASES; do
            if ! printf '%s\n' "$existing" | grep -qx "$db"; then
                error "PostgreSQL has no '$db' database ($0 fix creates it)"
                failed=$((failed + 1))
            fi
        done
    else
        error "PostgreSQL is not accepting connections"
        failed=$((failed + 1))
    fi

    # Without the password Redis answers NOAUTH, which still shows it is up
    # and enforcing authentication. Anything else is a failure.
    reply=$("${COMPOSE[@]}" exec -T wildbox-redis redis-cli ping 2>&1 </dev/null || true)
    case "$reply" in
        PONG*|*NOAUTH*) success "Redis answers" ;;
        *)
            error "Redis does not answer"
            failed=$((failed + 1))
            ;;
    esac
    return "$failed"
}

# The HTTP health endpoints. Returns the number of unhealthy services.
check_service_health() {
    log "Checking service health endpoints (2xx required, redirects not followed)..."
    local unhealthy=0
    wb_check_stack_health || unhealthy=$?
    if [[ $unhealthy -eq 0 ]]; then
        success "All services are healthy"
    else
        error "$unhealthy service(s) unhealthy"
    fi
    return "$unhealthy"
}

# Repairs for known situations. Only on request (`fix`): they create a
# database and restart services.
fix_known_issues() {
    log "Checking for known issues and applying fixes..."
    find_compose || return 1
    local existing db

    # shellcheck disable=SC2016
    existing=$("${COMPOSE[@]}" exec -T postgres sh -c \
        'psql -U "${POSTGRES_USER:-postgres}" -d postgres -X -q -tA -c "SELECT datname FROM pg_database"' \
        2>/dev/null </dev/null || true)
    if [[ -n "$existing" ]]; then
        for db in $DATABASES; do
            if ! printf '%s\n' "$existing" | grep -qx "$db"; then
                warn "Creating the missing '$db' database"
                # shellcheck disable=SC2016
                "${COMPOSE[@]}" exec -T postgres sh -c 'createdb -U "${POSTGRES_USER:-postgres}" "$1"' sh "$db" \
                    </dev/null || warn "Failed to create database: $db"
            fi
        done
    fi

    if "${COMPOSE[@]}" logs --since 10m gateway 2>/dev/null | grep -q "host not found in upstream"; then
        warn "The gateway could not resolve an upstream in the last 10 minutes; restarting it"
        "${COMPOSE[@]}" restart gateway || warn "Failed to restart gateway"
    fi

    if "${COMPOSE[@]}" logs --since 10m api 2>/dev/null | grep -q "No module named"; then
        warn "The api container is missing a Python module: rebuild it (docker compose build api)"
    fi
}

# Function to show resource usage
show_resource_usage() {
    log "Checking resource usage..."

    if command -v docker >/dev/null 2>&1; then
        echo "Container Resource Usage:"
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" 2>/dev/null || warn "Could not get container stats"
        echo ""
    fi

    echo "Disk: $(df -h / 2>/dev/null | tail -1 | awk '{print $3 "/" $2 " (" $5 " used)"}' || echo "N/A")"
    echo ""
}

# The table the checks use, for a human.
show_service_urls() {
    log "Health URLs (scripts/lib/health_endpoints.sh):"
    echo ""
    wb_health_endpoints | while IFS='|' read -r name url profile; do
        printf '  %-14s %s%s\n' "$name" "$url" "${profile:+   (profile: $profile)}"
    done
    echo ""
    echo "Clients use the gateway over HTTPS on port 443; the other ports are"
    echo "bound to 127.0.0.1. See docs/guides/ports.md."
    echo ""
}

# Full check. Exits non-zero when anything is unhealthy.
main() {
    echo "Wildbox Security Platform - Health Check"
    echo "========================================"
    echo ""

    local failures=0 count=0

    check_containers || true
    echo ""
    count=0
    check_databases || count=$?
    failures=$((failures + count))
    echo ""
    count=0
    check_service_health || count=$?
    failures=$((failures + count))
    echo ""
    show_resource_usage

    echo "Health Check Complete"
    echo "====================="
    if [[ $failures -eq 0 ]]; then
        success "Everything checked is healthy"
        return 0
    fi
    error "$failures check(s) failed"
    log "Logs: docker compose logs --tail=100 <service>"
    log "Known repairs (creates a missing database, restarts the gateway): $0 fix"
    return 1
}

# Handle command line arguments
case "${1:-check}" in
    "check"|"")
        main
        ;;
    "fix")
        fix_known_issues
        ;;
    "services")
        check_service_health || exit 1
        ;;
    "containers")
        check_containers
        ;;
    "databases")
        check_databases || exit 1
        ;;
    "urls")
        show_service_urls
        ;;
    *)
        echo "Usage: $0 [check|fix|services|containers|databases|urls]"
        echo ""
        echo "Commands:"
        echo "  check       - Run the full health check (default); non-zero exit when unhealthy"
        echo "  services    - Check the HTTP health endpoints only"
        echo "  databases   - Check PostgreSQL and Redis only"
        echo "  containers  - Show container status"
        echo "  fix         - Apply repairs for known issues (creates databases, restarts services)"
        echo "  urls        - Show the health URLs"
        exit 1
        ;;
esac
