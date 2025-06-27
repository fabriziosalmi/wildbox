#!/bin/bash
# Health check script for Docker containers

set -e

# Configuration
HOST=${HOST:-localhost}
PORT=${PORT:-8000}
TIMEOUT=${HEALTH_CHECK_TIMEOUT:-30}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Health check function
check_health() {
    local endpoint="http://${HOST}:${PORT}/health"
    local response
    local http_code
    
    log "Checking health endpoint: $endpoint"
    
    # Make HTTP request with timeout
    response=$(curl -s -w "%{http_code}" --max-time $TIMEOUT "$endpoint" 2>/dev/null || echo "000")
    http_code="${response: -3}"
    body="${response%???}"
    
    if [[ "$http_code" == "200" ]]; then
        log "Health check passed (HTTP $http_code)"
        if [[ -n "$body" && "$body" != "null" ]]; then
            log "Response: $body"
        fi
        return 0
    else
        error "Health check failed (HTTP $http_code)"
        if [[ -n "$body" && "$body" != "null" ]]; then
            error "Response: $body"
        fi
        return 1
    fi
}

# Check if service is responding
check_connectivity() {
    log "Checking connectivity to ${HOST}:${PORT}"
    
    if timeout $TIMEOUT bash -c "</dev/tcp/${HOST}/${PORT}"; then
        log "Service is accepting connections"
        return 0
    else
        error "Cannot connect to service"
        return 1
    fi
}

# Check Redis connectivity (if REDIS_URL is set)
check_redis() {
    if [[ -n "$REDIS_URL" ]]; then
        log "Checking Redis connectivity"
        
        # Extract host and port from Redis URL
        redis_host=$(echo "$REDIS_URL" | sed -n 's/.*:\/\/\([^:]*\).*/\1/p')
        redis_port=$(echo "$REDIS_URL" | sed -n 's/.*:\([0-9]*\).*/\1/p')
        
        if [[ -z "$redis_port" ]]; then
            redis_port=6379
        fi
        
        if timeout 5 bash -c "</dev/tcp/${redis_host}/${redis_port}"; then
            log "Redis is accessible"
            return 0
        else
            warn "Redis is not accessible"
            return 1
        fi
    fi
}

# Main health check
main() {
    log "Starting health check for Wildbox Security API"
    
    # Check basic connectivity first
    if ! check_connectivity; then
        exit 1
    fi
    
    # Check application health endpoint
    if ! check_health; then
        exit 1
    fi
    
    # Check Redis if configured
    check_redis || warn "Redis check failed, but continuing..."
    
    log "All health checks passed!"
    exit 0
}

# Run main function
main "$@"
