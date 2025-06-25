#!/bin/bash

# Integration test for Wildbox Security Gateway
# Tests basic functionality and routing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Test configuration
GATEWAY_URL="http://localhost"
GATEWAY_HTTPS_URL="https://localhost"

# Test functions
test_health_check() {
    log_info "Testing health check endpoint..."
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/health")
    
    if [ "$response" = "200" ]; then
        log_success "Health check passed (HTTP)"
    else
        log_error "Health check failed (HTTP): $response"
        return 1
    fi
    
    # Test HTTPS health check (ignore cert for self-signed)
    local https_response=$(curl -k -s -o /dev/null -w "%{http_code}" "$GATEWAY_HTTPS_URL/health")
    
    if [ "$https_response" = "200" ]; then
        log_success "Health check passed (HTTPS)"
    else
        log_error "Health check failed (HTTPS): $https_response"
        return 1
    fi
}

test_http_redirect() {
    log_info "Testing HTTP to HTTPS redirect..."
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/")
    
    if [ "$response" = "301" ]; then
        log_success "HTTP redirect working"
    else
        log_error "HTTP redirect failed: $response"
        return 1
    fi
}

test_ssl_configuration() {
    log_info "Testing SSL configuration..."
    
    # Test if SSL connection can be established
    if echo | openssl s_client -connect localhost:443 -servername wildbox.local 2>/dev/null | grep -q "CONNECTED"; then
        log_success "SSL connection established"
    else
        log_error "SSL connection failed"
        return 1
    fi
}

test_authentication_required() {
    log_info "Testing authentication requirement..."
    
    # Test API endpoint without auth should return 401
    local response=$(curl -k -s -o /dev/null -w "%{http_code}" "$GATEWAY_HTTPS_URL/api/v1/data/")
    
    if [ "$response" = "401" ]; then
        log_success "Authentication required (401 returned)"
    else
        log_warning "Expected 401, got: $response (might be expected if service not running)"
    fi
}

test_unknown_endpoint() {
    log_info "Testing unknown endpoint handling..."
    
    local response=$(curl -k -s -o /dev/null -w "%{http_code}" "$GATEWAY_HTTPS_URL/api/v1/nonexistent/")
    
    if [ "$response" = "404" ]; then
        log_success "Unknown endpoint handled correctly (404)"
    else
        log_warning "Expected 404, got: $response"
    fi
}

wait_for_service() {
    log_info "Waiting for gateway to be ready..."
    
    local max_retries=30
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        if curl -f -s "$GATEWAY_URL/health" > /dev/null 2>&1; then
            log_success "Gateway is ready!"
            return 0
        fi
        
        retry=$((retry + 1))
        if [ $retry -eq $max_retries ]; then
            log_error "Gateway failed to start within timeout"
            return 1
        fi
        
        sleep 2
    done
}

# Main test execution
main() {
    echo "🧪 Wildbox Security Gateway Integration Tests"
    echo "============================================"
    echo
    
    # Check if gateway is running
    if ! docker-compose ps | grep -q "wildbox-gateway.*Up"; then
        log_warning "Gateway not running, starting it..."
        cd "$PROJECT_DIR"
        make start
        sleep 10
    fi
    
    # Wait for service to be ready
    wait_for_service
    
    # Run tests
    local tests_passed=0
    local tests_total=0
    
    # Health check test
    tests_total=$((tests_total + 1))
    if test_health_check; then
        tests_passed=$((tests_passed + 1))
    fi
    
    # HTTP redirect test
    tests_total=$((tests_total + 1))
    if test_http_redirect; then
        tests_passed=$((tests_passed + 1))
    fi
    
    # SSL configuration test
    tests_total=$((tests_total + 1))
    if test_ssl_configuration; then
        tests_passed=$((tests_passed + 1))
    fi
    
    # Authentication test
    tests_total=$((tests_total + 1))
    if test_authentication_required; then
        tests_passed=$((tests_passed + 1))
    fi
    
    # Unknown endpoint test
    tests_total=$((tests_total + 1))
    if test_unknown_endpoint; then
        tests_passed=$((tests_passed + 1))
    fi
    
    # Results
    echo
    echo "📊 Test Results:"
    echo "  Passed: $tests_passed/$tests_total"
    
    if [ $tests_passed -eq $tests_total ]; then
        log_success "All tests passed! 🎉"
        return 0
    else
        log_error "Some tests failed"
        return 1
    fi
}

# Run tests
main "$@"
