#!/bin/bash

# Wildbox Security Validation Script
# ==================================
# Checks for common security issues and misconfigurations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNING_CHECKS=$((WARNING_CHECKS + 1))
}

error() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
}

check_security_issue() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local check_name="$1"
    local command="$2"
    local description="$3"
    local severity="$4"  # CRITICAL, HIGH, MEDIUM, LOW
    
    log "Checking: $check_name"
    
    if eval "$command"; then
        if [[ "$severity" == "CRITICAL" ]]; then
            error "CRITICAL: $description"
        elif [[ "$severity" == "HIGH" ]]; then
            error "HIGH: $description"
        else
            warning "$severity: $description"
        fi
    else
        success "$check_name - OK"
    fi
}

echo "🔍 Wildbox Security Validation"
echo "==============================="
echo ""

# Check 1: Default passwords in configuration files (excluding intentionally insecure defaults)
check_security_issue \
    "Default Passwords Check" \
    'grep -r "admin123456\|password123\|ChangeMeInProduction123" . --exclude-dir=.git --exclude="security_validation.sh" >/dev/null 2>&1' \
    "Production-ready default passwords found in configuration files" \
    "CRITICAL"

# Check 2: Hardcoded JWT secrets (excluding intentionally insecure defaults)
check_security_issue \
    "JWT Secret Check" \
    'grep -r "wildbox-super-secret\|jwt.*testing\|secret.*key.*test" . --exclude-dir=.git --exclude="security_validation.sh" >/dev/null 2>&1' \
    "Production-ready JWT secrets found - these should be environment variables" \
    "CRITICAL"

# Check 3: Debug mode in production files
check_security_issue \
    "Debug Mode Check" \
    'grep -r "DEBUG.*=.*true" docker-compose.yml >/dev/null 2>&1' \
    "Debug mode enabled in docker-compose.yml - should be false for production" \
    "HIGH"

# Check 4: Weak database passwords
check_security_issue \
    "Database Password Check" \
    'grep -r "postgres.*postgres\|password.*postgres" docker-compose.yml >/dev/null 2>&1' \
    "Default database credentials found" \
    "CRITICAL"

# Check 5: Missing .env.example
check_security_issue \
    "Environment Template Check" \
    '! test -f .env.example' \
    "Missing .env.example template file" \
    "HIGH"

# Check 6: Sensitive files not in .gitignore
check_security_issue \
    "GitIgnore Security Check" \
    '! grep -q "\.env$" .gitignore || ! grep -q "secrets/" .gitignore' \
    "Sensitive file patterns missing from .gitignore" \
    "HIGH"

# Check 7: Production-ready CORS configuration
check_security_issue \
    "CORS Configuration Check" \
    'grep -r "localhost" docker-compose.yml | grep -q CORS_ORIGINS' \
    "CORS configured for localhost - update for production domains" \
    "MEDIUM"

# Check 8: SSL/HTTPS configuration
check_security_issue \
    "HTTPS Configuration Check" \
    '! grep -r "ssl\|https\|tls" docker-compose.yml >/dev/null 2>&1' \
    "No HTTPS/SSL configuration found - required for production" \
    "HIGH"

# Check 9: API keys in plain text
check_security_issue \
    "API Key Security Check" \
    'grep -r "wbx-.*-prod\|api.*key.*=" docker-compose.yml | grep -v "\${" >/dev/null 2>&1' \
    "API keys found in plain text instead of environment variables" \
    "CRITICAL"

# Check 10: Test credentials in verification scripts
check_security_issue \
    "Test Credentials Check" \
    'grep -r "admin123456\|test.*password\|dummy.*key" *.py *.js >/dev/null 2>&1' \
    "Test credentials found in scripts - should use environment variables" \
    "MEDIUM"

echo ""
echo "🔒 Security Validation Summary"
echo "=============================="
echo "Total Checks: $TOTAL_CHECKS"
echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
echo -e "Warnings: ${YELLOW}$WARNING_CHECKS${NC}"
echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
echo ""

if [[ $FAILED_CHECKS -gt 0 ]]; then
    echo -e "${RED}❌ Security validation FAILED${NC}"
    echo "Please address the failed checks above before deploying to production."
    echo ""
    echo "Quick fixes:"
    echo "1. Copy .env.example to .env and configure secure values"
    echo "2. Generate secure random values for all secrets"
    echo "3. Set DEBUG=false for production"
    echo "4. Configure proper CORS origins for your domain"
    echo "5. Review SECURITY.md for complete requirements"
    exit 1
elif [[ $WARNING_CHECKS -gt 0 ]]; then
    echo -e "${YELLOW}⚠️  Security validation passed with warnings${NC}"
    echo "Consider addressing the warnings above for better security."
    exit 0
else
    echo -e "${GREEN}✅ Security validation PASSED${NC}"
    echo "All security checks passed!"
    exit 0
fi