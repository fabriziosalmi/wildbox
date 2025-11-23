#!/bin/bash
# Strict .env Validation Script
# Purpose: Refuse to start Docker containers if insecure default credentials are detected
# Usage: ./validate_env.sh before docker-compose up

set -e

echo "🔒 Validating .env configuration..."
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VALIDATION_FAILED=false
WARNINGS=()

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${RED}✗ CRITICAL: .env file not found${NC}"
    echo ""
    echo "Create .env from template:"
    echo "  cp .env.example .env"
    echo ""
    echo "Then update with secure values:"
    echo "  JWT_SECRET_KEY: openssl rand -hex 32"
    echo "  NEXTAUTH_SECRET: openssl rand -base64 32"
    echo "  POSTGRES_PASSWORD: openssl rand -base64 32"
    exit 1
fi

echo "✓ .env file exists"
echo ""

# Define insecure patterns that MUST NOT be in .env
INSECURE_PATTERNS=(
    # Default PostgreSQL credentials
    "postgres:postgres@"
    "postgres:postgres\$"
    "POSTGRES_PASSWORD=postgres"
    "POSTGRES_PASSWORD=password"
    "POSTGRES_PASSWORD=admin"
    
    # Insecure JWT secrets
    "JWT_SECRET_KEY=INSECURE-DEFAULT"
    "JWT_SECRET_KEY=your-super-secret"
    "JWT_SECRET_KEY=change-this"
    "JWT_SECRET_KEY=test"
    
    # Insecure NEXTAUTH secrets
    "NEXTAUTH_SECRET=wildbox-dashboard-secret"
    "NEXTAUTH_SECRET=wildbox-dev-secret"
    "NEXTAUTH_SECRET=secret"
    "NEXTAUTH_SECRET=test"
    
    # Placeholder patterns
    "generate-a-secure"
    "generate-secure"
    "replace-this-with"
    "your-secret-key-here"
    "change-me"
    "changeme"
    "CHANGE-THIS"
    
    # Weak passwords
    "PASSWORD=admin"
    "PASSWORD=password"
    "PASSWORD=123456"
    
    # Default API keys (from git history)
    "UrZMId_lkb_-9TcWSicVPCVNqSvnwr8e2VS9iXTAfxw"
    "wildbox-security-api-key-2025"
    
    # Test credentials that should never be in production
    "TestPassword123"
)

echo "Checking for insecure default credentials..."
for pattern in "${INSECURE_PATTERNS[@]}"; do
    if grep -q "$pattern" .env; then
        echo -e "${RED}✗ CRITICAL: Insecure credential detected: $pattern${NC}"
        VALIDATION_FAILED=true
    fi
done

# Check for required environment variables
REQUIRED_VARS=(
    "JWT_SECRET_KEY"
    "NEXTAUTH_SECRET"
    "POSTGRES_PASSWORD"
    "GATEWAY_INTERNAL_SECRET"
)

echo ""
echo "Checking for required environment variables..."
for var in "${REQUIRED_VARS[@]}"; do
    if ! grep -q "^${var}=" .env; then
        echo -e "${RED}✗ CRITICAL: Missing required variable: $var${NC}"
        VALIDATION_FAILED=true
    else
        # Check if variable is set but empty
        value=$(grep "^${var}=" .env | cut -d'=' -f2-)
        if [ -z "$value" ]; then
            echo -e "${RED}✗ CRITICAL: $var is empty${NC}"
            VALIDATION_FAILED=true
        else
            echo -e "${GREEN}✓ $var is set${NC}"
        fi
    fi
done

# Check secret strength
echo ""
echo "Validating secret strength..."

# JWT_SECRET_KEY should be at least 32 characters
JWT_SECRET=$(grep "^JWT_SECRET_KEY=" .env | cut -d'=' -f2- || echo "")
if [ -n "$JWT_SECRET" ] && [ ${#JWT_SECRET} -lt 32 ]; then
    echo -e "${YELLOW}⚠ WARNING: JWT_SECRET_KEY is too short (${#JWT_SECRET} chars, minimum 32)${NC}"
    WARNINGS+=("JWT_SECRET_KEY should be at least 32 characters")
fi

# NEXTAUTH_SECRET should be at least 32 characters
NEXTAUTH_SECRET=$(grep "^NEXTAUTH_SECRET=" .env | cut -d'=' -f2- || echo "")
if [ -n "$NEXTAUTH_SECRET" ] && [ ${#NEXTAUTH_SECRET} -lt 32 ]; then
    echo -e "${YELLOW}⚠ WARNING: NEXTAUTH_SECRET is too short (${#NEXTAUTH_SECRET} chars, minimum 32)${NC}"
    WARNINGS+=("NEXTAUTH_SECRET should be at least 32 characters")
fi

# POSTGRES_PASSWORD should be at least 16 characters
POSTGRES_PASSWORD=$(grep "^POSTGRES_PASSWORD=" .env | cut -d'=' -f2- || echo "")
if [ -n "$POSTGRES_PASSWORD" ] && [ ${#POSTGRES_PASSWORD} -lt 16 ]; then
    echo -e "${YELLOW}⚠ WARNING: POSTGRES_PASSWORD is too short (${#POSTGRES_PASSWORD} chars, minimum 16)${NC}"
    WARNINGS+=("POSTGRES_PASSWORD should be at least 16 characters")
fi

# Check for potentially exposed secrets in comments
if grep -E "^#.*SECRET.*=" .env | grep -vE "example|generate|your-" > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠ WARNING: Commented out secrets detected (may indicate test data)${NC}"
    WARNINGS+=("Review commented secrets in .env")
fi

# Summary
echo ""
echo "═══════════════════════════════════════"
if [ "$VALIDATION_FAILED" = true ]; then
    echo -e "${RED}✗ VALIDATION FAILED${NC}"
    echo ""
    echo "Your .env file contains insecure default credentials."
    echo "This configuration MUST NOT be used in any environment."
    echo ""
    echo "To fix:"
    echo ""
    echo "1. Generate secure secrets:"
    echo "   JWT_SECRET_KEY=\$(openssl rand -hex 32)"
    echo "   NEXTAUTH_SECRET=\$(openssl rand -base64 32)"
    echo "   POSTGRES_PASSWORD=\$(openssl rand -base64 32)"
    echo "   GATEWAY_INTERNAL_SECRET=\$(openssl rand -hex 32)"
    echo ""
    echo "2. Update .env file with generated values"
    echo ""
    echo "3. Re-run this validation: ./validate_env.sh"
    echo ""
    exit 1
fi

if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo -e "${YELLOW}⚠ VALIDATION PASSED WITH WARNINGS${NC}"
    echo ""
    echo "Warnings:"
    for warning in "${WARNINGS[@]}"; do
        echo "  - $warning"
    done
    echo ""
    echo "These warnings should be addressed before production deployment."
    echo ""
else
    echo -e "${GREEN}✓ VALIDATION PASSED${NC}"
    echo ""
    echo "Your .env configuration meets minimum security requirements."
    echo ""
fi

echo "═══════════════════════════════════════"
echo ""

# Exit with success if validation passed (even with warnings)
exit 0
