#!/bin/bash
# Wildbox Security Validation Script
# Post-Audit Compliance Checker
# Version: 2.1

# Don't exit on error - we want to run all checks and report at the end
set +e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
WARNINGS=0

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   WILDBOX SECURITY VALIDATION REPORT${NC}"
echo -e "${BLUE}   Post-Audit Compliance Verification${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============================================================================
# CRITICAL SECURITY CHECKS
# ============================================================================

echo -e "${BLUE}[1/8] Checking for hardcoded secrets...${NC}"

# Check docker-compose.yml for hardcoded passwords
HARDCODED_SECRETS=$(grep -r "PASSWORD=.*[^$]" docker-compose.yml open-security-*/docker-compose.yml 2>/dev/null | grep -v "\${" | grep -v "^#" || true)

if [ -z "$HARDCODED_SECRETS" ]; then
    echo -e "  ${GREEN}✓ No hardcoded secrets found in docker-compose files${NC}"
    ((PASSED++))
else
    echo -e "  ${RED}✗ Hardcoded secrets detected:${NC}"
    echo "$HARDCODED_SECRETS" | sed 's/^/    /'
    ((FAILED++))
fi

# Check for committed .env files (git ls-files returns 0 if tracked, non-zero if not)
if [ -f ".env" ]; then
    if git ls-files --error-unmatch .env >/dev/null 2>&1; then
        echo -e "  ${RED}✗ .env file is tracked by git (should be in .gitignore)${NC}"
        ((FAILED++))
    else
        echo -e "  ${GREEN}✓ .env file not committed to version control${NC}"
        ((PASSED++))
    fi
else
    echo -e "  ${GREEN}✓ No .env file present${NC}"
    ((PASSED++))
fi

# Check .env.example has required variables
REQUIRED_VARS=("JWT_SECRET_KEY" "NEXTAUTH_SECRET" "POSTGRES_PASSWORD" "N8N_BASIC_AUTH_PASSWORD" "GRAFANA_ADMIN_PASSWORD")
MISSING_VARS=()

for var in "${REQUIRED_VARS[@]}"; do
    if ! grep -q "^$var=" .env.example 2>/dev/null; then
        MISSING_VARS+=("$var")
    fi
done

if [ ${#MISSING_VARS[@]} -eq 0 ]; then
    echo -e "  ${GREEN}✓ All required secrets documented in .env.example${NC}"
    ((PASSED++))
else
    echo -e "  ${RED}✗ Missing secrets in .env.example: ${MISSING_VARS[*]}${NC}"
    ((FAILED++))
fi

echo ""

# ============================================================================
# DEPENDENCY PINNING CHECKS
# ============================================================================

echo -e "${BLUE}[2/8] Checking Docker image versions...${NC}"

# Check for :latest tags
LATEST_TAGS=$(grep -r "image:.*:latest" docker-compose.yml open-security-*/docker-compose.yml 2>/dev/null | grep -v "^#" || true)

if [ -z "$LATEST_TAGS" ]; then
    echo -e "  ${GREEN}✓ All Docker images pinned to specific versions${NC}"
    ((PASSED++))
else
    echo -e "  ${RED}✗ Unpinned Docker images found:${NC}"
    echo "$LATEST_TAGS" | sed 's/^/    /'
    ((FAILED++))
fi

echo ""

echo -e "${BLUE}[3/8] Checking Python dependency pinning...${NC}"

UNPINNED_DEPS=0

for req_file in open-security-*/requirements.txt; do
    if [ -f "$req_file" ]; then
        # Check for >= or > in requirements
        UNPINNED=$(grep -E ">=|>" "$req_file" 2>/dev/null | grep -v "^#" || true)
        
        if [ -n "$UNPINNED" ]; then
            echo -e "  ${RED}✗ Unpinned dependencies in $req_file:${NC}"
            echo "$UNPINNED" | sed 's/^/    /'
            ((UNPINNED_DEPS++))
        fi
    fi
done

if [ $UNPINNED_DEPS -eq 0 ]; then
    echo -e "  ${GREEN}✓ All Python dependencies pinned to exact versions${NC}"
    ((PASSED++))
else
    echo -e "  ${RED}✗ Found $UNPINNED_DEPS files with unpinned dependencies${NC}"
    ((FAILED++))
fi

echo ""

# ============================================================================
# TEST SUITE INTEGRITY
# ============================================================================

echo -e "${BLUE}[4/8] Checking test suite configuration...${NC}"

# Check for || true in test commands
TEST_BYPASS=$(grep -n "^\s*test.*|| true" Makefile open-security-*/Makefile 2>/dev/null | grep -v "find.*||" | grep -v "^#" || true)

if [ -z "$TEST_BYPASS" ]; then
    echo -e "  ${GREEN}✓ No test failures being silenced (no '|| true')${NC}"
    ((PASSED++))
else
    echo -e "  ${RED}✗ Test failures being bypassed:${NC}"
    echo "$TEST_BYPASS" | sed 's/^/    /'
    ((FAILED++))
fi

# Check if pytest is configured
PYTEST_COUNT=$(find open-security-* -name "pytest.ini" -o -name "pyproject.toml" 2>/dev/null | wc -l)

if [ "$PYTEST_COUNT" -gt 0 ]; then
    echo -e "  ${GREEN}✓ Pytest configuration found${NC}"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠ No pytest configuration files found${NC}"
    ((WARNINGS++))
fi

echo ""

# ============================================================================
# ERROR HANDLING CHECKS
# ============================================================================

echo -e "${BLUE}[5/8] Checking error handling patterns...${NC}"

# Check for blanket exception handling
BLANKET_EXCEPTIONS=$(grep -rn "except Exception as e:" open-security-*/app/*.py 2>/dev/null | wc -l)

if [ "$BLANKET_EXCEPTIONS" -lt 10 ]; then
    echo -e "  ${GREEN}✓ Limited use of blanket exception handling ($BLANKET_EXCEPTIONS instances)${NC}"
    ((PASSED++))
elif [ "$BLANKET_EXCEPTIONS" -lt 20 ]; then
    echo -e "  ${YELLOW}⚠ Moderate blanket exception handling ($BLANKET_EXCEPTIONS instances)${NC}"
    echo -e "    ${YELLOW}Consider using specific exception types${NC}"
    ((WARNINGS++))
else
    echo -e "  ${RED}✗ Excessive blanket exception handling ($BLANKET_EXCEPTIONS instances)${NC}"
    echo -e "    ${RED}See docs/ENGINEERING_STANDARDS.md for proper error handling${NC}"
    ((FAILED++))
fi

# Check for proper logging
LOGGER_IMPORTS=$(grep -r "import.*logger\|import.*structlog" open-security-*/app/*.py 2>/dev/null | wc -l)

if [ "$LOGGER_IMPORTS" -gt 5 ]; then
    echo -e "  ${GREEN}✓ Structured logging in use${NC}"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠ Limited logging implementation${NC}"
    ((WARNINGS++))
fi

echo ""

# ============================================================================
# OBSERVABILITY CHECKS
# ============================================================================

echo -e "${BLUE}[6/8] Checking observability implementation...${NC}"

# Check for health endpoints
HEALTH_ENDPOINTS=$(grep -r "@router.get.*health" open-security-*/app/*.py 2>/dev/null | wc -l)

if [ "$HEALTH_ENDPOINTS" -ge 5 ]; then
    echo -e "  ${GREEN}✓ Health check endpoints implemented ($HEALTH_ENDPOINTS services)${NC}"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠ Limited health check coverage ($HEALTH_ENDPOINTS endpoints)${NC}"
    ((WARNINGS++))
fi

# Check for metrics endpoints
METRICS_ENDPOINTS=$(grep -r "@router.get.*metrics" open-security-*/app/*.py 2>/dev/null | wc -l)

if [ "$METRICS_ENDPOINTS" -ge 3 ]; then
    echo -e "  ${GREEN}✓ Metrics endpoints implemented${NC}"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠ Metrics endpoints need implementation${NC}"
    ((WARNINGS++))
fi

echo ""

# ============================================================================
# DOCUMENTATION CHECKS
# ============================================================================

echo -e "${BLUE}[7/8] Checking documentation...${NC}"

REQUIRED_DOCS=("README.md" "SECURITY.md" "docs/ENGINEERING_STANDARDS.md" ".env.example")
MISSING_DOCS=()

for doc in "${REQUIRED_DOCS[@]}"; do
    if [ ! -f "$doc" ]; then
        MISSING_DOCS+=("$doc")
    fi
done

if [ ${#MISSING_DOCS[@]} -eq 0 ]; then
    echo -e "  ${GREEN}✓ All required documentation present${NC}"
    ((PASSED++))
else
    echo -e "  ${RED}✗ Missing documentation: ${MISSING_DOCS[*]}${NC}"
    ((FAILED++))
fi

# Check for API documentation
OPENAPI_DOCS=$(find open-security-* -name "main.py" -exec grep -l "openapi_tags\|swagger_ui_parameters" {} \; 2>/dev/null | wc -l)

if [ "$OPENAPI_DOCS" -ge 3 ]; then
    echo -e "  ${GREEN}✓ OpenAPI documentation configured${NC}"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠ Limited OpenAPI documentation${NC}"
    ((WARNINGS++))
fi

echo ""

# ============================================================================
# PRODUCTION READINESS
# ============================================================================

echo -e "${BLUE}[8/8] Checking production readiness...${NC}"

# Check for resource limits in docker-compose
RESOURCE_LIMITS=$(grep -r "resources:" docker-compose.yml 2>/dev/null | wc -l)

if [ "$RESOURCE_LIMITS" -ge 3 ]; then
    echo -e "  ${GREEN}✓ Resource limits configured${NC}"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠ Limited resource limits configured${NC}"
    echo -e "    ${YELLOW}Consider adding CPU/memory limits to prevent resource exhaustion${NC}"
    ((WARNINGS++))
fi

# Check for .dockerignore files
DOCKERIGNORE_COUNT=$(find open-security-* -name ".dockerignore" 2>/dev/null | wc -l)

if [ "$DOCKERIGNORE_COUNT" -ge 5 ]; then
    echo -e "  ${GREEN}✓ .dockerignore files present${NC}"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠ Missing .dockerignore files in some services${NC}"
    ((WARNINGS++))
fi

echo ""

# ============================================================================
# SUMMARY REPORT
# ============================================================================

TOTAL=$((PASSED + FAILED + WARNINGS))
SCORE=$((PASSED * 100 / TOTAL))

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   VALIDATION SUMMARY${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}Passed:   ${PASSED}${NC}"
echo -e "  ${RED}Failed:   ${FAILED}${NC}"
echo -e "  ${YELLOW}Warnings: ${WARNINGS}${NC}"
echo ""
echo -e "  Overall Score: ${SCORE}%"
echo ""

# Grade determination
if [ $SCORE -ge 90 ]; then
    GRADE="A"
    COLOR=$GREEN
elif [ $SCORE -ge 80 ]; then
    GRADE="B"
    COLOR=$GREEN
elif [ $SCORE -ge 70 ]; then
    GRADE="C"
    COLOR=$YELLOW
elif [ $SCORE -ge 60 ]; then
    GRADE="D"
    COLOR=$YELLOW
else
    GRADE="F"
    COLOR=$RED
fi

echo -e "  Grade: ${COLOR}${GRADE}${NC}"
echo ""

# Comparison to audit
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   AUDIT COMPARISON${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Initial Audit Score: 41% (D-)"
echo "  Current Score:       ${SCORE}% (${GRADE})"
echo ""

if [ $SCORE -gt 41 ]; then
    IMPROVEMENT=$((SCORE - 41))
    echo -e "  ${GREEN}Improvement: +${IMPROVEMENT} points${NC}"
else
    DECLINE=$((41 - SCORE))
    echo -e "  ${RED}Decline: -${DECLINE} points${NC}"
fi

echo ""

# Recommendations
if [ $FAILED -gt 0 ]; then
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}   CRITICAL ACTIONS REQUIRED${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  1. Review failed checks above"
    echo "  2. Consult docs/ENGINEERING_STANDARDS.md"
    echo "  3. Fix critical security issues before deployment"
    echo ""
fi

# Exit code
if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
