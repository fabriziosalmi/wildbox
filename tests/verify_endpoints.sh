#!/bin/bash
# Wildbox Endpoint Verification Script
# Tests all "Unknown" endpoints from Pages Status Report

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# API Keys
GUARDIAN_API_KEY="your-guardian-api-key"
TOOLS_API_KEY="your-tools-api-key"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to test endpoint
test_endpoint() {
    local name="$1"
    local url="$2"
    local method="${3:-GET}"
    local api_key="$4"
    local expected_status="${5:-200}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "\n${BLUE}Testing: ${name}${NC}"
    echo "URL: ${url}"
    
    local response
    local status
    
    if [ -n "$api_key" ]; then
        response=$(curl -s -X "$method" "$url" \
            -H "X-API-Key: $api_key" \
            -H "Content-Type: application/json" \
            -w "\n%{http_code}" \
            --max-time 10)
    else
        response=$(curl -s -X "$method" "$url" \
            -H "Content-Type: application/json" \
            -w "\n%{http_code}" \
            --max-time 10)
    fi
    
    status=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✅ PASS${NC} (HTTP $status)"
        if [ -n "$body" ] && [ "$body" != "null" ]; then
            echo "Response preview: $(echo "$body" | jq -c . 2>/dev/null | head -c 100)..."
        fi
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC} (HTTP $status, expected $expected_status)"
        if [ -n "$body" ]; then
            echo "Error: $body"
        fi
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Print header
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Wildbox Endpoint Verification - Task 2.3              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Testing all 'Unknown' endpoints from Pages Status Report..."

# ============================================================================
# GUARDIAN ENDPOINTS (Now Fixed!)
# ============================================================================
echo -e "\n${YELLOW}═══ GUARDIAN (Vulnerability Management) ═══${NC}"

test_endpoint \
    "Guardian Stats (via Gateway)" \
    "http://localhost/api/v1/guardian/vulnerabilities/stats/" \
    "GET" \
    "$GUARDIAN_API_KEY" \
    "200"

test_endpoint \
    "Guardian Vulnerabilities List (via Gateway)" \
    "http://localhost/api/v1/guardian/vulnerabilities/?page=1&page_size=5" \
    "GET" \
    "$GUARDIAN_API_KEY" \
    "200"

test_endpoint \
    "Guardian Direct Stats (bypass gateway)" \
    "http://localhost:8013/api/v1/vulnerabilities/vulnerabilities/stats/" \
    "GET" \
    "$GUARDIAN_API_KEY" \
    "200"

# ============================================================================
# THREAT INTEL ENDPOINTS
# ============================================================================
echo -e "\n${YELLOW}═══ THREAT INTELLIGENCE ═══${NC}"

test_endpoint \
    "Threat Intel Lookup (via Gateway)" \
    "http://localhost/api/v1/data/indicators/search?query=8.8.8.8&type=ip" \
    "GET" \
    "" \
    "200"

test_endpoint \
    "Threat Intel Data (via Gateway)" \
    "http://localhost/api/v1/data/indicators/?page=1&limit=10" \
    "GET" \
    "" \
    "200"

# ============================================================================
# RESPONDER ENDPOINTS
# ============================================================================
echo -e "\n${YELLOW}═══ INCIDENT RESPONSE (Responder) ═══${NC}"

test_endpoint \
    "Responder Playbooks List" \
    "http://localhost:8018/api/v1/playbooks" \
    "GET" \
    "" \
    "200"

test_endpoint \
    "Responder Runs History" \
    "http://localhost:8018/api/v1/runs" \
    "GET" \
    "" \
    "200"

test_endpoint \
    "Responder Metrics" \
    "http://localhost:8018/api/v1/metrics" \
    "GET" \
    "" \
    "200"

# ============================================================================
# AI AGENTS ENDPOINTS
# ============================================================================
echo -e "\n${YELLOW}═══ AI ANALYST (Agents) ═══${NC}"

test_endpoint \
    "AI Agents Health" \
    "http://localhost:8006/health" \
    "GET" \
    "" \
    "200"

test_endpoint \
    "AI Agents Capabilities" \
    "http://localhost:8006/api/v1/capabilities" \
    "GET" \
    "" \
    "200"

# ============================================================================
# TOOLS ENDPOINTS
# ============================================================================
echo -e "\n${YELLOW}═══ SECURITY TOOLS ═══${NC}"

test_endpoint \
    "Tools List" \
    "http://localhost:8000/api/v1/tools" \
    "GET" \
    "$TOOLS_API_KEY" \
    "200"

test_endpoint \
    "Tool Categories" \
    "http://localhost:8000/api/v1/categories" \
    "GET" \
    "$TOOLS_API_KEY" \
    "200"

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                      TEST SUMMARY                              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Total Tests:  $TOTAL_TESTS"
echo -e "${GREEN}Passed:       $PASSED_TESTS${NC}"
echo -e "${RED}Failed:       $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✅ All endpoints are working!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Update Pages Status Report"
    echo "  2. Test through Dashboard UI"
    echo "  3. Run integration tests"
    exit 0
else
    echo -e "${RED}❌ Some endpoints failed. Review the output above.${NC}"
    exit 1
fi
