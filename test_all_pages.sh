#!/bin/bash

# Comprehensive Dashboard Pages Test Script
# Tests all pages for real data and reports issues

set -e

echo "========================================"
echo "Dashboard Pages Verification Test"
echo "========================================"
echo ""

# Wait for services to be ready
echo "⏳ Waiting 30 seconds for all services to start..."
sleep 30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to test endpoint
test_endpoint() {
    local name=$1
    local url=$2
    local headers=$3
    local expected_status=${4:-200}
    
    echo -n "Testing $name... "
    
    if [ -n "$headers" ]; then
        response=$(curl -s -w "\n%{http_code}" -H "$headers" "$url")
    else
        response=$(curl -s -w "\n%{http_code}" "$url")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [ "$http_code" -eq "$expected_status" ]; then
        echo -e "${GREEN}✅ PASS${NC} (HTTP $http_code)"
        echo "   Response preview: $(echo "$body" | head -c 100)..."
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC} (HTTP $http_code, expected $expected_status)"
        echo "   Response: $body"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Function to test JSON endpoint
test_json_endpoint() {
    local name=$1
    local url=$2
    local headers=$3
    local jq_filter=${4:-'.'}
    
    echo -n "Testing $name... "
    
    if [ -n "$headers" ]; then
        response=$(curl -s -H "$headers" "$url")
    else
        response=$(curl -s "$url")
    fi
    
    # Check if response is valid JSON
    if echo "$response" | jq -e "$jq_filter" > /dev/null 2>&1; then
        count=$(echo "$response" | jq "$jq_filter" 2>/dev/null)
        echo -e "${GREEN}✅ PASS${NC}"
        echo "   Data: $count"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo "   Invalid JSON or query failed"
        echo "   Response: $(echo "$response" | head -c 200)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

echo "========================================="
echo "1. Testing Toolbox Page API"
echo "========================================="
test_json_endpoint "Tools List" \
    "http://localhost:80/api/v1/tools/tools" \
    "X-API-Key: wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90" \
    "length"

echo ""
echo "========================================="
echo "2. Testing Guardian/Vulnerabilities APIs"
echo "========================================="
test_json_endpoint "Guardian Health" \
    "http://localhost:8013/health" \
    "" \
    ".status"

test_json_endpoint "Vulnerabilities List" \
    "http://localhost:8013/api/v1/vulnerabilities/vulnerabilities/" \
    "X-API-Key: wbx-guardian-6fb6e69a0d7c62d6931e6bdfe7754263" \
    ".count"

test_json_endpoint "Vulnerabilities Stats" \
    "http://localhost:8013/api/v1/vulnerabilities/stats/" \
    "X-API-Key: wbx-guardian-6fb6e69a0d7c62d6931e6bdfe7754263" \
    ".total"

echo ""
echo "========================================="
echo "3. Testing Threat Intelligence APIs"
echo "========================================="
test_endpoint "Data Service Health" \
    "http://localhost:8002/health"

test_json_endpoint "Threat Feeds" \
    "http://localhost:8002/api/v1/feeds/" \
    "" \
    "length"

test_json_endpoint "Indicators Search" \
    "http://localhost:8002/api/v1/indicators/search/" \
    "" \
    ".results | length"

echo ""
echo "========================================="
echo "4. Testing Responder APIs"
echo "========================================="
test_endpoint "Responder Root" \
    "http://localhost:8018/"

test_json_endpoint "Playbooks List" \
    "http://localhost:8018/v1/playbooks" \
    "" \
    "length"

echo ""
echo "========================================="
echo "5. Testing Agents APIs"
echo "========================================="
test_json_endpoint "Agents Stats" \
    "http://localhost:8006/stats" \
    "" \
    ".total_analyses"

echo ""
echo "========================================="
echo "6. Testing Identity Service"
echo "========================================="
test_endpoint "Identity Health" \
    "http://localhost:8001/health"

echo ""
echo "========================================="
echo "7. Testing Gateway Routes"
echo "========================================="
test_endpoint "Gateway Health" \
    "http://localhost:80/health"

echo ""
echo "========================================="
echo "Summary"
echo "========================================="
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tests failed. Check output above for details.${NC}"
    exit 1
fi
