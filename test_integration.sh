#!/bin/bash

# Wildbox Integration Test Script
# Tests connectivity between dashboard and backend services

echo "🚀 Starting Wildbox Integration Tests..."
echo "==============================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test endpoints
API_BASE=${API_BASE:-"http://localhost:8000"}
DATA_BASE=${DATA_BASE:-"http://localhost:8002"}
DASHBOARD_BASE=${DASHBOARD_BASE:-"http://localhost:3000"}

# Function to test endpoint
test_endpoint() {
    local url=$1
    local description=$2
    local expected_status=${3:-200}
    
    echo -n "Testing $description... "
    
    response=$(curl -s -w "%{http_code}" -o /dev/null "$url" --max-time 10)
    
    if [ "$response" -eq "$expected_status" ]; then
        echo -e "${GREEN}✅ PASS${NC} (HTTP $response)"
        return 0
    else
        echo -e "${RED}❌ FAIL${NC} (HTTP $response, expected $expected_status)"
        return 1
    fi
}

# Function to test API with JSON response
test_api_json() {
    local url=$1
    local description=$2
    local json_key=$3
    
    echo -n "Testing $description... "
    
    response=$(curl -s "$url" --max-time 10)
    status=$?
    
    if [ $status -ne 0 ]; then
        echo -e "${RED}❌ FAIL${NC} (Connection failed)"
        return 1
    fi
    
    if echo "$response" | jq -e ".$json_key" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC} (JSON key '$json_key' found)"
        return 0
    else
        echo -e "${YELLOW}⚠️  PARTIAL${NC} (Connected but missing expected JSON key '$json_key')"
        echo "    Response: $(echo "$response" | head -c 100)..."
        return 1
    fi
}

echo -e "${BLUE}1. Testing Core API Health Endpoints${NC}"
echo "-------------------------------------------"

# Test basic health endpoints
test_endpoint "$API_BASE/health" "API Health Check"
test_endpoint "$DATA_BASE/health" "Data Service Health Check"

echo ""
echo -e "${BLUE}2. Testing New Integration Endpoints${NC}"
echo "-------------------------------------------"

# Test new system health aggregation endpoint
test_api_json "$API_BASE/api/system/health-aggregate" "System Health Aggregation" "status"

# Test new threat intel dashboard endpoint
test_api_json "$DATA_BASE/api/v1/dashboard/threat-intel" "Threat Intel Dashboard Metrics" "active_feeds"

# Test existing system metrics
test_api_json "$API_BASE/api/system/metrics" "System Metrics" "uptime"

# Test existing data stats
test_api_json "$DATA_BASE/api/v1/stats" "Data Statistics" "total_indicators"

echo ""
echo -e "${BLUE}3. Testing CORS Configuration${NC}"
echo "-------------------------------------------"

# Test preflight OPTIONS request
echo -n "Testing CORS preflight (OPTIONS)... "
cors_response=$(curl -s -X OPTIONS -H "Origin: http://localhost:3000" -H "Access-Control-Request-Method: GET" -w "%{http_code}" -o /dev/null "$API_BASE/api/system/metrics" --max-time 10)

if [ "$cors_response" -eq 204 ] || [ "$cors_response" -eq 200 ]; then
    echo -e "${GREEN}✅ PASS${NC} (HTTP $cors_response)"
else
    echo -e "${YELLOW}⚠️  NEEDS CONFIG${NC} (HTTP $cors_response)"
    echo "    Note: CORS might need configuration in the API services"
fi

echo ""
echo -e "${BLUE}4. Testing Dashboard API Integration${NC}"
echo "-------------------------------------------"

# Check if dashboard can reach APIs (if dashboard is running)
if curl -s "$DASHBOARD_BASE" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Dashboard is running${NC}"
    
    # Test dashboard health
    test_endpoint "$DASHBOARD_BASE" "Dashboard Health"
    
    # Note: We can't easily test the actual API calls from here since they require authentication
    echo -e "${BLUE}ℹ️  Dashboard-to-API calls require authentication and are tested via browser${NC}"
else
    echo -e "${YELLOW}⚠️  Dashboard not running - start with: npm run dev${NC}"
fi

echo ""
echo -e "${BLUE}5. Testing Docker Network Connectivity${NC}"
echo "-------------------------------------------"

# Check if we're in Docker environment
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo -e "${GREEN}✅ Running in Docker environment${NC}"
    
    # Test internal service names
    test_endpoint "http://open-security-api:8000/health" "API via Docker network"
    test_endpoint "http://open-security-data:8002/health" "Data Service via Docker network"
else
    echo -e "${BLUE}ℹ️  Running outside Docker - using localhost endpoints${NC}"
fi

echo ""
echo -e "${BLUE}📋 Integration Test Summary${NC}"
echo "==============================================="

# Quick curl commands for manual testing
echo "Manual test commands:"
echo ""
echo -e "${YELLOW}# Test System Health Aggregation:${NC}"
echo "curl -s '$API_BASE/api/system/health-aggregate' | jq"
echo ""
echo -e "${YELLOW}# Test Threat Intel Metrics:${NC}"
echo "curl -s '$DATA_BASE/api/v1/dashboard/threat-intel' | jq"
echo ""
echo -e "${YELLOW}# Test CORS with browser dev tools:${NC}"
echo "fetch('$API_BASE/api/system/metrics')"
echo "  .then(r => r.json())"
echo "  .then(console.log)"
echo ""

echo -e "${GREEN}Integration tests completed!${NC}"
echo ""
echo "Next steps:"
echo "1. Start all services: docker-compose up -d"
echo "2. Start dashboard: cd open-security-dashboard && npm run dev"
echo "3. Open browser: http://localhost:3000"
echo "4. Check Network tab for API calls"
