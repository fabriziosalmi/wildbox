#!/bin/bash
# Task 2.3 - Verifica Sistematica Endpoint
# Script per verificare tutti gli endpoint critici del sistema

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL=0
PASSED=0
FAILED=0

# Function to test endpoint
test_endpoint() {
    local name=$1
    local url=$2
    local expected_status=${3:-200}
    local headers=$4
    local description=$5
    
    TOTAL=$((TOTAL + 1))
    echo -e "\n${BLUE}[$TOTAL] Testing: $name${NC}"
    echo "    URL: $url"
    [ ! -z "$description" ] && echo "    Description: $description"
    
    local cmd="curl -s -o /dev/null -w '%{http_code}' --max-time 10"
    [ ! -z "$headers" ] && cmd="$cmd $headers"
    cmd="$cmd '$url'"
    
    local status=$(eval $cmd)
    
    if [ "$status" = "$expected_status" ]; then
        echo -e "    ${GREEN}✅ PASS${NC} (HTTP $status)"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "    ${RED}❌ FAIL${NC} (HTTP $status, expected $expected_status)"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Function to test JSON endpoint
test_json_endpoint() {
    local name=$1
    local url=$2
    local headers=$3
    local description=$4
    
    TOTAL=$((TOTAL + 1))
    echo -e "\n${BLUE}[$TOTAL] Testing: $name${NC}"
    echo "    URL: $url"
    [ ! -z "$description" ] && echo "    Description: $description"
    
    local cmd="curl -s --max-time 10"
    [ ! -z "$headers" ] && cmd="$cmd $headers"
    cmd="$cmd '$url'"
    
    local response=$(eval $cmd)
    
    if echo "$response" | jq . >/dev/null 2>&1; then
        echo -e "    ${GREEN}✅ PASS${NC} (Valid JSON response)"
        echo "    Sample: $(echo "$response" | jq -c . | head -c 100)..."
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "    ${RED}❌ FAIL${NC} (Invalid JSON or no response)"
        echo "    Response: ${response:0:100}..."
        FAILED=$((FAILED + 1))
        return 1
    fi
}

echo "======================================================================"
echo "  Task 2.3 - Verifica Sistematica Endpoint"
echo "======================================================================"
echo ""
echo "Inizio verifica endpoint critici..."

# ======================================================================
# SECTION 1: HEALTH CHECKS
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SECTION 1: Health Checks${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

test_json_endpoint "Gateway Health" \
    "http://localhost/health" \
    "" \
    "API Gateway health status"

test_json_endpoint "Identity Service Health" \
    "http://localhost:8001/health" \
    "" \
    "Authentication service health"

test_json_endpoint "Tools API Health" \
    "http://localhost:8000/health" \
    "" \
    "Security tools service health"

test_json_endpoint "Data Service Health" \
    "http://localhost:8002/health" \
    "" \
    "Threat intelligence service health"

test_json_endpoint "Guardian Health" \
    "http://localhost:8013/health/" \
    "" \
    "Vulnerability management health"

test_json_endpoint "Responder Health" \
    "http://localhost:8018/health" \
    "" \
    "Incident response service health"

test_json_endpoint "Agents Health" \
    "http://localhost:8006/health" \
    "" \
    "AI agents service health"

# ======================================================================
# SECTION 2: AUTHENTICATION ENDPOINTS
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SECTION 2: Authentication Endpoints${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

test_endpoint "Identity Login Endpoint" \
    "http://localhost:8001/api/v1/auth/login" \
    "422" \
    "" \
    "Login endpoint (422 = validation error, means it's working)"

test_endpoint "Identity Register Endpoint" \
    "http://localhost:8001/api/v1/auth/register" \
    "422" \
    "" \
    "Registration endpoint"

# ======================================================================
# SECTION 3: THREAT INTELLIGENCE
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SECTION 3: Threat Intelligence${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

test_json_endpoint "Threat Intel Dashboard Stats" \
    "http://localhost:8002/api/v1/dashboard/threat-intel" \
    "" \
    "Dashboard statistics"

test_json_endpoint "Threat Sources List" \
    "http://localhost:8002/api/v1/sources" \
    "" \
    "Active threat intelligence sources"

test_json_endpoint "IOC Search Endpoint" \
    "http://localhost:8002/api/v1/indicators/search?q=test&limit=1" \
    "" \
    "Indicator of Compromise search"

# ======================================================================
# SECTION 4: SECURITY TOOLS
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SECTION 4: Security Tools${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

test_json_endpoint "Tools List" \
    "http://localhost:8000/api/v1/tools/tools" \
    "-H 'X-API-Key: wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90'" \
    "List of available security tools"

test_json_endpoint "Tools Categories" \
    "http://localhost:8000/api/v1/tools/categories" \
    "-H 'X-API-Key: wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90'" \
    "Tool categories"

# ======================================================================
# SECTION 5: VULNERABILITY MANAGEMENT (Guardian)
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SECTION 5: Vulnerability Management${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

test_json_endpoint "Vulnerabilities Stats" \
    "http://localhost:8013/api/v1/vulnerabilities/vulnerabilities/stats/" \
    "-H 'X-API-Key: wbx-guardian-6fb6e69a0d7c62d6931e6bdfe7754263'" \
    "Vulnerability statistics"

test_json_endpoint "Vulnerabilities List" \
    "http://localhost:8013/api/v1/vulnerabilities/vulnerabilities/" \
    "-H 'X-API-Key: wbx-guardian-6fb6e69a0d7c62d6931e6bdfe7754263'" \
    "List of vulnerabilities"

# ======================================================================
# SECTION 6: INCIDENT RESPONSE (Responder)
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SECTION 6: Incident Response${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

test_json_endpoint "Playbooks List" \
    "http://localhost:8018/api/v1/playbooks" \
    "" \
    "Available response playbooks"

test_json_endpoint "Playbook Runs History" \
    "http://localhost:8018/api/v1/runs" \
    "" \
    "Playbook execution history"

test_json_endpoint "Responder Metrics" \
    "http://localhost:8018/api/v1/metrics" \
    "" \
    "Service metrics and statistics"

# ======================================================================
# SECTION 7: AI AGENTS
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SECTION 7: AI Agents${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

test_json_endpoint "Agents Info" \
    "http://localhost:8006/" \
    "" \
    "AI agents service information"

test_json_endpoint "Agents Stats" \
    "http://localhost:8006/api/v1/stats" \
    "" \
    "AI analysis statistics"

# ======================================================================
# SECTION 8: DASHBOARD (Frontend)
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SECTION 8: Dashboard (Frontend)${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"

test_endpoint "Dashboard Homepage" \
    "http://localhost:3000" \
    "200" \
    "" \
    "Next.js frontend homepage"

test_endpoint "Dashboard Login Page" \
    "http://localhost:3000/auth/login" \
    "200" \
    "" \
    "Authentication page"

# ======================================================================
# SUMMARY
# ======================================================================
echo -e "\n${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SUMMARY${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Total Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED!${NC}"
    echo ""
    echo "Il sistema è completamente funzionante e pronto per l'uso."
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    echo ""
    echo "Rivedere i test falliti sopra per identificare i problemi."
    exit 1
fi
