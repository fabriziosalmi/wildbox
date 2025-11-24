#!/bin/bash
#
# Blue/Green health monitoring script
#
# Checks health of both blue and green environments
#
# Usage:
#   ./blue_green_health.sh

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🏥 Blue/Green Health Check"
echo "=========================="
echo ""

# Check all services
SERVICES=("identity" "guardian" "data" "tools" "agents")

for SERVICE in "${SERVICES[@]}"; do
    echo -e "${BLUE}Checking $SERVICE:${NC}"
    
    # Blue environment
    BLUE_STATUS="❌ DOWN"
    BLUE_VERSION="unknown"
    if docker ps --format '{{.Names}}' | grep -q "wildbox-${SERVICE}-blue"; then
        BLUE_PORT=$(docker-compose -f docker-compose.blue-green.yml port ${SERVICE}-blue 8001 2>/dev/null | cut -d: -f2 || echo "")
        if [ -n "$BLUE_PORT" ]; then
            if curl -sf "http://localhost:$BLUE_PORT/health" > /dev/null 2>&1; then
                BLUE_STATUS="${GREEN}✓ HEALTHY${NC}"
                BLUE_VERSION=$(curl -sf "http://localhost:$BLUE_PORT/version" | jq -r '.version' 2>/dev/null || echo "unknown")
            else
                BLUE_STATUS="${RED}✗ UNHEALTHY${NC}"
            fi
        fi
    fi
    
    # Green environment
    GREEN_STATUS="❌ DOWN"
    GREEN_VERSION="unknown"
    if docker ps --format '{{.Names}}' | grep -q "wildbox-${SERVICE}-green"; then
        GREEN_PORT=$(docker-compose -f docker-compose.blue-green.yml port ${SERVICE}-green 8001 2>/dev/null | cut -d: -f2 || echo "")
        if [ -n "$GREEN_PORT" ]; then
            if curl -sf "http://localhost:$GREEN_PORT/health" > /dev/null 2>&1; then
                GREEN_STATUS="${GREEN}✓ HEALTHY${NC}"
                GREEN_VERSION=$(curl -sf "http://localhost:$GREEN_PORT/version" | jq -r '.version' 2>/dev/null || echo "unknown")
            else
                GREEN_STATUS="${RED}✗ UNHEALTHY${NC}"
            fi
        fi
    fi
    
    echo -e "  Blue:  $BLUE_STATUS (v$BLUE_VERSION)"
    echo -e "  Green: $GREEN_STATUS (v$GREEN_VERSION)"
    echo ""
done

# Check HAProxy stats
echo -e "${BLUE}HAProxy Status:${NC}"
if docker ps --format '{{.Names}}' | grep -q "wildbox-haproxy"; then
    echo -e "  ${GREEN}✓ RUNNING${NC}"
    echo -e "  Stats UI: http://localhost:8404/stats"
else
    echo -e "  ${RED}✗ NOT RUNNING${NC}"
fi
echo ""

# Check active environment
echo -e "${BLUE}Active Environment:${NC}"
ACTIVE_ENV=$(grep -o "server.*-blue\|server.*-green" haproxy/haproxy.cfg | head -1 | sed 's/server.*-//' || echo "unknown")
if [ "$ACTIVE_ENV" = "blue" ]; then
    echo -e "  ${BLUE}BLUE (production)${NC}"
elif [ "$ACTIVE_ENV" = "green" ]; then
    echo -e "  ${GREEN}GREEN (new version)${NC}"
else
    echo -e "  ${YELLOW}UNKNOWN${NC}"
fi
