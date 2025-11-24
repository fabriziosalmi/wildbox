#!/bin/bash
#
# Blue/Green rollback script
#
# Instantly switches traffic back to blue environment
#
# Usage:
#   ./blue_green_rollback.sh <service>
#   ./blue_green_rollback.sh identity

set -euo pipefail

SERVICE=$1

RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}🔄 Rolling back $SERVICE to blue environment${NC}"
echo "============================================="

# Step 1: Ensure blue is running
echo -e "${BLUE}Step 1: Starting blue environment...${NC}"
docker-compose -f docker-compose.blue-green.yml up -d ${SERVICE}-blue
docker-compose -f docker-compose.blue-green.yml scale ${SERVICE}-blue=1

sleep 10

# Step 2: Verify blue health
echo -e "${BLUE}Step 2: Verifying blue health...${NC}"
BLUE_PORT=$(docker-compose -f docker-compose.blue-green.yml port ${SERVICE}-blue 8001 | cut -d: -f2)

for i in {1..30}; do
    if curl -sf "http://localhost:$BLUE_PORT/health" > /dev/null; then
        echo -e "${GREEN}✓ Blue environment healthy${NC}"
        break
    fi
    echo "Waiting for blue environment... ($i/30)"
    sleep 2
done

# Step 3: Switch HAProxy back to blue
echo -e "${BLUE}Step 3: Switching traffic to blue...${NC}"
sed -i.bak "s/server ${SERVICE}-green/${SERVICE}-blue/g" haproxy/haproxy.cfg
docker-compose -f docker-compose.blue-green.yml exec haproxy kill -USR2 1

# Step 4: Stop green
echo -e "${BLUE}Step 4: Stopping green environment...${NC}"
docker-compose -f docker-compose.blue-green.yml stop ${SERVICE}-green

echo ""
echo -e "${GREEN}============================================="
echo -e "✓ Rollback complete!"
echo -e "=============================================${NC}"
echo ""
echo "Traffic restored to blue environment."
echo "Green environment stopped."
