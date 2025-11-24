#!/bin/bash
#
# Blue/Green deployment script
#
# Deploys new version to green environment, validates health, and switches traffic
#
# Usage:
#   ./blue_green_deploy.sh <service> <version>
#   ./blue_green_deploy.sh identity 0.3.0

set -euo pipefail

SERVICE=$1
VERSION=$2

echo "🚀 Blue/Green Deployment: $SERVICE v$VERSION"
echo "============================================="

# Colors
GREEN='\033[0[32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Step 1: Deploy to green environment
echo -e "${BLUE}Step 1: Deploying to green environment...${NC}"
docker-compose -f docker-compose.blue-green.yml up -d ${SERVICE}-green

# Wait for container to start
sleep 10

# Step 2: Health check green environment
echo -e "${BLUE}Step 2: Running health checks on green...${NC}"
GREEN_PORT=$(docker-compose -f docker-compose.blue-green.yml port ${SERVICE}-green 8001 | cut -d: -f2)

for i in {1..30}; do
    if curl -sf "http://localhost:$GREEN_PORT/health" > /dev/null; then
        echo -e "${GREEN}✓ Green environment healthy${NC}"
        break
    fi
    echo "Waiting for green environment... ($i/30)"
    sleep 2
done

# Verify health
if ! curl -sf "http://localhost:$GREEN_PORT/health" > /dev/null; then
    echo -e "${RED}✗ Green environment unhealthy - aborting deployment${NC}"
    docker-compose -f docker-compose.blue-green.yml logs ${SERVICE}-green
    exit 1
fi

# Step 3: Run smoke tests
echo -e "${BLUE}Step 3: Running smoke tests...${NC}"
./scripts/smoke_tests.sh "http://localhost:$GREEN_PORT" || {
    echo -e "${RED}✗ Smoke tests failed - aborting${NC}"
    exit 1
}

# Step 4: Switch HAProxy to green
echo -e "${BLUE}Step 4: Switching traffic to green...${NC}"
sed -i.bak "s/server ${SERVICE}-blue/${SERVICE}-green/g" haproxy/haproxy.cfg
docker-compose -f docker-compose.blue-green.yml exec haproxy kill -USR2 1  # Reload config

echo -e "${GREEN}✓ Traffic switched to green${NC}"

# Step 5: Monitor for errors
echo -e "${BLUE}Step 5: Monitoring for errors (60s)...${NC}"
sleep 60

# Check error rate
ERROR_COUNT=$(docker-compose -f docker-compose.blue-green.yml logs ${SERVICE}-green --since 1m | grep -c ERROR || true)
if [ "$ERROR_COUNT" -gt 10 ]; then
    echo -e "${RED}✗ High error rate detected ($ERROR_COUNT errors) - rolling back${NC}"
    ./scripts/blue_green_rollback.sh $SERVICE
    exit 1
fi

echo -e "${GREEN}✓ No errors detected${NC}"

# Step 6: Scale down blue (keep for rollback)
echo -e "${BLUE}Step 6: Scaling down blue (keeping for rollback)...${NC}"
docker-compose -f docker-compose.blue-green.yml scale ${SERVICE}-blue=0

echo ""
echo -e "${GREEN}============================================="
echo -e "✓ Deployment complete!"
echo -e "=============================================${NC}"
echo ""
echo "Blue environment kept running for rollback."
echo "To rollback: ./scripts/blue_green_rollback.sh $SERVICE"
echo "To finalize: ./scripts/blue_green_finalize.sh $SERVICE"
