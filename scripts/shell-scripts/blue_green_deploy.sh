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

# Validate SERVICE name (alphanumeric, hyphens, underscores only)
if ! [[ "$SERVICE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "ERROR: Invalid service name: $SERVICE (only alphanumeric, hyphens, underscores allowed)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The port each service listens on inside its container, and its health route.
case "$SERVICE" in
  guardian) APP_PORT=8013; HEALTH_PATH=/health/ ;;
  *) APP_PORT=8001; HEALTH_PATH=/health ;;
esac

echo "🚀 Blue/Green Deployment: $SERVICE v$VERSION"
echo "============================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Step 1: Deploy to green environment
echo -e "${BLUE}Step 1: Deploying to green environment...${NC}"
# --scale: the green services are at 0 replicas in the compose file, and a
# bare `up` of a service at 0 replicas starts nothing.
docker-compose -f docker-compose.blue-green.yml up -d --scale ${SERVICE}-green=1 ${SERVICE}-green

# Wait for container to start
sleep 10

# Step 2: Health check green environment
echo -e "${BLUE}Step 2: Running health checks on green...${NC}"
GREEN_PORT=$(docker-compose -f docker-compose.blue-green.yml port ${SERVICE}-green $APP_PORT | cut -d: -f2)

for i in {1..30}; do
    if curl -sf "http://localhost:$GREEN_PORT$HEALTH_PATH" > /dev/null; then
        echo -e "${GREEN}✓ Green environment healthy${NC}"
        break
    fi
    echo "Waiting for green environment... ($i/30)"
    sleep 2
done

# Verify health
if ! curl -sf "http://localhost:$GREEN_PORT$HEALTH_PATH" > /dev/null; then
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

# guardian's worker and its single beat follow the traffic (#550).
if [ "$SERVICE" = "guardian" ]; then
    echo -e "${BLUE}Step 4b: Moving guardian's background tasks to green...${NC}"
    "$SCRIPT_DIR/blue_green_guardian_tasks.sh" green
fi

# Step 5: Monitor for errors
echo -e "${BLUE}Step 5: Monitoring for errors (60s)...${NC}"
sleep 60

# Check error rate
ERROR_COUNT=$(docker-compose -f docker-compose.blue-green.yml logs ${SERVICE}-green --since 1m | grep -c ERROR || true)
if [ "$ERROR_COUNT" -gt 10 ]; then
    echo -e "${RED}✗ High error rate detected ($ERROR_COUNT errors) - rolling back${NC}"
    "$SCRIPT_DIR/blue_green_rollback.sh" $SERVICE
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
