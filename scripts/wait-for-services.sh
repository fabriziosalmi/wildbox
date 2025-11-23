#!/bin/bash
#
# Wildbox Service Health Checker
# Waits for all critical services to be healthy before proceeding
#
# Usage:
#   ./scripts/wait-for-services.sh
#
# Exit codes:
#   0 - All services healthy
#   1 - One or more services failed to become healthy
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MAX_WAIT=180  # Maximum wait time in seconds (3 minutes)
POLL_INTERVAL=5  # Check every 5 seconds
VERBOSE=${VERBOSE:-false}

# Service definitions: name:host:port:path
SERVICES=(
  "gateway:localhost:80:/health"
  "identity:localhost:8001:/health"
  "api:localhost:8000:/health"
  "data:localhost:8002:/health"
)

# Optional services (warn but don't fail)
OPTIONAL_SERVICES=(
  "guardian:localhost:8003:/health"
  "responder:localhost:8018:/health"
  "agents:localhost:8006:/health"
  "cspm:localhost:8019:/health"
)

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}🔍 Wildbox Service Health Checker${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "⏱️  Maximum wait: ${MAX_WAIT}s (polling every ${POLL_INTERVAL}s)"
echo -e "📋 Checking ${#SERVICES[@]} critical services"
echo ""

check_service() {
  local name=$1
  local host=$2
  local port=$3
  local path=$4
  
  local url="http://${host}:${port}${path}"
  
  if [ "$VERBOSE" = "true" ]; then
    echo -e "${BLUE}   Checking: ${url}${NC}"
  fi
  
  # Use curl with timeout and suppress output
  if curl -f -s -o /dev/null --max-time 3 "$url" 2>/dev/null; then
    return 0
  else
    return 1
  fi
}

wait_for_service() {
  local name=$1
  local host=$2
  local port=$3
  local path=$4
  local is_optional=${5:-false}
  
  local attempts=$((MAX_WAIT / POLL_INTERVAL))
  local attempt=1
  
  while [ $attempt -le $attempts ]; do
    if check_service "$name" "$host" "$port" "$path"; then
      echo -e "${GREEN}✅ $name${NC} is healthy (attempt $attempt/$attempts)"
      return 0
    fi
    
    if [ "$VERBOSE" = "true" ] || [ $((attempt % 3)) -eq 0 ]; then
      echo -e "${YELLOW}⏳ Waiting for $name...${NC} (attempt $attempt/$attempts)"
    fi
    
    sleep $POLL_INTERVAL
    ((attempt++))
  done
  
  if [ "$is_optional" = "true" ]; then
    echo -e "${YELLOW}⚠️  $name${NC} did not become healthy (optional - continuing)"
    return 0
  else
    echo -e "${RED}❌ $name${NC} failed to become healthy after ${MAX_WAIT}s"
    return 1
  fi
}

# Track failures
FAILED_SERVICES=()

# Check critical services
echo -e "${BLUE}🔐 Checking critical services:${NC}"
echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"

for service_def in "${SERVICES[@]}"; do
  IFS=':' read -r name host port path <<< "$service_def"
  
  if ! wait_for_service "$name" "$host" "$port" "$path" false; then
    FAILED_SERVICES+=("$name")
  fi
done

# Check optional services
if [ ${#OPTIONAL_SERVICES[@]} -gt 0 ]; then
  echo ""
  echo -e "${BLUE}📦 Checking optional services:${NC}"
  echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
  
  for service_def in "${OPTIONAL_SERVICES[@]}"; do
    IFS=':' read -r name host port path <<< "$service_def"
    wait_for_service "$name" "$host" "$port" "$path" true
  done
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

# Report results
if [ ${#FAILED_SERVICES[@]} -eq 0 ]; then
  echo -e "${GREEN}🎉 All critical services are healthy and ready!${NC}"
  echo ""
  echo -e "${GREEN}✅ Gateway:  http://localhost${NC}"
  echo -e "${GREEN}✅ Identity: http://localhost:8001${NC}"
  echo -e "${GREEN}✅ API:      http://localhost:8000${NC}"
  echo -e "${GREEN}✅ Data:     http://localhost:8002${NC}"
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
  exit 0
else
  echo -e "${RED}🔥 Service health check failed!${NC}"
  echo -e "${RED}   ${#FAILED_SERVICES[@]} service(s) did not become healthy:${NC}"
  for service in "${FAILED_SERVICES[@]}"; do
    echo -e "${RED}   • $service${NC}"
  done
  echo ""
  echo -e "${YELLOW}📋 Troubleshooting steps:${NC}"
  echo -e "   1. Check if containers are running:"
  echo -e "      ${BLUE}docker-compose ps${NC}"
  echo ""
  echo -e "   2. View logs for failed services:"
  for service in "${FAILED_SERVICES[@]}"; do
    echo -e "      ${BLUE}docker-compose logs --tail=50 $service${NC}"
  done
  echo ""
  echo -e "   3. Verify network connectivity:"
  echo -e "      ${BLUE}docker-compose exec gateway ping -c 2 identity${NC}"
  echo ""
  echo -e "   4. Restart failed services:"
  for service in "${FAILED_SERVICES[@]}"; do
    echo -e "      ${BLUE}docker-compose restart $service${NC}"
  done
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
  exit 1
fi
