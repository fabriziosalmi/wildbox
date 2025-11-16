#!/bin/bash
# Rate Limiting Monitoring Script
# Sprint 1: Monitor API gateway rate limiting effectiveness

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=============================================="
echo "Wildbox Rate Limiting Statistics"
echo "=============================================="
echo ""

# Check if gateway is running
if ! docker-compose ps gateway | grep -q "Up"; then
    echo -e "${RED}ERROR: Gateway is not running${NC}"
    exit 1
fi

# Time window (default: last hour)
TIME_WINDOW="${1:-1h}"

echo -e "${GREEN}Analyzing last ${TIME_WINDOW}...${NC}"
echo ""

# Count 429 responses
echo "=== Rate Limited Requests ==="
RATE_LIMITED_COUNT=$(docker-compose logs gateway --since "$TIME_WINDOW" 2>/dev/null | grep -c " 429 " || echo "0")
echo -e "Total rate limited requests: ${YELLOW}${RATE_LIMITED_COUNT}${NC}"
echo ""

# Top IPs being rate limited
if [ "$RATE_LIMITED_COUNT" -gt 0 ]; then
    echo "=== Top 10 Rate Limited IPs ==="
    docker-compose logs gateway --since "$TIME_WINDOW" 2>/dev/null | \
      grep " 429 " | \
      awk '{print $1}' | \
      sort | uniq -c | sort -rn | head -10 | \
      while read count ip; do
        echo -e "  ${ip}: ${RED}${count} requests${NC}"
      done
    echo ""
    
    # Rate limited by endpoint
    echo "=== Rate Limited by Endpoint ==="
    docker-compose logs gateway --since "$TIME_WINDOW" 2>/dev/null | \
      grep " 429 " | \
      awk '{print $7}' | \
      sort | uniq -c | sort -rn | head -10 | \
      while read count endpoint; do
        echo -e "  ${endpoint}: ${RED}${count} requests${NC}"
      done
    echo ""
else
    echo -e "${GREEN}No rate limiting triggered in the last ${TIME_WINDOW}${NC}"
    echo ""
fi

# Overall request statistics
echo "=== Overall Gateway Statistics ==="
TOTAL_REQUESTS=$(docker-compose logs gateway --since "$TIME_WINDOW" 2>/dev/null | grep -c "HTTP/1\." || echo "0")
echo -e "Total requests: ${YELLOW}${TOTAL_REQUESTS}${NC}"

if [ "$TOTAL_REQUESTS" -gt 0 ]; then
    RATE_LIMITED_PERCENTAGE=$(awk "BEGIN {printf \"%.2f\", ($RATE_LIMITED_COUNT / $TOTAL_REQUESTS) * 100}")
    echo -e "Rate limited percentage: ${YELLOW}${RATE_LIMITED_PERCENTAGE}%${NC}"
fi
echo ""

# Status code distribution
echo "=== HTTP Status Code Distribution ==="
docker-compose logs gateway --since "$TIME_WINDOW" 2>/dev/null | \
  grep -oP 'HTTP/1\.[01]" \K[0-9]{3}' | \
  sort | uniq -c | sort -rn | head -10 | \
  while read count status; do
    case $status in
      2*) color=$GREEN ;;
      4*) color=$YELLOW ;;
      5*) color=$RED ;;
      *) color=$NC ;;
    esac
    echo -e "  ${status}: ${color}${count} requests${NC}"
  done
echo ""

# Average response time (if available in logs)
echo "=== Performance Metrics ==="
AVG_TIME=$(docker-compose logs gateway --since "$TIME_WINDOW" 2>/dev/null | \
  grep -oP 'rt=\K[0-9.]+' | \
  awk '{sum+=$1; count++} END {if(count>0) printf "%.3f", sum/count; else print "N/A"}')
echo -e "Average response time: ${YELLOW}${AVG_TIME}s${NC}"
echo ""

echo "=============================================="
echo "Monitoring complete"
echo "=============================================="
