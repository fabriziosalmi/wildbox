#!/bin/bash

##############################################################################
# Wildbox API Documentation Generator
# Automatically generates static OpenAPI documentation by spinning up services
# and fetching their OpenAPI schemas
##############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCS_DIR="$PROJECT_ROOT/docs/api"
TEMP_DIR="/tmp/wildbox-api-docs-$$"

# Service configurations (name, port, container_name)
declare -a SERVICES=(
    "api:8000:open-security-tools"
    "identity:8001:open-security-identity"
    "data:8002:open-security-data"
    "guardian:8013:open-security-guardian"
    "responder:8018:open-security-responder"
    "agents:8006:open-security-agents"
)

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Wildbox API Documentation Generator${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to cleanup
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    cd "$PROJECT_ROOT"
    echo "Stopping docker-compose services..."
    docker-compose down --remove-orphans 2>/dev/null || true
    rm -rf "$TEMP_DIR"
    echo -e "${GREEN}Cleanup complete${NC}"
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Create temp directory
mkdir -p "$TEMP_DIR"

echo -e "${BLUE}Step 1: Starting Docker Compose services...${NC}"
cd "$PROJECT_ROOT"
docker-compose up -d

echo -e "${YELLOW}Waiting for services to be ready...${NC}"
sleep 10

# Wait for services to be healthy
echo -e "${YELLOW}Checking service health...${NC}"
max_retries=30
retry=0

for retry_attempt in $(seq 1 $max_retries); do
    ready=0
    for service_config in "${SERVICES[@]}"; do
        IFS=':' read -r service_name port container_name <<< "$service_config"

        if curl -s http://localhost:$port/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} $service_name (port $port) is ready"
            ((ready++))
        else
            echo -e "${RED}✗${NC} $service_name (port $port) not ready yet"
        fi
    done

    if [ $ready -eq ${#SERVICES[@]} ]; then
        echo -e "${GREEN}All services are ready!${NC}"
        break
    fi

    if [ $retry_attempt -lt $max_retries ]; then
        echo "Waiting 5 seconds before retry ($retry_attempt/$max_retries)..."
        sleep 5
    else
        echo -e "${RED}ERROR: Services did not start in time${NC}"
        exit 1
    fi
done

echo ""
echo -e "${BLUE}Step 2: Fetching OpenAPI schemas...${NC}"

for service_config in "${SERVICES[@]}"; do
    IFS=':' read -r service_name port container_name <<< "$service_config"

    echo -e "${YELLOW}Fetching OpenAPI schema for $service_name (port $port)...${NC}"

    # Try to fetch OpenAPI schema
    if curl -s http://localhost:$port/openapi.json -o "$TEMP_DIR/${service_name}-openapi.json"; then
        echo -e "${GREEN}✓${NC} Successfully fetched $service_name OpenAPI schema"
    elif curl -s http://localhost:$port/api/openapi.json -o "$TEMP_DIR/${service_name}-openapi.json"; then
        echo -e "${GREEN}✓${NC} Successfully fetched $service_name OpenAPI schema (from /api/openapi.json)"
    else
        echo -e "${RED}✗${NC} Failed to fetch $service_name OpenAPI schema"
    fi
done

echo ""
echo -e "${BLUE}Step 3: Generating static HTML documentation...${NC}"

# Create HTML documentation files for each service
for service_config in "${SERVICES[@]}"; do
    IFS=':' read -r service_name port container_name <<< "$service_config"

    schema_file="$TEMP_DIR/${service_name}-openapi.json"

    if [ -f "$schema_file" ]; then
        output_file="$DOCS_DIR/${service_name}-api.html"

        echo -e "${YELLOW}Generating HTML documentation for $service_name...${NC}"

        # Read the OpenAPI schema
        schema_content=$(cat "$schema_file")

        # Extract title and description from schema
        title=$(echo "$schema_content" | grep -o '"title":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "$service_name API")
        description=$(echo "$schema_content" | grep -o '"description":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "$service_name API Documentation")

        # Generate HTML using ReDoc
        cat > "$output_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$title - Wildbox API</title>
    <meta name="description" content="$description">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='75' font-size='75' fill='%23ef4444'>🛡️</text></svg>">
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', sans-serif;
            background: #0f0f0f;
            color: #e5e7eb;
        }
        redoc {
            display: block;
        }
        redoc::part(logo) {
            max-width: 300px;
        }
    </style>
</head>
<body>
    <redoc spec-url="data:application/json;base64,$(echo -n "$schema_content" | base64)"></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
</body>
</html>
EOF

        echo -e "${GREEN}✓${NC} Generated $output_file"
    else
        echo -e "${RED}✗${NC} Schema file not found for $service_name"
    fi
done

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}API Documentation generation complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Generated files:"
for service_config in "${SERVICES[@]}"; do
    IFS=':' read -r service_name port container_name <<< "$service_config"
    if [ -f "$DOCS_DIR/${service_name}-api.html" ]; then
        echo -e "  ${GREEN}✓${NC} $DOCS_DIR/${service_name}-api.html"
    fi
done

echo ""
echo -e "${BLUE}Documentation is ready at: $DOCS_DIR${NC}"
