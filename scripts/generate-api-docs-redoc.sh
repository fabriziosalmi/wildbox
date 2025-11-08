#!/bin/bash

##############################################################################
# Wildbox API Documentation Generator with ReDoc and Redocly
# Generates styled HTML documentation from live OpenAPI endpoints
##############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCS_DIR="$PROJECT_ROOT/docs/api"
TEMP_DIR="/tmp/wildbox-openapi-$$"

# Services (name, port)
declare -a SERVICES=(
    "api:8000"
    "identity:8001"
    "data:8002"
    "guardian:8013"
    "responder:8018"
    "agents:8006"
)

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Wildbox API Documentation Generator  ║${NC}"
echo -e "${BLUE}║  Using ReDoc & Redocly                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}\n"

# Check if Docker is running
echo -e "${YELLOW}Checking Docker...${NC}"
if ! docker ps > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Docker is not running${NC}"
    echo "Please start Docker Desktop and try again"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker is running\n"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    cd "$PROJECT_ROOT"
    docker-compose down --remove-orphans 2>/dev/null || true
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

# Create temp directory
mkdir -p "$TEMP_DIR"

# Step 1: Start services
echo -e "${BLUE}Step 1: Starting Docker Compose services${NC}"
cd "$PROJECT_ROOT"
docker-compose up -d

# Step 2: Wait for services
echo -e "${BLUE}Step 2: Waiting for services to be ready...${NC}"
sleep 15

max_retries=30
for retry in $(seq 1 $max_retries); do
    ready_count=0
    for service_port in "${SERVICES[@]}"; do
        IFS=':' read -r service port <<< "$service_port"

        if curl -s http://localhost:$port/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} $service (port $port) is ready"
            ((ready_count++))
        else
            echo -e "${RED}✗${NC} $service (port $port) not ready yet"
        fi
    done

    if [ $ready_count -eq ${#SERVICES[@]} ]; then
        echo -e "\n${GREEN}All services are ready!${NC}\n"
        break
    fi

    if [ $retry -lt $max_retries ]; then
        echo "Retrying in 5 seconds... ($retry/$max_retries)"
        sleep 5
    else
        echo -e "${RED}ERROR: Services did not start in time${NC}"
        exit 1
    fi
done

# Step 3: Download OpenAPI schemas
echo -e "${BLUE}Step 3: Downloading OpenAPI schemas${NC}"
for service_port in "${SERVICES[@]}"; do
    IFS=':' read -r service port <<< "$service_port"

    echo -e "${YELLOW}Downloading $service OpenAPI schema...${NC}"

    if curl -s http://localhost:$port/openapi.json -o "$TEMP_DIR/${service}-openapi.json"; then
        echo -e "${GREEN}✓${NC} Downloaded $service"
    else
        echo -e "${RED}✗${NC} Failed to download $service"
    fi
done

# Step 4: Generate HTML with Redocly
echo -e "\n${BLUE}Step 4: Generating HTML documentation with Redocly${NC}"
mkdir -p "$DOCS_DIR"

for service_port in "${SERVICES[@]}"; do
    IFS=':' read -r service port <<< "$service_port"

    schema_file="$TEMP_DIR/${service}-openapi.json"
    if [ -f "$schema_file" ]; then
        output_file="$DOCS_DIR/${service}-api.html"

        echo -e "${YELLOW}Generating ${service}-api.html...${NC}"

        # Use redocly to build HTML
        redocly build-docs "$schema_file" -o "$output_file" --title "$service API" 2>/dev/null || {
            # Fallback: Use standalone Redoc
            echo -e "${YELLOW}Using ReDoc standalone...${NC}"
            cat > "$output_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>$service API - Wildbox</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body {
            margin: 0;
            padding: 0;
            background: #0f0f0f;
            color: #e5e7eb;
            font-family: 'Roboto', sans-serif;
        }
    </style>
</head>
<body>
    <redoc spec-url='data:application/json;base64,$(base64 < "$schema_file")'></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
</body>
</html>
EOF
        }

        echo -e "${GREEN}✓${NC} Generated $output_file"
    else
        echo -e "${RED}✗${NC} Schema file not found for $service"
    fi
done

# Step 5: Create styled index
echo -e "\n${BLUE}Step 5: Creating styled index page${NC}"

cat > "$DOCS_DIR/swagger-index.html" << 'INDEXEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wildbox API Documentation</title>
    <meta name="description" content="Complete API documentation for Wildbox Security Platform">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='75' font-size='75'>🛡️</text></svg>">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
            color: #e5e7eb;
            line-height: 1.6;
            min-height: 100vh;
            padding: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            margin-bottom: 4rem;
            padding-bottom: 2rem;
            border-bottom: 2px solid rgba(239, 68, 68, 0.2);
        }

        h1 {
            font-size: 3rem;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
        }

        .subtitle {
            color: #9ca3af;
            font-size: 1.2rem;
            margin-bottom: 1rem;
        }

        .timestamp {
            color: #6b7280;
            font-size: 0.9rem;
            margin-top: 1rem;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }

        .card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 12px;
            padding: 2rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
        }

        .card:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: rgba(239, 68, 68, 0.4);
            transform: translateY(-4px);
            box-shadow: 0 20px 40px rgba(239, 68, 68, 0.1);
        }

        .card h2 {
            color: #f87171;
            margin-bottom: 0.5rem;
            font-size: 1.3rem;
            text-transform: capitalize;
        }

        .card p {
            color: #d1d5db;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
            line-height: 1.6;
        }

        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.2s ease;
            border: none;
            cursor: pointer;
        }

        .btn:hover {
            transform: scale(1.05);
            box-shadow: 0 10px 25px rgba(239, 68, 68, 0.3);
        }

        .info-box {
            background: rgba(239, 68, 68, 0.05);
            border-left: 4px solid #ef4444;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 2rem;
        }

        .info-box strong {
            color: #f87171;
        }

        .info-box code {
            background: rgba(0, 0, 0, 0.3);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            color: #86efac;
        }

        footer {
            text-align: center;
            color: #6b7280;
            font-size: 0.9rem;
            margin-top: 4rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(239, 68, 68, 0.1);
        }

        footer a {
            color: #f87171;
            text-decoration: none;
            transition: color 0.2s;
        }

        footer a:hover {
            color: #fca5a5;
            text-decoration: underline;
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 2rem;
            }

            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Wildbox API Documentation</h1>
            <p class="subtitle">Complete REST API Reference for all Security Services</p>
            <p class="timestamp">Generated with Redocly from live OpenAPI endpoints</p>
        </header>

        <div class="info-box">
            All microservices expose complete OpenAPI 3.0 specifications. Each documentation page includes full endpoint details, request/response examples, authentication requirements, and error codes.
        </div>

        <div class="grid">
            <div class="card">
                <h2>API / Tools Service</h2>
                <p>Core security tool execution, orchestration, and resource management platform.</p>
                <a href="api-api.html" class="btn">View Documentation →</a>
            </div>

            <div class="card">
                <h2>Identity Service</h2>
                <p>Authentication, authorization, JWT token management, and user account administration.</p>
                <a href="identity-api.html" class="btn">View Documentation →</a>
            </div>

            <div class="card">
                <h2>Data Service</h2>
                <p>Threat intelligence, IOC management, security data aggregation and analysis.</p>
                <a href="data-api.html" class="btn">View Documentation →</a>
            </div>

            <div class="card">
                <h2>Guardian Service</h2>
                <p>Integration management, queue monitoring, workflow orchestration and automation.</p>
                <a href="guardian-api.html" class="btn">View Documentation →</a>
            </div>

            <div class="card">
                <h2>Responder Service</h2>
                <p>Incident response playbook execution, remediation automation, and workflow management.</p>
                <a href="responder-api.html" class="btn">View Documentation →</a>
            </div>

            <div class="card">
                <h2>Agents Service</h2>
                <p>AI-powered threat analysis, machine learning intelligence enrichment, and autonomous security.</p>
                <a href="agents-api.html" class="btn">View Documentation →</a>
            </div>
        </div>

        <footer>
            <p>Wildbox Security Platform • <a href="https://github.com/fabriziosalmi/wildbox" target="_blank">GitHub Repository</a></p>
        </footer>
    </div>
</body>
</html>
INDEXEOF

echo -e "${GREEN}✓${NC} Created index page\n"

# Final summary
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}API Documentation generation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}\n"

echo "Generated files in: ${DOCS_DIR}/"
ls -lh "$DOCS_DIR"/*.html 2>/dev/null | awk '{print "  " $NF}'

echo -e "\n${BLUE}Access documentation:${NC}"
echo "  • Index: $DOCS_DIR/swagger-index.html"
echo "  • Individual APIs in: $DOCS_DIR/"

echo -e "\n${BLUE}Next steps:${NC}"
echo "  1. Review generated files"
echo "  2. Commit to git: git add docs/api/*.html"
echo "  3. Push to GitHub Pages"
