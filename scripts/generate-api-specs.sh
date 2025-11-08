#!/bin/bash

# Script to generate OpenAPI specifications for all Wildbox services
# This script should be run after starting all services with docker-compose

set -e

echo "🔍 Wildbox API Specs Generator"
echo "================================"
echo ""

# Create output directory
OUTPUT_DIR="./website/static/api-specs"
mkdir -p "$OUTPUT_DIR"

# Array of services with their ports and names
declare -A SERVICES=(
    ["identity"]="8001"
    ["tools"]="8000"
    ["data"]="8002"
    ["agents"]="8006"
    ["responder"]="8018"
    ["cspm"]="8019"
    ["guardian"]="8013"
)

# Function to check if service is healthy
check_service() {
    local service=$1
    local port=$2

    echo -n "Checking $service (port $port)... "

    if curl -sf "http://localhost:$port/health" > /dev/null 2>&1 || \
       curl -sf "http://localhost:$port/api/health" > /dev/null 2>&1; then
        echo "✅ Healthy"
        return 0
    else
        echo "❌ Not responding"
        return 1
    fi
}

# Function to download OpenAPI spec
download_spec() {
    local service=$1
    local port=$2
    local output_file="$OUTPUT_DIR/${service}.openapi.json"

    echo -n "Downloading OpenAPI spec for $service... "

    # Try multiple common OpenAPI endpoints
    local endpoints=(
        "http://localhost:$port/openapi.json"
        "http://localhost:$port/api/openapi.json"
        "http://localhost:$port/api/v1/openapi.json"
        "http://localhost:$port/docs/openapi.json"
    )

    for endpoint in "${endpoints[@]}"; do
        if curl -sf "$endpoint" -o "$output_file" 2>/dev/null; then
            # Validate JSON
            if jq empty "$output_file" 2>/dev/null; then
                echo "✅ Success"
                echo "   Saved to: $output_file"
                return 0
            else
                rm -f "$output_file"
            fi
        fi
    done

    echo "⚠️  Not available (service may not expose OpenAPI)"
    return 1
}

# Main execution
echo "📊 Service Health Check"
echo "------------------------"

healthy_count=0
total_count=${#SERVICES[@]}

for service in "${!SERVICES[@]}"; do
    port=${SERVICES[$service]}
    if check_service "$service" "$port"; then
        ((healthy_count++))
    fi
done

echo ""
echo "Healthy services: $healthy_count/$total_count"
echo ""

if [ $healthy_count -eq 0 ]; then
    echo "❌ No services are healthy. Please start services with:"
    echo "   docker-compose up -d"
    exit 1
fi

echo "📥 Downloading OpenAPI Specifications"
echo "--------------------------------------"

success_count=0

for service in "${!SERVICES[@]}"; do
    port=${SERVICES[$service]}
    if check_service "$service" "$port" > /dev/null 2>&1; then
        if download_spec "$service" "$port"; then
            ((success_count++))
        fi
    fi
done

echo ""
echo "================================"
echo "✨ Generation Complete!"
echo ""
echo "Downloaded $success_count OpenAPI specifications"
echo "Output directory: $OUTPUT_DIR"
echo ""

# List generated files
if [ $success_count -gt 0 ]; then
    echo "Generated files:"
    ls -lh "$OUTPUT_DIR"/*.openapi.json 2>/dev/null || true
fi

echo ""
echo "Next steps:"
echo "1. Review the generated specs in $OUTPUT_DIR"
echo "2. Build the documentation site: cd website && npm run build"
echo "3. Preview locally: cd website && npm run serve"
echo ""
