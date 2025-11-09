#!/bin/bash

# Quick Start Script for Web Attack Detection Use Case
# This script automates the setup and testing of log ingestion

set -e

echo "🛡️  Wildbox Web Attack Detection - Quick Start"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running from correct directory
if [[ ! -f "README.md" ]] || [[ ! -d "sample-logs" ]]; then
    echo -e "${RED}Error: Please run this script from the use-cases/web-attack-detection directory${NC}"
    exit 1
fi

echo "Step 1: Checking prerequisites..."
echo "-----------------------------------"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker first.${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker is running"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: docker-compose is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} docker-compose is available"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}Warning: python3 not found. Log generator won't work.${NC}"
else
    echo -e "${GREEN}✓${NC} Python 3 is available"
fi

echo ""
echo "Step 2: Creating test environment..."
echo "--------------------------------------"

# Create test directory
TEST_DIR="/tmp/wildbox-test"
mkdir -p ${TEST_DIR}/logs
echo -e "${GREEN}✓${NC} Created test directory: ${TEST_DIR}"

# Copy sample logs
cp sample-logs/nginx-access.log ${TEST_DIR}/logs/access.log
echo -e "${GREEN}✓${NC} Copied sample logs to ${TEST_DIR}/logs/access.log"

echo ""
echo "Step 3: Checking Wildbox services..."
echo "--------------------------------------"

# Navigate to Wildbox root
WILDBOX_ROOT="../../"
cd ${WILDBOX_ROOT}

# Check if services are running
if ! docker-compose ps | grep -q "Up"; then
    echo -e "${YELLOW}Wildbox services not running. Starting them now...${NC}"
    docker-compose up -d
    echo "Waiting for services to be healthy (30 seconds)..."
    sleep 30
else
    echo -e "${GREEN}✓${NC} Wildbox services are running"
fi

# Verify Data Lake is accessible
if curl -s http://localhost:8001/health > /dev/null; then
    echo -e "${GREEN}✓${NC} Data Lake is healthy"
else
    echo -e "${RED}Error: Data Lake is not responding at http://localhost:8001${NC}"
    echo "Try: docker-compose ps"
    exit 1
fi

echo ""
echo "Step 4: Sensor configuration..."
echo "--------------------------------"

# Go back to use case directory
cd use-cases/web-attack-detection

# Create sensor config for testing
cat > /tmp/wildbox-test-config.yaml <<EOF
# Test Configuration for Web Attack Detection
data_lake:
  endpoint: "http://localhost:8001/api/v1/ingest"
  api_key: "test-key-123"
  tls_verify: false
  batch_size: 50
  flush_interval: 10

collection:
  process_events: false
  network_connections: false
  file_monitoring: false
  user_events: false
  system_inventory: false
  log_forwarding: true

log_sources:
  - name: nginx_access
    type: file
    path: ${TEST_DIR}/logs/access.log
    format: nginx
    enabled: true

performance:
  query_interval: 5
  max_memory_mb: 128
  max_cpu_percent: 5
  max_queue_size: 500
  worker_threads: 2

logging:
  level: INFO
  format: json

sensor:
  name: "test-web-server-sensor"
  tags:
    - "test"
    - "web-attack-detection"
EOF

echo -e "${GREEN}✓${NC} Created sensor configuration: /tmp/wildbox-test-config.yaml"

echo ""
echo "Step 5: Generating test data..."
echo "--------------------------------"

if command -v python3 &> /dev/null; then
    # Generate additional test logs
    echo "Generating 100 test log entries..."
    python3 sample-logs/generate_logs.py \
        --output ${TEST_DIR}/logs/access.log \
        --count 100 \
        --attack-rate 0.4 2>/dev/null || echo -e "${YELLOW}Warning: Log generation failed${NC}"
    echo -e "${GREEN}✓${NC} Generated test logs"
else
    echo -e "${YELLOW}Skipping log generation (python3 not available)${NC}"
fi

echo ""
echo "Step 6: Displaying sample data..."
echo "----------------------------------"

echo "First 5 log entries:"
head -5 ${TEST_DIR}/logs/access.log

echo ""
echo "Attack patterns detected in sample:"
echo -n "  SQL Injection attempts: "
grep -c "OR\|UNION\|DROP TABLE" ${TEST_DIR}/logs/access.log || echo "0"
echo -n "  XSS attempts: "
grep -c "<script>\|onerror=" ${TEST_DIR}/logs/access.log || echo "0"
echo -n "  Path Traversal attempts: "
grep -c "\.\./\.\./\.\." ${TEST_DIR}/logs/access.log || echo "0"

echo ""
echo "=============================================="
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "=============================================="
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. Start the sensor (choose one option):"
echo ""
echo "   Option A - Using Docker (recommended):"
echo "   $ cd ../../open-security-sensor"
echo "   $ cp /tmp/wildbox-test-config.yaml ./config.yaml"
echo "   $ docker-compose up -d"
echo ""
echo "   Option B - Running locally:"
echo "   $ cd ../../open-security-sensor"
echo "   $ pip install -r requirements.txt"
echo "   $ python main.py --config /tmp/wildbox-test-config.yaml"
echo ""
echo "2. Monitor log ingestion:"
echo "   $ watch -n 2 'curl -s http://localhost:8001/api/v1/telemetry/stats | jq'"
echo ""
echo "3. View ingested events:"
echo "   $ curl http://localhost:8001/api/v1/telemetry/events | jq"
echo ""
echo "4. Generate real-time logs (in another terminal):"
echo "   $ python3 sample-logs/generate_logs.py \\"
echo "       --output ${TEST_DIR}/logs/access.log \\"
echo "       --realtime --duration 60"
echo ""
echo "5. Access the dashboard:"
echo "   $ open http://localhost:3000"
echo ""
echo "📖 Full documentation: use-cases/web-attack-detection/README.md"
echo "🔍 Testing guide: use-cases/web-attack-detection/docs/testing-guide.md"
echo ""
echo "Test environment location: ${TEST_DIR}"
echo "Sample logs: ${TEST_DIR}/logs/access.log"
echo "Sensor config: /tmp/wildbox-test-config.yaml"
echo ""
