#!/bin/bash

# Admin E2E Test Runner for Wildbox Dashboard
# This script runs comprehensive admin workflow tests

set -e

echo "🚀 Starting Wildbox Admin E2E Tests..."
echo "=================================="

# Check if services are running
echo "🔍 Checking if services are running..."

# Check if dashboard is running
if ! curl -s http://localhost:3000 > /dev/null; then
    echo "❌ Dashboard not running on localhost:3000"
    echo "Please start the dashboard with: npm run dev"
    exit 1
fi

# Check if identity service is running  
if ! curl -s http://localhost/api/v1/identity/health > /dev/null; then
    echo "❌ Identity service not running on localhost"
    echo "Please start the identity service and gateway"
    exit 1
fi

echo "✅ Services are running"

# Create screenshots directory if it doesn't exist
mkdir -p tests/screenshots

# Run the tests
echo "🧪 Running admin comprehensive tests..."

# Run specific admin tests
echo "📝 Running admin workflow tests..."
npx playwright test admin-comprehensive.spec.ts --reporter=html

echo "🎉 Tests completed!"
echo "📊 Test report available at: playwright-report/index.html"
echo "📸 Screenshots saved to: tests/screenshots/"

# Open test report if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🔍 Opening test report..."
    open playwright-report/index.html
fi
