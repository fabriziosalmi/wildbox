#!/bin/bash

# Frontend-Only E2E Test Runner for Wildbox Dashboard
# This script runs UI-focused tests that don't require backend services

set -e

echo "🚀 Starting Wildbox Frontend E2E Tests..."
echo "======================================="

# Check if dashboard is running
echo "🔍 Checking if dashboard is running..."

if ! curl -s http://localhost:3000 > /dev/null; then
    echo "❌ Dashboard not running on localhost:3000"
    echo "Please start the dashboard with: npm run dev"
    exit 1
fi

echo "✅ Dashboard is running"

# Create screenshots directory if it doesn't exist
mkdir -p tests/screenshots

# Run the UI-only tests
echo "🧪 Running frontend UI tests..."

echo "📝 Running login form and UI component tests..."
npx playwright test admin-ui-only.spec.ts --reporter=html

echo "🎉 Frontend tests completed!"
echo "📊 Test report available at: playwright-report/index.html"
echo "📸 Screenshots saved to: tests/screenshots/"

# Open test report if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🔍 Opening test report..."
    open playwright-report/index.html
fi
