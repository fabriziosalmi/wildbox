#!/bin/bash

# Test script to verify the authentication fix works from the dashboard perspective
# SECURITY WARNING: This uses test credentials - set proper credentials via environment variables

echo "🧪 Testing Dashboard Authentication Fix"
echo "======================================="

# Get credentials from environment or use test defaults (NOT for production!)
TEST_EMAIL="${TEST_ADMIN_EMAIL:-superadmin@wildbox.com}"
TEST_PASSWORD="${TEST_ADMIN_PASSWORD:-CHANGE_THIS_PASSWORD}"

if [[ "$TEST_PASSWORD" == "CHANGE_THIS_PASSWORD" ]]; then
    echo "⚠️  WARNING: Using insecure test credentials!"
    echo "   Set TEST_ADMIN_EMAIL and TEST_ADMIN_PASSWORD environment variables"
    echo "   for secure testing"
fi

# Test login via the dashboard API endpoint
echo -e "\n1. Testing login endpoint through dashboard..."

LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:3000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$TEST_EMAIL\", \"password\": \"$TEST_PASSWORD\"}")

if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    echo "✅ Dashboard login API endpoint works correctly"
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")
else
    echo "❌ Dashboard login API endpoint failed:"
    echo "$LOGIN_RESPONSE"
fi

# Test direct identity service endpoint that dashboard should use
echo -e "\n2. Testing identity service endpoint that dashboard uses..."

IDENTITY_LOGIN_RESPONSE=$(curl -s -X POST "http://localhost/api/v1/identity/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$TEST_EMAIL&password=$TEST_PASSWORD")

if echo "$IDENTITY_LOGIN_RESPONSE" | grep -q "access_token"; then
    echo "✅ Identity service login endpoint works correctly"
    IDENTITY_TOKEN=$(echo "$IDENTITY_LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")
    
    # Test user info endpoint
    echo -e "\n3. Testing user info endpoint..."
    USER_INFO_RESPONSE=$(curl -s -X GET "http://localhost/api/v1/identity/auth/me" \
      -H "Authorization: Bearer $IDENTITY_TOKEN")
    
    if echo "$USER_INFO_RESPONSE" | grep -q "email"; then
        echo "✅ User info endpoint works correctly"
        USER_EMAIL=$(echo "$USER_INFO_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['email'])" 2>/dev/null || echo "")
        echo "   User: $USER_EMAIL"
    else
        echo "❌ User info endpoint failed:"
        echo "$USER_INFO_RESPONSE"
    fi
else
    echo "❌ Identity service login endpoint failed:"
    echo "$IDENTITY_LOGIN_RESPONSE"
fi

echo -e "\n🎉 Authentication endpoint testing complete!"
echo -e "\nNext step: Try logging in through the web interface at http://localhost:3000"
echo "Use credentials: $TEST_EMAIL / [password from environment]"
