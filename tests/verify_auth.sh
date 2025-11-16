#!/bin/bash
# Quick verification script for admin authentication

set -e

# Load environment variables
source tests/.env

echo "======================================================================"
echo "ADMIN AUTHENTICATION VERIFICATION"
echo "======================================================================"

# Step 1: Login
echo ""
echo "1. Testing login for: ${TEST_ADMIN_EMAIL}"
LOGIN_RESPONSE=$(curl -s -X POST "${IDENTITY_SERVICE_URL}/api/v1/auth/jwt/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${TEST_ADMIN_EMAIL}&password=${TEST_ADMIN_PASSWORD}")

if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    echo "✅ Login successful!"
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
    echo "   Token: ${ACCESS_TOKEN:0:50}..."
else
    echo "❌ Login failed!"
    echo "   Response: $LOGIN_RESPONSE"
    exit 1
fi

# Step 2: Get user profile
echo ""
echo "2. Testing authenticated profile access"
PROFILE_RESPONSE=$(curl -s -X GET "${IDENTITY_SERVICE_URL}/api/v1/users/me" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}")

if echo "$PROFILE_RESPONSE" | grep -q "email"; then
    echo "✅ Profile access successful!"
    echo "   Response: $PROFILE_RESPONSE" | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"   Email: {d.get('email')}\\n   Superuser: {d.get('is_superuser')}\\n   Active: {d.get('is_active')}\")" || echo "   $PROFILE_RESPONSE"
else
    echo "❌ Profile access failed!"
    echo "   Response: $PROFILE_RESPONSE"
    exit 1
fi

echo ""
echo "======================================================================"
echo "VERIFICATION COMPLETE - Authentication is working!"
echo "======================================================================"
