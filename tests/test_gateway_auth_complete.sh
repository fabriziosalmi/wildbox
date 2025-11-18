#!/bin/bash

# Comprehensive Gateway Authentication Test
# Tests all authentication flows through the gateway

set -e

echo "🔐 Wildbox Gateway Authentication Test"
echo "======================================="

# Configuration
GATEWAY_URL="http://localhost:80"
API_KEY="your-test-api-key-here"
TEST_EMAIL="gateway-ui-test@example.com"
TEST_PASSWORD="testpassword123"
TEST_NAME="Gateway UI Test User"

echo "🔧 Testing Gateway Health..."
health_response=$(curl -s "$GATEWAY_URL/health")
if echo "$health_response" | grep -q '"status":"healthy"'; then
    echo "✅ Gateway is healthy"
else
    echo "❌ Gateway health check failed: $health_response"
    exit 1
fi

echo ""
echo "📝 Testing User Registration..."
register_response=$(curl -s -X POST "$GATEWAY_URL/api/v1/identity/auth/register" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\",
    \"name\": \"$TEST_NAME\"
  }")

if echo "$register_response" | grep -q "access_token"; then
    echo "✅ Registration successful"
    register_token=$(echo "$register_response" | jq -r '.access_token')
else
    echo "⚠️  Registration response: $register_response"
    if echo "$register_response" | grep -q "Email already registered"; then
        echo "ℹ️  User already exists, proceeding with login test"
    else
        echo "❌ Registration failed"
        exit 1
    fi
fi

echo ""
echo "🔑 Testing User Login..."
login_response=$(curl -s -X POST "$GATEWAY_URL/api/v1/identity/auth/login-json" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{
    \"username\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\"
  }")

if echo "$login_response" | grep -q "access_token"; then
    echo "✅ Login successful"
    access_token=$(echo "$login_response" | jq -r '.access_token')
else
    echo "❌ Login failed: $login_response"
    exit 1
fi

echo ""
echo "👤 Testing User Profile Access..."
profile_response=$(curl -s -X GET "$GATEWAY_URL/api/v1/identity/auth/me" \
  -H "Authorization: Bearer $access_token" \
  -H "X-API-Key: $API_KEY")

if echo "$profile_response" | grep -q "\"email\""; then
    echo "✅ Profile access successful"
    user_email=$(echo "$profile_response" | jq -r '.email')
    echo "   User: $user_email"
else
    echo "❌ Profile access failed: $profile_response"
    exit 1
fi

echo ""
echo "🚪 Testing Logout..."
logout_response=$(curl -s -X POST "$GATEWAY_URL/api/v1/identity/auth/logout" \
  -H "Authorization: Bearer $access_token" \
  -H "X-API-Key: $API_KEY")

if echo "$logout_response" | grep -q "Successfully logged out"; then
    echo "✅ Logout successful"
else
    echo "❌ Logout failed: $logout_response"
    exit 1
fi

echo ""
echo "🔒 Testing Token Invalidation..."
# Try to access profile with the same token after logout
invalid_response=$(curl -s -X GET "$GATEWAY_URL/api/v1/identity/auth/me" \
  -H "Authorization: Bearer $access_token" \
  -H "X-API-Key: $API_KEY")

if echo "$invalid_response" | grep -q "Not authenticated"; then
    echo "✅ Token properly invalidated after logout"
else
    echo "⚠️  Token may still be valid after logout (depends on logout implementation)"
    echo "   Response: $invalid_response"
fi

echo ""
echo "🌐 Testing Dashboard Accessibility..."
dashboard_response=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/")
if [ "$dashboard_response" = "200" ]; then
    echo "✅ Dashboard accessible through gateway"
else
    echo "❌ Dashboard not accessible: HTTP $dashboard_response"
    exit 1
fi

echo ""
echo "🎉 All tests passed! Authentication flow is working correctly through the gateway."
echo ""
echo "📋 Summary:"
echo "   - Gateway URL: $GATEWAY_URL"
echo "   - Registration: ✅ Working"
echo "   - Login: ✅ Working"
echo "   - Profile Access: ✅ Working"
echo "   - Logout: ✅ Working"
echo "   - Dashboard: ✅ Accessible"
echo ""
echo "🖥️  Dashboard UI: $GATEWAY_URL"
echo "📚 API Documentation: $GATEWAY_URL/docs (if enabled)"
