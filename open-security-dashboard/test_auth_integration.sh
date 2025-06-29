#!/bin/bash

# Test script for the updated dashboard authentication integration

echo "🧪 Testing Dashboard Authentication Integration with Open Security Identity"
echo "========================================================================="

# Check if the identity service is running
echo -e "\n1. Checking if Identity Service is available..."
if curl -f -s http://localhost:8001/health > /dev/null; then
    echo "✅ Identity Service is running on port 8001"
else
    echo "❌ Identity Service is not running. Please start it first:"
    echo "   cd open-security-identity && make dev"
    exit 1
fi

# Test user registration
echo -e "\n2. Testing user registration endpoint..."
REGISTER_RESPONSE=$(curl -s -X POST "http://localhost:8001/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@dashboard.com",
    "password": "testpassword123"
  }')

if echo "$REGISTER_RESPONSE" | grep -q "access_token"; then
    echo "✅ Registration endpoint works correctly"
    ACCESS_TOKEN=$(echo "$REGISTER_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
else
    echo "⚠️ Registration may have failed (user might already exist)"
    echo "Attempting login instead..."
fi

# Test user login
echo -e "\n3. Testing user login endpoint..."
LOGIN_RESPONSE=$(curl -s -X POST "http://localhost:8001/api/v1/auth/jwt/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test@dashboard.com&password=testpassword123")

if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    echo "✅ Login endpoint works correctly"
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
else
    echo "❌ Login failed:"
    echo "$LOGIN_RESPONSE"
    exit 1
fi

# Test user info endpoint
echo -e "\n4. Testing user info endpoint..."
USER_INFO=$(curl -s -X GET "http://localhost:8001/api/v1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

if echo "$USER_INFO" | grep -q "email"; then
    echo "✅ User info endpoint works correctly"
    echo "   User: $(echo "$USER_INFO" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['email'])")"
else
    echo "❌ User info endpoint failed:"
    echo "$USER_INFO"
    exit 1
fi

echo -e "\n🎉 All authentication endpoints are working correctly!"
echo -e "\nNext steps:"
echo "1. Start the dashboard: cd open-security-dashboard && npm run dev"
echo "2. Visit http://localhost:3000/auth/login"
echo "3. Use test@dashboard.com / testpassword123 to login"
echo -e "\n✅ Dashboard authentication integration is ready!"
