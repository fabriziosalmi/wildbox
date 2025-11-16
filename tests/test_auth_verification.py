#!/usr/bin/env python3
"""
Quick verification script for admin authentication
"""
import os
import requests
from dotenv import load_dotenv

# Load test environment variables
load_dotenv("tests/.env")

ADMIN_EMAIL = os.getenv("TEST_ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL")

print("=" * 60)
print("ADMIN AUTHENTICATION VERIFICATION")
print("=" * 60)

# Step 1: Login
print(f"\n1. Testing login for: {ADMIN_EMAIL}")
login_response = requests.post(
    f"{IDENTITY_URL}/api/v1/auth/jwt/login",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data=f"username={ADMIN_EMAIL}&password={ADMIN_PASSWORD}",
    timeout=10
)

if login_response.status_code == 200:
    token_data = login_response.json()
    access_token = token_data.get("access_token")
    print(f"✅ Login successful!")
    print(f"   Token type: {token_data.get('token_type')}")
    print(f"   Token: {access_token[:50]}...")
else:
    print(f"❌ Login failed: {login_response.status_code}")
    print(f"   Response: {login_response.text}")
    exit(1)

# Step 2: Get user profile
print(f"\n2. Testing authenticated profile access")
profile_response = requests.get(
    f"{IDENTITY_URL}/api/v1/users/me",
    headers={"Authorization": f"Bearer {access_token}"},
    timeout=10
)

if profile_response.status_code == 200:
    profile_data = profile_response.json()
    print(f"✅ Profile access successful!")
    print(f"   Email: {profile_data.get('email')}")
    print(f"   ID: {profile_data.get('id')}")
    print(f"   Superuser: {profile_data.get('is_superuser')}")
    print(f"   Active: {profile_data.get('is_active')}")
    print(f"   Verified: {profile_data.get('is_verified')}")
else:
    print(f"❌ Profile access failed: {profile_response.status_code}")
    print(f"   Response: {profile_response.text}")
    exit(1)

# Step 3: Test API key generation
print(f"\n3. Testing API key generation")
api_key_response = requests.post(
    f"{IDENTITY_URL}/api/v1/api-keys",
    headers={
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    },
    json={
        "name": "test-integration-key",
        "description": "Integration test API key"
    },
    timeout=10
)

if api_key_response.status_code in [200, 201]:
    api_key_data = api_key_response.json()
    print(f"✅ API key generation successful!")
    print(f"   Key ID: {api_key_data.get('id')}")
    print(f"   Key Name: {api_key_data.get('name')}")
    if 'key' in api_key_data:
        print(f"   API Key: {api_key_data['key'][:30]}...")
else:
    print(f"⚠️  API key generation: {api_key_response.status_code}")
    print(f"   Response: {api_key_response.text[:200]}")
    print(f"   (This may be expected if endpoint doesn't exist yet)")

print("\n" + "=" * 60)
print("VERIFICATION COMPLETE")
print("=" * 60)
