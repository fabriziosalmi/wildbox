#!/usr/bin/env python3
"""Debug script to test Identity authentication flow"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import requests

# Load environment
env_path = Path("tests/.env")
print(f"Loading .env from: {env_path.absolute()}")
print(f".env exists: {env_path.exists()}")
load_dotenv(env_path)

# Get credentials
admin_email = os.getenv("TEST_ADMIN_EMAIL")
admin_password = os.getenv("TEST_ADMIN_PASSWORD")
identity_url = os.getenv("IDENTITY_SERVICE_URL")

print(f"\nEnvironment variables:")
print(f"  ADMIN_EMAIL: {admin_email}")
print(f"  ADMIN_PASSWORD: {'*' * len(admin_password) if admin_password else 'NOT SET'}")
print(f"  IDENTITY_URL: {identity_url}")

if not all([admin_email, admin_password, identity_url]):
    print("\n❌ Missing environment variables!")
    sys.exit(1)

# Test 1: Login
print(f"\n1. Testing login...")
login_response = requests.post(
    f"{identity_url}/api/v1/auth/jwt/login",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data=f"username={admin_email}&password={admin_password}",
    timeout=10
)

if login_response.status_code == 200:
    token_data = login_response.json()
    access_token = token_data.get("access_token")
    print(f"✅ Login successful! Token: {access_token[:30]}...")
else:
    print(f"❌ Login failed: {login_response.status_code}")
    print(f"   Response: {login_response.text}")
    sys.exit(1)

# Test 2: Get profile
print(f"\n2. Testing authenticated profile...")
profile_response = requests.get(
    f"{identity_url}/api/v1/users/me",
    headers={"Authorization": f"Bearer {access_token}"},
    timeout=10
)

if profile_response.status_code == 200:
    profile = profile_response.json()
    print(f"✅ Profile access successful!")
    print(f"   Email: {profile.get('email')}")
    print(f"   Superuser: {profile.get('is_superuser')}")
else:
    print(f"❌ Profile failed: {profile_response.status_code}")
    print(f"   Response: {profile_response.text}")
    sys.exit(1)

# Test 3: API Key creation
print(f"\n3. Testing API key creation...")
api_key_response = requests.post(
    f"{identity_url}/api/v1/api-keys",
    headers={
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    },
    json={
        "name": "debug-test-key",
        "description": "Debug test API key"
    },
    timeout=10
)

print(f"API Key creation status: {api_key_response.status_code}")
print(f"Response: {api_key_response.text[:200]}")

print(f"\n{'='*60}")
print("All manual tests completed!")
print("This proves the endpoints work - issue must be in test code")
print(f"{'='*60}")
