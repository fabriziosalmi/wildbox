#!/usr/bin/env python3
"""Test API key endpoints"""
import os
import requests
from dotenv import load_dotenv

load_dotenv("tests/.env")

ADMIN_EMAIL = os.getenv("TEST_ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL")

print("=" * 60)
print("TESTING API KEY ENDPOINTS")
print("=" * 60)

# Step 1: Login
print("\n1. Logging in...")
login_response = requests.post(
    f"{IDENTITY_URL}/api/v1/auth/jwt/login",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data=f"username={ADMIN_EMAIL}&password={ADMIN_PASSWORD}",
    timeout=10
)

if login_response.status_code != 200:
    print(f"❌ Login failed: {login_response.status_code}")
    exit(1)

token = login_response.json()["access_token"]
print(f"✅ Login successful! Token: {token[:30]}...")

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# Step 2: Create API key
print("\n2. Creating API key...")
create_response = requests.post(
    f"{IDENTITY_URL}/api/v1/api-keys",
    headers=headers,
    json={
        "name": "test-sprint1-key",
        "expires_at": None
    },
    timeout=10
)

print(f"Status: {create_response.status_code}")
if create_response.status_code in [200, 201]:
    key_data = create_response.json()
    print(f"✅ API key created!")
    print(f"   ID: {key_data.get('id')}")
    print(f"   Name: {key_data.get('name')}")
    print(f"   Prefix: {key_data.get('prefix')}")
    print(f"   Full Key: {key_data.get('key', 'NOT RETURNED')[:40]}...")

    api_key_prefix = key_data.get('prefix')
else:
    print(f"❌ Failed: {create_response.text}")
    exit(1)

# Step 3: List API keys
print("\n3. Listing API keys...")
list_response = requests.get(
    f"{IDENTITY_URL}/api/v1/api-keys",
    headers=headers,
    timeout=10
)

print(f"Status: {list_response.status_code}")
if list_response.status_code == 200:
    keys = list_response.json()
    print(f"✅ Found {len(keys)} API key(s):")
    for key in keys:
        print(f"   - {key.get('name')} ({key.get('prefix')})")
else:
    print(f"❌ Failed: {list_response.text}")

# Step 4: Revoke API key
if api_key_prefix:
    print(f"\n4. Revoking API key {api_key_prefix}...")
    revoke_response = requests.delete(
        f"{IDENTITY_URL}/api/v1/api-keys/{api_key_prefix}",
        headers=headers,
        timeout=10
    )

    print(f"Status: {revoke_response.status_code}")
    if revoke_response.status_code == 200:
        print(f"✅ API key revoked!")
    else:
        print(f"❌ Failed: {revoke_response.text}")

print("\n" + "=" * 60)
print("TEST COMPLETE!")
print("=" * 60)
