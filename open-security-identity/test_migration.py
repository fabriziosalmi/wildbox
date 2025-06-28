#!/usr/bin/env python3
"""
Test script for FastAPI Users migration.
Tests that the new authentication system works properly.
"""

import asyncio
import httpx
import json
from typing import Dict, Any

BASE_URL = "http://localhost:8000"
API_V1_PREFIX = "/api/v1"

async def test_endpoints():
    """Test the new FastAPI Users endpoints."""
    
    async with httpx.AsyncClient() as client:
        print("🔍 Testing FastAPI Users migration...")
        
        # Test registration endpoint
        print("\n1. Testing registration endpoint...")
        registration_data = {
            "email": "test@example.com", 
            "password": "testpassword123"
        }
        
        try:
            response = await client.post(
                f"{BASE_URL}{API_V1_PREFIX}/auth/register",
                json=registration_data
            )
            print(f"   Registration status: {response.status_code}")
            if response.status_code == 201:
                user_data = response.json()
                print(f"   User created: {user_data.get('email')}")
                print(f"   User ID: {user_data.get('id')}")
                print(f"   Is verified: {user_data.get('is_verified')}")
            else:
                print(f"   Error: {response.text}")
        except Exception as e:
            print(f"   Connection error: {e}")
        
        # Test login endpoint
        print("\n2. Testing login endpoint...")
        login_data = {
            "username": "test@example.com",  # FastAPI Users uses 'username' field
            "password": "testpassword123"
        }
        
        try:
            response = await client.post(
                f"{BASE_URL}{API_V1_PREFIX}/auth/jwt/login",
                data=login_data,  # Form data for OAuth2
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            print(f"   Login status: {response.status_code}")
            if response.status_code == 200:
                auth_data = response.json()
                access_token = auth_data.get("access_token")
                print(f"   Access token received: {access_token[:20]}...")
                
                # Test protected endpoint
                print("\n3. Testing protected endpoint...")
                headers = {"Authorization": f"Bearer {access_token}"}
                response = await client.get(
                    f"{BASE_URL}{API_V1_PREFIX}/users/me",
                    headers=headers
                )
                print(f"   Protected endpoint status: {response.status_code}")
                if response.status_code == 200:
                    user_info = response.json()
                    print(f"   Current user: {user_info.get('email')}")
                else:
                    print(f"   Error: {response.text}")
            else:
                print(f"   Error: {response.text}")
        except Exception as e:
            print(f"   Connection error: {e}")
        
        # Test documentation endpoints
        print("\n4. Testing documentation...")
        try:
            docs_response = await client.get(f"{BASE_URL}/docs")
            print(f"   Documentation status: {docs_response.status_code}")
        except Exception as e:
            print(f"   Connection error: {e}")

if __name__ == "__main__":
    print("🚀 FastAPI Users Migration Test")
    print("=" * 50)
    print("Make sure the server is running with: uvicorn app.main:app --reload")
    print()
    
    asyncio.run(test_endpoints())
