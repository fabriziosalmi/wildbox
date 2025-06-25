#!/usr/bin/env python3
"""
Demo script for Open Security Identity service.

This script demonstrates the core functionality of the identity service.
"""

import asyncio
import httpx
from app.auth import generate_api_key, get_password_hash
from app.models import User, Team, ApiKey


async def demo_auth_functions():
    """Demonstrate authentication functions."""
    print("🔐 Authentication Functions Demo")
    print("=" * 40)
    
    # Password hashing
    password = "mysecretpassword"
    hashed = get_password_hash(password)
    print(f"Password: {password}")
    print(f"Hash: {hashed[:50]}...")
    
    # API key generation
    full_key, prefix, hashed_key = generate_api_key()
    print(f"\nGenerated API Key:")
    print(f"  Full key: {full_key}")
    print(f"  Prefix: {prefix}")
    print(f"  Hash: {hashed_key[:20]}...")


def demo_models():
    """Demonstrate model creation."""
    print("\n📊 Database Models Demo")
    print("=" * 40)
    
    # Create a user (without saving to DB)
    user = User(
        email="demo@wildbox.com",
        hashed_password=get_password_hash("password123"),
        is_active=True
    )
    print(f"User: {user}")
    
    # Create a team
    team = Team(
        name="Demo Team",
        owner_id=user.id
    )
    print(f"Team: {team}")
    
    # Create an API key
    full_key, prefix, hashed_key = generate_api_key()
    api_key = ApiKey(
        hashed_key=hashed_key,
        prefix=prefix,
        user_id=user.id,
        team_id=team.id,
        name="Demo API Key"
    )
    print(f"API Key: {api_key}")


async def demo_api_endpoints():
    """Demonstrate API endpoints (requires running service)."""
    print("\n🌐 API Endpoints Demo")
    print("=" * 40)
    
    base_url = "http://localhost:8000"
    
    try:
        async with httpx.AsyncClient() as client:
            # Test root endpoint
            response = await client.get(f"{base_url}/")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Service: {data['service']}")
                print(f"✅ Version: {data['version']}")
                print(f"✅ Status: {data['status']}")
            else:
                print(f"❌ Service not running (status: {response.status_code})")
                
            # Test health endpoint
            response = await client.get(f"{base_url}/health")
            if response.status_code == 200:
                print("✅ Health check passed")
            else:
                print("❌ Health check failed")
                
    except httpx.ConnectError:
        print("❌ Cannot connect to service. Make sure it's running on port 8000.")
        print("   Start with: uvicorn app.main:app --reload")


def demo_subscription_plans():
    """Demonstrate subscription plan logic."""
    print("\n💳 Subscription Plans Demo")
    print("=" * 40)
    
    from app.billing import billing_service
    
    plans = ["free", "pro", "business"]
    
    for plan in plans:
        permissions = billing_service.get_plan_permissions(plan)
        rate_limits = billing_service.get_rate_limits(plan)
        
        print(f"\n{plan.upper()} Plan:")
        print(f"  Permissions: {', '.join(permissions)}")
        print(f"  Rate Limits: {rate_limits}")


async def main():
    """Run all demos."""
    print("🎯 Open Security Identity - Demo Script")
    print("=" * 50)
    
    await demo_auth_functions()
    demo_models()
    demo_subscription_plans()
    await demo_api_endpoints()
    
    print("\n✅ Demo completed!")
    print("\nNext steps:")
    print("1. Start the service: uvicorn app.main:app --reload")
    print("2. Visit http://localhost:8000/docs for API documentation")
    print("3. Use the API endpoints to register users and create API keys")


if __name__ == "__main__":
    asyncio.run(main())
