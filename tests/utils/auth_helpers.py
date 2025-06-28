"""
Authentication helpers for test orchestration
Manages JWT tokens, API keys, and user authentication across services
"""

import requests
import asyncio
import time
from typing import Dict, Optional, Any
import secrets
import hashlib


class AuthManager:
    """Manages authentication for all test services"""
    
    def __init__(self):
        self.base_urls = {
            "identity": "http://localhost:8001",
            "gateway": "http://localhost:80",
            "tools": "http://localhost:8000",
            "data": "http://localhost:8002",
            "guardian": "http://localhost:8013",
            "sensor": "http://localhost:8004",
            "responder": "http://localhost:8018",
            "agents": "http://localhost:8006",
            "cspm": "http://localhost:8019",
            "automations": "http://localhost:5678",
            "dashboard": "http://localhost:3000"
        }
        
        self.tokens = {}
        self.api_keys = {}
        self.test_users = {}
        
    async def setup(self):
        """Setup authentication environment"""
        await self.wait_for_services()
        await self.create_test_users()
        await self.generate_api_keys()
        
    async def wait_for_services(self, timeout: int = 60):
        """Wait for all services to be healthy"""
        print("🔍 Waiting for services to be ready...")
        
        health_endpoints = {
            "identity": "/health",
            "tools": "/health", 
            "data": "/health",
            "gateway": "/health",
            "guardian": "/health",
            "responder": "/api/v1/health",
            "cspm": "/health",
            "agents": "/health"
        }
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            all_ready = True
            for service, endpoint in health_endpoints.items():
                try:
                    url = f"{self.base_urls[service]}{endpoint}"
                    response = requests.get(url, timeout=5)
                    if response.status_code != 200:
                        all_ready = False
                        break
                except:
                    all_ready = False
                    break
                    
            if all_ready:
                print("✅ All services are ready")
                return
                
            await asyncio.sleep(2)
            
        raise Exception("Services not ready within timeout")
        
    async def create_test_users(self):
        """Create test users with different roles"""
        users_to_create = [
            {
                "email": "admin@wildbox.test",
                "password": "AdminPass123!",
                "role": "owner",
                "plan": "business"
            },
            {
                "email": "manager@wildbox.test", 
                "password": "ManagerPass123!",
                "role": "admin",
                "plan": "pro"
            },
            {
                "email": "analyst@wildbox.test",
                "password": "AnalystPass123!",
                "role": "member", 
                "plan": "pro"
            },
            {
                "email": "viewer@wildbox.test",
                "password": "ViewerPass123!",
                "role": "viewer",
                "plan": "free"
            }
        ]
        
        for user_data in users_to_create:
            try:
                # Register user
                register_response = await self.register_user(
                    user_data["email"], 
                    user_data["password"]
                )
                
                if register_response:
                    # Login to get token
                    token = await self.login_user(
                        user_data["email"],
                        user_data["password"]
                    )
                    
                    if token:
                        self.test_users[user_data["role"]] = {
                            "email": user_data["email"],
                            "password": user_data["password"],
                            "token": token,
                            "plan": user_data["plan"]
                        }
                        self.tokens[user_data["role"]] = token
                        
            except Exception as e:
                print(f"⚠️ Warning: Could not create test user {user_data['email']}: {e}")
                
    async def register_user(self, email: str, password: str) -> Optional[Dict]:
        """Register a new user"""
        try:
            url = f"{self.base_urls['identity']}/api/v1/auth/register"
            data = {
                "email": email,
                "password": password,
                "company_name": "Wildbox Test Corp"
            }
            
            response = requests.post(url, json=data, timeout=10)
            if response.status_code in [200, 201]:
                return response.json()
            elif response.status_code == 400 and "already exists" in response.text:
                # User already exists, that's ok
                return {"message": "User exists"}
            else:
                print(f"Registration failed for {email}: {response.status_code} {response.text}")
                return None
                
        except Exception as e:
            print(f"Registration error for {email}: {e}")
            return None
            
    async def login_user(self, email: str, password: str) -> Optional[str]:
        """Login user and return JWT token"""
        try:
            url = f"{self.base_urls['identity']}/api/v1/auth/login"
            data = f"username={email}&password={password}"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            
            response = requests.post(url, data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json().get("access_token")
            else:
                print(f"Login failed for {email}: {response.status_code} {response.text}")
                return None
                
        except Exception as e:
            print(f"Login error for {email}: {e}")
            return None
            
    async def generate_api_keys(self):
        """Generate API keys for testing"""
        for role, user_data in self.test_users.items():
            try:
                url = f"{self.base_urls['identity']}/api/v1/auth/api-keys"
                headers = {"Authorization": f"Bearer {user_data['token']}"}
                data = {"name": f"test-key-{role}"}
                
                response = requests.post(url, json=data, headers=headers, timeout=10)
                if response.status_code in [200, 201]:
                    api_key = response.json().get("api_key")
                    if api_key:
                        self.api_keys[role] = api_key
                        
            except Exception as e:
                print(f"⚠️ Warning: Could not generate API key for {role}: {e}")
                
    def get_token(self, role: str = "admin") -> Optional[str]:
        """Get JWT token for role"""
        return self.tokens.get(role)
        
    def get_api_key(self, role: str = "admin") -> Optional[str]:
        """Get API key for role"""
        return self.api_keys.get(role)
        
    def get_auth_headers(self, role: str = "admin", use_api_key: bool = False) -> Dict[str, str]:
        """Get authentication headers"""
        if use_api_key:
            api_key = self.get_api_key(role)
            if api_key:
                return {"Authorization": f"Bearer {api_key}"}
        else:
            token = self.get_token(role)
            if token:
                return {"Authorization": f"Bearer {token}"}
                
        return {}
        
    def make_authenticated_request(self, method: str, url: str, role: str = "admin", 
                                 use_api_key: bool = False, **kwargs) -> requests.Response:
        """Make authenticated HTTP request"""
        headers = kwargs.get("headers", {})
        headers.update(self.get_auth_headers(role, use_api_key))
        kwargs["headers"] = headers
        
        return requests.request(method, url, **kwargs)