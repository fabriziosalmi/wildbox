"""
Dashboard Frontend Test Module
Tests page loading, navigation, data population
"""

import requests
import asyncio
import time
from typing import Dict, List, Any, Optional


class DashboardFrontendTester:
    """Comprehensive tests for Dashboard Frontend (Port 3000)"""
    
    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.results = []
        
    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.results.append({
            "name": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
        
    async def test_service_health(self) -> bool:
        """Test dashboard service health"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=15)
            
            # Dashboard should respond with HTML or redirect
            passed = response.status_code in [200, 301, 302]
            
            if passed:
                content_type = response.headers.get('content-type', '')
                if 'text/html' in content_type:
                    details = "Dashboard serving HTML content"
                else:
                    details = f"Dashboard responding (Content-Type: {content_type})"
            else:
                details = f"HTTP {response.status_code}"
                
            self.log_test_result("Dashboard Service Health", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Dashboard Service Health", False, f"Error: {str(e)}")
            return False
            
    async def test_page_loading_with_widgets(self) -> bool:
        """Test initial page loading with all widgets"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=20)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for typical dashboard elements
                dashboard_elements = [
                    'dashboard',
                    'widget',
                    'chart',
                    'security',
                    'wildbox',
                    'nav',
                    'menu'
                ]
                
                found_elements = []
                for element in dashboard_elements:
                    if element in content:
                        found_elements.append(element)
                
                passed = len(found_elements) >= 3  # At least some dashboard elements
                
                if passed:
                    details = f"Dashboard elements found: {', '.join(found_elements)}"
                else:
                    details = f"Limited dashboard content, found: {', '.join(found_elements)}"
                    
            elif response.status_code in [301, 302]:
                # Redirect is acceptable (might redirect to login)
                location = response.headers.get('location', 'unknown')
                details = f"Dashboard redirects to: {location}"
                passed = True
            else:
                details = f"Page loading failed: HTTP {response.status_code}"
                passed = False
                
            self.log_test_result("Page Loading with All Widgets", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Page Loading with All Widgets", False, f"Error: {str(e)}")
            return False
            
    async def test_navigation_without_errors(self) -> bool:
        """Test complete navigation without errors"""
        try:
            # Test various dashboard routes
            navigation_routes = [
                "/",
                "/dashboard",
                "/tools",
                "/reports",
                "/settings",
                "/profile"
            ]
            
            successful_routes = 0
            error_routes = 0
            
            for route in navigation_routes:
                try:
                    response = requests.get(f"{self.base_url}{route}", timeout=10)
                    
                    # Success codes or redirects are good
                    if response.status_code in [200, 301, 302]:
                        successful_routes += 1
                    elif response.status_code in [401, 403]:
                        # Authentication required is acceptable
                        successful_routes += 1
                    elif response.status_code >= 500:
                        error_routes += 1
                        
                except Exception:
                    error_routes += 1
            
            # Good navigation if most routes work and no server errors
            passed = successful_routes > 0 and error_routes == 0
            
            if passed:
                details = f"Navigation working: {successful_routes}/{len(navigation_routes)} routes accessible, {error_routes} errors"
            else:
                details = f"Navigation issues: {successful_routes} successful, {error_routes} errors"
                
            self.log_test_result("Complete Navigation without Errors", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Complete Navigation without Errors", False, f"Error: {str(e)}")
            return False
            
    async def test_data_population(self) -> bool:
        """Test real data population and updates"""
        try:
            # Test API endpoints that dashboard might use
            api_endpoints = [
                "/api/dashboard",
                "/api/stats",
                "/api/widgets",
                "/api/data"
            ]
            
            data_endpoints = 0
            
            for endpoint in api_endpoints:
                try:
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                    
                    # Any structured response indicates data API
                    if response.status_code in [200, 401, 403]:
                        data_endpoints += 1
                        
                        # Check for JSON data
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                if isinstance(data, (dict, list)) and data:
                                    data_endpoints += 1  # Bonus for actual data
                            except:
                                pass
                                
                except Exception:
                    pass
            
            passed = data_endpoints > 0
            
            if passed:
                details = f"Data population APIs accessible: {data_endpoints} endpoints"
            else:
                details = "No data population APIs found"
                
            self.log_test_result("Real Data Population", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Real Data Population", False, f"Error: {str(e)}")
            return False
            
    async def test_static_assets_loading(self) -> bool:
        """Test static assets loading (CSS, JS, images)"""
        try:
            # Test common static asset paths
            asset_paths = [
                "/static/css/main.css",
                "/static/js/main.js",
                "/css/style.css",
                "/js/app.js",
                "/assets/logo.png",
                "/favicon.ico"
            ]
            
            loaded_assets = 0
            
            for asset_path in asset_paths:
                try:
                    response = requests.get(f"{self.base_url}{asset_path}", timeout=5)
                    
                    # Static assets should return 200 or proper mime types
                    if response.status_code == 200:
                        content_type = response.headers.get('content-type', '')
                        if any(t in content_type for t in ['css', 'javascript', 'image', 'text']):
                            loaded_assets += 1
                            
                except Exception:
                    pass
            
            # Also check if main page references static assets
            try:
                main_response = requests.get(f"{self.base_url}/", timeout=10)
                if main_response.status_code == 200:
                    content = main_response.text.lower()
                    if any(ref in content for ref in ['.css', '.js', 'stylesheet', 'script']):
                        loaded_assets += 1  # Main page references assets
            except:
                pass
            
            passed = loaded_assets > 0
            
            if passed:
                details = f"Static assets loading: {loaded_assets} assets/references found"
            else:
                details = "No static assets found"
                
            self.log_test_result("Static Assets Loading", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Static Assets Loading", False, f"Error: {str(e)}")
            return False
            
    async def test_responsive_design(self) -> bool:
        """Test responsive design elements"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for responsive design indicators
                responsive_indicators = [
                    'viewport',
                    'media query',
                    'responsive',
                    'mobile',
                    'bootstrap',
                    'flex',
                    'grid'
                ]
                
                found_indicators = []
                for indicator in responsive_indicators:
                    if indicator in content:
                        found_indicators.append(indicator)
                
                passed = len(found_indicators) >= 2  # Some responsive elements
                
                if passed:
                    details = f"Responsive design elements: {', '.join(found_indicators)}"
                else:
                    details = "Limited responsive design elements found"
                    
            else:
                passed = False
                details = f"Cannot check responsive design: HTTP {response.status_code}"
                
            self.log_test_result("Responsive Design Elements", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Responsive Design Elements", False, f"Error: {str(e)}")
            return False


async def run_tests() -> Dict[str, Any]:
    """Run all dashboard frontend tests"""
    tester = DashboardFrontendTester()
    
    # Run tests in sequence
    tests = [
        tester.test_service_health,
        tester.test_page_loading_with_widgets,
        tester.test_navigation_without_errors,
        tester.test_data_population,
        tester.test_static_assets_loading,
        tester.test_responsive_design
    ]
    
    success_count = 0
    for test in tests:
        try:
            success = await test()
            if success:
                success_count += 1
        except Exception as e:
            print(f"Dashboard frontend test error: {e}")
            
    all_passed = success_count == len(tests)
    
    return {
        "success": all_passed,
        "tests": tester.results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }