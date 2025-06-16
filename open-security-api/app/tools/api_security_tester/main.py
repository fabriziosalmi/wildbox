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
        
    except Exception as e:
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
    
    elif category == "injection":
        result = await test_injection_vulnerabilities(base_url, endpoints, headers, include_fuzzing, delay)
        tests.extend(result["tests"])
        vulnerabilities.extend(result["vulnerabilities"])
    
    # Add more categories...
    
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
                except Exception as e:
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

async def test_injection_vulnerabilities(base_url: str, endpoints: List[APIEndpoint], headers: Dict, include_fuzzing: bool, delay: float) -> Dict[str, List]:
    """Test for injection vulnerabilities"""
    tests = []
    vulnerabilities = []
    
    test = SecurityTest(
        test_name="Injection Vulnerabilities",
        category="Injection",
        description="Testing for SQL injection, NoSQL injection, and command injection",
        executed=True,
        passed=True,
        findings=[],
        recommendations=[]
    )
    
    injection_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM users--",
        "admin'/*",
        "'; SELECT * FROM information_schema.tables--",
        "1; ls -la",
        "|whoami",
        "$(id)",
        "`cat /etc/passwd`"
    ]
    
    for endpoint in endpoints:
        if endpoint.parameters:
            for param in endpoint.parameters:
                for payload in injection_payloads:
                    try:
                        if endpoint.method == "GET":
                            url = f"{urljoin(base_url, endpoint.path)}?{param}={payload}"
                        else:
                            url = urljoin(base_url, endpoint.path)
                        
                        async with aiohttp.ClientSession() as session:
                            if endpoint.method == "GET":
                                async with session.get(url, headers=headers, timeout=10) as response:
                                    response_text = await response.text()
                            else:
                                data = {param: payload}
                                async with session.post(url, json=data, headers=headers, timeout=10) as response:
                                    response_text = await response.text()
                            
                            # Check for injection indicators
                            error_indicators = [
                                'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
                                'sqlite', 'mongodb', 'command not found', 'permission denied'
                            ]
                            
                            for indicator in error_indicators:
                                if indicator in response_text.lower():
                                    vulnerabilities.append(APIVulnerability(
                                        severity="High",
                                        category="Injection",
                                        title="Injection Vulnerability Detected",
                                        description=f"Injection payload triggered error: {indicator}",
                                        endpoint=endpoint.path,
                                        method=endpoint.method,
                                        request_details={"parameter": param, "payload": payload},
                                        response_details={"error_indicator": indicator},
                                        cwe_id="CWE-89",
                                        remediation="Use parameterized queries and input validation"
                                    ))
                                    test.passed = False
                                    test.findings.append(f"Injection detected in parameter: {param}")
                    
                    except Exception:
                        continue
                    
                    await asyncio.sleep(delay)
    
    tests.append(test)
    return {"tests": tests, "vulnerabilities": vulnerabilities}

def analyze_owasp_api_top10_compliance(vulnerabilities: List[APIVulnerability], tests: List[SecurityTest]) -> Dict[str, str]:
    """Analyze compliance with OWASP API Security Top 10"""
    compliance = {
        "API1_Broken_Object_Level_Authorization": "PASS",
        "API2_Broken_Authentication": "PASS",
        "API3_Broken_Object_Property_Level_Authorization": "PASS",
        "API4_Unrestricted_Resource_Consumption": "PASS",
        "API5_Broken_Function_Level_Authorization": "PASS",
        "API6_Unrestricted_Access_to_Sensitive_Business_Flows": "PASS",
        "API7_Server_Side_Request_Forgery": "PASS",
        "API8_Security_Misconfiguration": "PASS",
        "API9_Improper_Inventory_Management": "PASS",
        "API10_Unsafe_Consumption_of_APIs": "PASS"
    }
    
    # Mark as FAIL if vulnerabilities found in each category
    for vuln in vulnerabilities:
        if "API1" in vuln.owasp_category or "authorization" in vuln.category.lower():
            compliance["API1_Broken_Object_Level_Authorization"] = "FAIL"
        if "API2" in vuln.owasp_category or "authentication" in vuln.category.lower():
            compliance["API2_Broken_Authentication"] = "FAIL"
        if "API3" in vuln.owasp_category or "data exposure" in vuln.category.lower():
            compliance["API3_Broken_Object_Property_Level_Authorization"] = "FAIL"
        if "injection" in vuln.category.lower():
            compliance["API7_Server_Side_Request_Forgery"] = "FAIL"
    
    return compliance

def calculate_security_score(vulnerabilities: List[APIVulnerability], tests: List[SecurityTest]) -> float:
    """Calculate overall security score"""
    if not tests:
        return 0.0
    
    base_score = 100.0
    
    # Deduct points based on vulnerabilities
    for vuln in vulnerabilities:
        if vuln.severity == "Critical":
            base_score -= 25
        elif vuln.severity == "High":
            base_score -= 15
        elif vuln.severity == "Medium":
            base_score -= 8
        elif vuln.severity == "Low":
            base_score -= 3
    
    # Bonus for passed tests
    passed_tests = len([t for t in tests if t.passed])
    total_tests = len(tests)
    
    if total_tests > 0:
        test_bonus = (passed_tests / total_tests) * 20
        base_score += test_bonus
    
    return max(0.0, min(100.0, base_score))

def determine_risk_rating(vulnerabilities: List[APIVulnerability]) -> str:
    """Determine overall risk rating"""
    critical_count = len([v for v in vulnerabilities if v.severity == "Critical"])
    high_count = len([v for v in vulnerabilities if v.severity == "High"])
    
    if critical_count > 0:
        return "Critical"
    elif high_count > 2:
        return "High"
    elif high_count > 0:
        return "Medium"
    else:
        return "Low"

def generate_recommendations(
    vulnerabilities: List[APIVulnerability],
    tests: List[SecurityTest],
    owasp_compliance: Dict[str, str]
) -> List[str]:
    """Generate security recommendations"""
    recommendations = []
    
    if vulnerabilities:
        recommendations.append("Address all identified vulnerabilities before production deployment")
    
    failed_owasp = [k for k, v in owasp_compliance.items() if v == "FAIL"]
    if failed_owasp:
        recommendations.append(f"Focus on OWASP API Security Top 10 compliance: {', '.join(failed_owasp)}")
    
    recommendations.extend([
        "Implement comprehensive input validation and sanitization",
        "Use parameterized queries to prevent injection attacks",
        "Implement proper authentication and authorization mechanisms",
        "Apply the principle of least privilege for API access",
        "Implement rate limiting and resource consumption controls",
        "Use HTTPS for all API communications",
        "Implement comprehensive logging and monitoring",
        "Regular security testing and code reviews",
        "Keep API documentation up to date and secure"
    ])
    
    return recommendations

# Export tool info for registration
tool_info = TOOL_INFO
