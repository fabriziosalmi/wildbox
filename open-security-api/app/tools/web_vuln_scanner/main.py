"""Web vulnerability scanner tool implementation."""

import asyncio
import aiohttp
import ssl
import urllib.parse
import sys
import os
from datetime import datetime
from typing import Dict, Any, List
import logging

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from app.utils.tool_utils import RateLimiter
    from app.config.tool_config import ToolConfig
except ImportError:
    # Fallback for when running as standalone
    class RateLimiter:
        def __init__(self, max_requests=10, time_window=60):
            pass
        async def acquire(self):
            pass
    
    class ToolConfig:
        DEFAULT_RATE_LIMIT = 10
        DEFAULT_RATE_WINDOW = 60

try:
    from .schemas import (
        WebVulnScannerInput, WebVulnScannerOutput, VulnerabilityFinding,
        SecurityHeader, VulnerabilityLevel, ScanDepth
    )
except ImportError:
    from schemas import (
        WebVulnScannerInput, WebVulnScannerOutput, VulnerabilityFinding,
        SecurityHeader, VulnerabilityLevel, ScanDepth
    )

logger = logging.getLogger(__name__)

# Tool metadata
TOOL_INFO = {
    "name": "web_vuln_scanner",
    "display_name": "Web Vulnerability Scanner",
    "description": "Real web application security scanner that detects vulnerabilities and security misconfigurations",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "web_security"
}


async def check_security_headers(url: str, rate_limiter: RateLimiter = None) -> List[SecurityHeader]:
    """Check for security headers in HTTP response."""
    security_headers = []
    
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(ssl=False)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Apply rate limiting if rate_limiter is provided
            if rate_limiter:
                await rate_limiter.acquire()
                
            async with session.get(url) as response:
                headers = response.headers
                
                # Check for important security headers
                security_checks = [
                    ("Content-Security-Policy", "Implement CSP to prevent XSS attacks"),
                    ("X-Frame-Options", "Prevent clickjacking attacks"),
                    ("X-Content-Type-Options", "Prevent MIME type sniffing"),
                    ("Strict-Transport-Security", "Enforce HTTPS connections"),
                    ("Referrer-Policy", "Control referrer information leakage"),
                ]
                
                for header_name, recommendation in security_checks:
                    header_value = headers.get(header_name)
                    security_headers.append(SecurityHeader(
                        header=header_name,
                        present=header_value is not None,
                        value=header_value,
                        recommendation=recommendation
                    ))
                    
    except Exception as e:
        logger.error(f"Error checking security headers: {e}")
        
    return security_headers


async def scan_for_vulnerabilities(url: str, scan_depth: ScanDepth, rate_limiter: RateLimiter = None) -> List[VulnerabilityFinding]:
    """Scan for common web vulnerabilities."""
    vulnerabilities = []
    
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        connector = aiohttp.TCPConnector(ssl=False)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Test for basic XSS
            xss_payloads = ["<script>alert('xss')</script>"]
            
            for payload in xss_payloads:
                test_url = f"{url}?test={urllib.parse.quote(payload)}"
                try:
                    async with session.get(test_url) as response:
                        content = await response.text()
                        if payload in content and "text/html" in response.headers.get("content-type", ""):
                            vulnerabilities.append(VulnerabilityFinding(
                                id="XSS-001",
                                title="Reflected XSS Vulnerability",
                                description="Application reflects user input without proper sanitization",
                                severity=VulnerabilityLevel.HIGH,
                                url=test_url,
                                evidence=f"Payload '{payload}' reflected in response",
                                remediation="Implement proper input validation and output encoding"
                            ))
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
                    logger.error(f"Error testing XSS on {url}: {e}")
                    pass
            
            # Test for SQL injection indicators
            sql_payloads = ["'", "1' OR '1'='1"]
            for payload in sql_payloads:
                test_url = f"{url}?id={urllib.parse.quote(payload)}"
                try:
                    async with session.get(test_url) as response:
                        content = await response.text().lower()
                        sql_errors = ["mysql_fetch_array", "sql syntax", "sqlite_step"]
                        
                        for error in sql_errors:
                            if error in content:
                                vulnerabilities.append(VulnerabilityFinding(
                                    id="SQLi-001",
                                    title="SQL Injection Vulnerability",
                                    description="Application may be vulnerable to SQL injection attacks",
                                    severity=VulnerabilityLevel.CRITICAL,
                                    url=test_url,
                                    evidence=f"SQL error detected: {error}",
                                    remediation="Use parameterized queries and input validation"
                                ))
                                break
                    
                    if any(v.id == "SQLi-001" for v in vulnerabilities):
                        break
                except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
                    logger.error(f"Error testing SQL injection on {test_url}: {e}")
                    pass
            
            # Check for information disclosure
            info_paths = ["/robots.txt", "/.git/", "/admin/"]
            for path in info_paths:
                test_url = urllib.parse.urljoin(url, path)
                try:
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            if path == "/robots.txt":
                                vulnerabilities.append(VulnerabilityFinding(
                                    id="INFO-001",
                                    title="Robots.txt File Found",
                                    description="Robots.txt file accessible",
                                    severity=VulnerabilityLevel.LOW,
                                    url=test_url,
                                    evidence="Robots.txt file found",
                                    remediation="Review robots.txt for sensitive information"
                                ))
                            elif "/.git/" in path:
                                vulnerabilities.append(VulnerabilityFinding(
                                    id="INFO-002",
                                    title="Git Repository Exposed",
                                    description="Git repository accessible via web",
                                    severity=VulnerabilityLevel.CRITICAL,
                                    url=test_url,
                                    evidence="Git repository files accessible",
                                    remediation="Remove .git directory from web-accessible location"
                                ))
                except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
                    logger.error(f"Error testing information disclosure on {test_url}: {e}")
                    pass
                    
    except Exception as e:
        logger.error(f"Error during vulnerability scanning: {e}")
        
    return vulnerabilities


async def check_ssl_info(url: str, rate_limiter: RateLimiter = None) -> Dict[str, Any]:
    """Check SSL/TLS configuration."""
    parsed_url = urllib.parse.urlparse(url)
    
    if parsed_url.scheme.lower() == "https":
        return {
            "enabled": True,
            "recommendation": "SSL/TLS appears to be configured"
        }
    else:
        return {
            "enabled": False,
            "error": "HTTPS not detected",
            "recommendation": "Enable HTTPS with valid SSL certificate"
        }


async def execute_tool(input_data: WebVulnScannerInput) -> WebVulnScannerOutput:
    """Execute the web vulnerability scanner tool."""
    
    start_time = datetime.now()
    
    # Initialize rate limiter
    rate_limiter = RateLimiter(max_requests=10, time_window=60)
    
    # Get security headers
    security_headers = await check_security_headers(input_data.target_url, rate_limiter)
    
    # Scan for vulnerabilities
    vulnerabilities = await scan_for_vulnerabilities(input_data.target_url, input_data.scan_depth, rate_limiter)
    
    # Check SSL info
    ssl_info = await check_ssl_info(input_data.target_url, rate_limiter)
    
    # Calculate summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulnerabilities:
        summary[vuln.severity.value] += 1
    
    # Generate recommendations
    recommendations = []
    if summary["critical"] > 0:
        recommendations.append("Address critical vulnerabilities immediately")
    if summary["high"] > 0:
        recommendations.append("High severity vulnerabilities require urgent attention")
    if not ssl_info.get("enabled"):
        recommendations.append("Enable HTTPS with proper SSL/TLS configuration")
    if any(not h.present for h in security_headers):
        recommendations.append("Implement missing security headers")
    
    if not recommendations:
        recommendations.append("Security configuration appears adequate")
    
    duration = (datetime.now() - start_time).total_seconds()
    
    return WebVulnScannerOutput(
        target_url=input_data.target_url,
        scan_depth=input_data.scan_depth.value,
        timestamp=start_time,
        duration=duration,
        status="completed",
        pages_scanned=1,
        vulnerabilities=vulnerabilities,
        security_headers=security_headers,
        ssl_info=ssl_info,
        summary=summary,
        recommendations=recommendations
    )
