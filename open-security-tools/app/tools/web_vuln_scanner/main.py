"""Web vulnerability scanner tool implementation."""

import asyncio
import aiohttp
import ssl
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List
import logging

from ...utils.tool_utils import RateLimiter
from ...safe_http import guarded_session
from ...utils.tls import certificate_error_message, client_ssl
from ...tool_config import ToolConfig
from ...tool_errors import RUN_ERRORS
from ...log_safety import host_of
from .schemas import (
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


async def check_security_headers(url: str, rate_limiter: RateLimiter = None,
                                 verify_ssl: bool = True) -> List[SecurityHeader]:
    """Check for security headers in HTTP response.

    A TLS certificate verification failure is re-raised, not logged and
    swallowed: the caller reports it instead of an empty header list.
    """
    security_headers = []
    
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        # Guarded: non-public targets are refused on every connection,
        # redirect hops included.
        async with guarded_session(ssl=client_ssl(verify_ssl), timeout=timeout) as session:
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
                    
    except aiohttp.ClientConnectorCertificateError:
        raise
    except RUN_ERRORS as e:
        logger.error(f"Error checking security headers: {type(e).__name__}")
        
    return security_headers


async def scan_for_vulnerabilities(url: str, scan_depth: ScanDepth, rate_limiter: RateLimiter = None,
                                   verify_ssl: bool = True) -> List[VulnerabilityFinding]:
    """Scan for common web vulnerabilities."""
    vulnerabilities = []
    
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        # Guarded: non-public targets are refused on every connection,
        # redirect hops included.
        async with guarded_session(ssl=client_ssl(verify_ssl), timeout=timeout) as session:
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
                except aiohttp.ClientConnectorCertificateError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
                    logger.error(f"Error testing XSS on {host_of(url)}: {type(e).__name__}")
                    pass
            
            # Test for SQL injection indicators
            sql_payloads = ["'", "1' OR '1'='1"]
            for payload in sql_payloads:
                test_url = f"{url}?id={urllib.parse.quote(payload)}"
                try:
                    async with session.get(test_url) as response:
                        # Parenthesised: `await response.text().lower()` calls
                        # .lower() on the coroutine and raised AttributeError,
                        # so this check never reported anything (#507).
                        content = (await response.text()).lower()
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
                except aiohttp.ClientConnectorCertificateError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
                    logger.error(f"Error testing SQL injection on {host_of(test_url)}: {type(e).__name__}")
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
                except aiohttp.ClientConnectorCertificateError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
                    logger.error(f"Error testing information disclosure on {host_of(test_url)}: {type(e).__name__}")
                    pass
                    
    except aiohttp.ClientConnectorCertificateError:
        raise
    except RUN_ERRORS as e:
        logger.error(f"Error during vulnerability scanning: {type(e).__name__}")
        
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
    
    try:
        # Get security headers
        security_headers = await check_security_headers(
            input_data.target_url, rate_limiter, verify_ssl=input_data.verify_ssl
        )

        # Scan for vulnerabilities
        vulnerabilities = await scan_for_vulnerabilities(
            input_data.target_url, input_data.scan_depth, rate_limiter,
            verify_ssl=input_data.verify_ssl
        )
    except aiohttp.ClientConnectorCertificateError as e:
        # Reported as-is. There is no fallback to an unverified connection.
        message = certificate_error_message(e, input_data.target_url)
        logger.warning(f"TLS certificate could not be verified for {host_of(input_data.target_url)}")
        return WebVulnScannerOutput(
            success=False,
            error_message=message,
            target_url=input_data.target_url,
            scan_depth=input_data.scan_depth.value,
            timestamp=start_time,
            duration=(datetime.now() - start_time).total_seconds(),
            status="tls_verification_failed",
            pages_scanned=0,
            ssl_info={"enabled": True, "verified": False, "error": message},
        )
    
    # Check SSL info
    ssl_info = await check_ssl_info(input_data.target_url, rate_limiter)
    if ssl_info.get("enabled"):
        # Record whether the results came over a verified connection.
        ssl_info["verified"] = input_data.verify_ssl
        if not input_data.verify_ssl:
            ssl_info["note"] = "Certificate verification was disabled for this scan (verify_ssl=false)"
    
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
        success=True,
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
