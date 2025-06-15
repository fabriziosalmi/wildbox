"""Web vulnerability scanner tool implementation."""

import asyncio
import random
import ssl
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List

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


# Tool metadata
TOOL_INFO = {
    "name": "web_vuln_scanner",
    "display_name": "Web Vulnerability Scanner",
    "description": "Comprehensive web application security scanner that detects common vulnerabilities and security misconfigurations",
    "version": "2.1.0",
    "author": "Wildbox Security Team",
    "category": "web_security"
}


async def check_security_headers(url: str) -> List[SecurityHeader]:
    """Simulate security headers analysis."""
    await asyncio.sleep(random.uniform(0.5, 1.5))
    
    headers_to_check = [
        {
            "header": "Content-Security-Policy",
            "present": random.choice([True, False]),
            "recommendation": "Implement CSP to prevent XSS attacks"
        },
        {
            "header": "X-Frame-Options",
            "present": random.choice([True, False]),
            "recommendation": "Prevent clickjacking attacks"
        },
        {
            "header": "X-Content-Type-Options",
            "present": random.choice([True, False]),
            "recommendation": "Prevent MIME type sniffing"
        },
        {
            "header": "Strict-Transport-Security",
            "present": random.choice([True, False]),
            "recommendation": "Enforce HTTPS connections"
        },
        {
            "header": "Referrer-Policy",
            "present": random.choice([True, False]),
            "recommendation": "Control referrer information leakage"
        }
    ]
    
    security_headers = []
    for header_info in headers_to_check:
        header = SecurityHeader(
            header=header_info["header"],
            present=header_info["present"],
            value=f"strict-origin-when-cross-origin" if header_info["present"] else None,
            recommendation=header_info["recommendation"]
        )
        security_headers.append(header)
    
    return security_headers


async def scan_for_vulnerabilities(url: str, scan_depth: ScanDepth, max_pages: int) -> List[VulnerabilityFinding]:
    """Simulate vulnerability scanning."""
    
    # Simulate scanning time based on depth
    scan_time = {
        ScanDepth.SURFACE: random.uniform(1, 3),
        ScanDepth.STANDARD: random.uniform(3, 8),
        ScanDepth.DEEP: random.uniform(8, 15)
    }
    await asyncio.sleep(scan_time[scan_depth])
    
    # Potential vulnerabilities database
    potential_vulns = [
        {
            "id": "XSS-001",
            "title": "Reflected Cross-Site Scripting (XSS)",
            "description": "User input is reflected in the response without proper sanitization",
            "severity": VulnerabilityLevel.HIGH,
            "evidence": "<script>alert('XSS')</script>",
            "remediation": "Implement input validation and output encoding"
        },
        {
            "id": "SQLi-002",
            "title": "SQL Injection Vulnerability",
            "description": "Application may be vulnerable to SQL injection attacks",
            "severity": VulnerabilityLevel.CRITICAL,
            "evidence": "Error: mysql_fetch_array() expects parameter 1",
            "remediation": "Use parameterized queries and input validation"
        },
        {
            "id": "DIR-003",
            "title": "Directory Traversal",
            "description": "Possible directory traversal vulnerability detected",
            "severity": VulnerabilityLevel.MEDIUM,
            "evidence": "../../etc/passwd accessible",
            "remediation": "Implement proper file path validation"
        },
        {
            "id": "INFO-004",
            "title": "Information Disclosure",
            "description": "Sensitive information exposed in error messages",
            "severity": VulnerabilityLevel.LOW,
            "evidence": "Database connection string visible",
            "remediation": "Configure custom error pages"
        },
        {
            "id": "CSRF-005",
            "title": "Cross-Site Request Forgery",
            "description": "Forms lack CSRF protection tokens",
            "severity": VulnerabilityLevel.MEDIUM,
            "evidence": "No anti-CSRF token found in form",
            "remediation": "Implement CSRF tokens in all forms"
        }
    ]
    
    # Randomly select vulnerabilities based on scan depth
    num_vulns = {
        ScanDepth.SURFACE: random.randint(0, 2),
        ScanDepth.STANDARD: random.randint(1, 3),
        ScanDepth.DEEP: random.randint(2, 5)
    }
    
    found_vulns = random.sample(potential_vulns, min(num_vulns[scan_depth], len(potential_vulns)))
    
    vulnerabilities = []
    for vuln in found_vulns:
        vulnerability = VulnerabilityFinding(
            id=vuln["id"],
            title=vuln["title"],
            description=vuln["description"],
            severity=vuln["severity"],
            url=f"{url}/vulnerable-page",
            evidence=vuln["evidence"],
            remediation=vuln["remediation"]
        )
        vulnerabilities.append(vulnerability)
    
    return vulnerabilities


async def analyze_ssl(url: str) -> Dict[str, Any]:
    """Simulate SSL/TLS analysis."""
    await asyncio.sleep(random.uniform(0.3, 1.0))
    
    if not url.startswith('https://'):
        return {"error": "HTTPS not detected", "recommendation": "Enable HTTPS with valid SSL certificate"}
    
    return {
        "certificate_valid": random.choice([True, False]),
        "expires_in_days": random.randint(30, 365),
        "issuer": "Let's Encrypt Authority X3",
        "protocol_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "vulnerabilities": random.choice([[], ["Weak cipher detected"]])
    }


async def execute_tool(input_data: WebVulnScannerInput) -> WebVulnScannerOutput:
    """Execute the web vulnerability scanner."""
    start_time = datetime.now()
    
    try:
        # Parse and validate URL
        parsed_url = urllib.parse.urlparse(input_data.target_url)
        if not parsed_url.scheme:
            raise ValueError("Invalid URL: scheme required")
        
        # Simulate page crawling
        pages_to_scan = min(input_data.max_pages, 
                          {ScanDepth.SURFACE: 5, ScanDepth.STANDARD: 25, ScanDepth.DEEP: 50}[input_data.scan_depth])
        
        # Perform scans
        tasks = []
        
        # Vulnerability scanning
        tasks.append(scan_for_vulnerabilities(input_data.target_url, input_data.scan_depth, pages_to_scan))
        
        # Security headers check
        if input_data.check_headers:
            tasks.append(check_security_headers(input_data.target_url))
        
        # SSL analysis
        ssl_task = None
        if input_data.check_ssl:
            ssl_task = analyze_ssl(input_data.target_url)
            tasks.append(ssl_task)
        
        # Execute all tasks
        results = await asyncio.gather(*tasks)
        
        vulnerabilities = results[0]
        security_headers = results[1] if input_data.check_headers else []
        ssl_info = results[2] if input_data.check_ssl else {}
        
        # Calculate summary
        summary = {
            "critical": len([v for v in vulnerabilities if v.severity == VulnerabilityLevel.CRITICAL]),
            "high": len([v for v in vulnerabilities if v.severity == VulnerabilityLevel.HIGH]),
            "medium": len([v for v in vulnerabilities if v.severity == VulnerabilityLevel.MEDIUM]),
            "low": len([v for v in vulnerabilities if v.severity == VulnerabilityLevel.LOW])
        }
        
        # Generate recommendations
        recommendations = []
        if summary["critical"] > 0:
            recommendations.append("Address critical vulnerabilities immediately")
        if not any(h.present for h in security_headers):
            recommendations.append("Implement security headers to improve overall security posture")
        if ssl_info.get("vulnerabilities"):
            recommendations.append("Update SSL/TLS configuration to use stronger ciphers")
        if not recommendations:
            recommendations.append("Maintain current security practices and perform regular scans")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return WebVulnScannerOutput(
            target_url=input_data.target_url,
            scan_depth=input_data.scan_depth.value,
            timestamp=start_time,
            duration=duration,
            status="completed",
            pages_scanned=pages_to_scan,
            vulnerabilities=vulnerabilities,
            security_headers=security_headers,
            ssl_info=ssl_info,
            summary=summary,
            recommendations=recommendations
        )
        
    except Exception as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return WebVulnScannerOutput(
            target_url=input_data.target_url,
            scan_depth=input_data.scan_depth.value,
            timestamp=start_time,
            duration=duration,
            status=f"failed: {str(e)}",
            pages_scanned=0,
            vulnerabilities=[],
            security_headers=[],
            ssl_info={},
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
            recommendations=["Fix scan errors and retry"]
        )


# Alias for the main execution function
run = execute_tool
