"""HTTP Security Headers Scanner - Real security tool for analyzing HTTP headers."""

import asyncio
import aiohttp
import ssl
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import logging
import re

try:
    from .schemas import HttpSecurityScannerInput, HttpSecurityScannerOutput, SecurityHeader
except ImportError:
    from schemas import HttpSecurityScannerInput, HttpSecurityScannerOutput, SecurityHeader

logger = logging.getLogger(__name__)

# Tool metadata
TOOL_INFO = {
    "name": "http_security_scanner",
    "display_name": "HTTP Security Headers Scanner",
    "description": "Scans web applications for missing or misconfigured security headers that could lead to vulnerabilities",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "web_security"
}

class HttpSecurityScanner:
    """HTTP Security Headers Scanner for analyzing web application security headers."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = None
        
        # Define critical security headers with their descriptions and recommendations
        self.security_headers_config = {
            "Strict-Transport-Security": {
                "severity": "high",
                "description": "Enforces secure HTTPS connections and prevents man-in-the-middle attacks",
                "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            },
            "Content-Security-Policy": {
                "severity": "high",
                "description": "Prevents XSS attacks by controlling which resources can be loaded",
                "recommendation": "Add CSP header with appropriate directives for your application"
            },
            "X-Frame-Options": {
                "severity": "medium",
                "description": "Prevents clickjacking attacks by controlling iframe embedding",
                "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
            },
            "X-Content-Type-Options": {
                "severity": "medium",
                "description": "Prevents MIME type sniffing attacks",
                "recommendation": "Add: X-Content-Type-Options: nosniff"
            },
            "Referrer-Policy": {
                "severity": "medium",
                "description": "Controls how much referrer information is included with requests",
                "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
            },
            "Permissions-Policy": {
                "severity": "low",
                "description": "Controls which browser features can be used by the page",
                "recommendation": "Add Permissions-Policy header to control feature access"
            },
            "X-XSS-Protection": {
                "severity": "low",
                "description": "Legacy XSS filter (mostly superseded by CSP)",
                "recommendation": "Add: X-XSS-Protection: 1; mode=block (though CSP is preferred)"
            }
        }
        
    async def __aenter__(self):
        # Create SSL context that allows self-signed certificates for testing
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector, 
            timeout=timeout,
            headers={"User-Agent": "Wildbox-Security-Scanner/1.0"}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def normalize_url(self, url: str) -> str:
        """Normalize URL by adding protocol if missing."""
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url

    async def fetch_headers(self, url: str, follow_redirects: bool = True) -> Tuple[Dict[str, str], int, str]:
        """Fetch HTTP headers from the given URL."""
        try:
            allow_redirects = follow_redirects
            async with self.session.get(url, allow_redirects=allow_redirects) as response:
                # Convert headers to dict (case-insensitive)
                headers = {k.lower(): v for k, v in response.headers.items()}
                return headers, response.status, str(response.url)
        except Exception as e:
            logger.error(f"Error fetching headers from {url}: {e}")
            raise

    def analyze_security_headers(self, headers: Dict[str, str]) -> List[SecurityHeader]:
        """Analyze the presence and quality of security headers."""
        security_headers = []
        
        for header_name, config in self.security_headers_config.items():
            header_key = header_name.lower()
            present = header_key in headers
            value = headers.get(header_key) if present else None
            
            security_header = SecurityHeader(
                name=header_name,
                value=value,
                present=present,
                severity=config["severity"],
                description=config["description"],
                recommendation=None if present else config["recommendation"]
            )
            
            security_headers.append(security_header)
            
        return security_headers

    def check_additional_vulnerabilities(self, headers: Dict[str, str], url: str) -> List[str]:
        """Check for additional security vulnerabilities in headers."""
        vulnerabilities = []
        
        # Check for server information disclosure
        if 'server' in headers:
            server_value = headers['server']
            if any(tech in server_value.lower() for tech in ['apache', 'nginx', 'iis', 'tomcat']):
                vulnerabilities.append(f"Server information disclosed: {server_value}")
        
        # Check for X-Powered-By header (information disclosure)
        if 'x-powered-by' in headers:
            vulnerabilities.append(f"Technology disclosure via X-Powered-By: {headers['x-powered-by']}")
        
        # Check for weak CSP policies
        if 'content-security-policy' in headers:
            csp = headers['content-security-policy']
            if 'unsafe-inline' in csp:
                vulnerabilities.append("Content Security Policy allows 'unsafe-inline' which reduces XSS protection")
            if 'unsafe-eval' in csp:
                vulnerabilities.append("Content Security Policy allows 'unsafe-eval' which reduces XSS protection")
            if '*' in csp and 'script-src' in csp:
                vulnerabilities.append("Content Security Policy uses wildcard (*) in script-src which is insecure")
        
        # Check for insecure cookies
        if 'set-cookie' in headers:
            cookie_value = headers['set-cookie']
            if 'secure' not in cookie_value.lower() and url.startswith('https'):
                vulnerabilities.append("Cookies missing 'Secure' flag on HTTPS site")
            if 'httponly' not in cookie_value.lower():
                vulnerabilities.append("Cookies missing 'HttpOnly' flag - vulnerable to XSS")
        
        # Check for HSTS issues
        if 'strict-transport-security' in headers:
            hsts = headers['strict-transport-security']
            if 'max-age' not in hsts:
                vulnerabilities.append("HSTS header missing max-age directive")
            else:
                # Extract max-age value
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        vulnerabilities.append(f"HSTS max-age too low: {max_age} seconds (recommended: 31536000+)")
        
        return vulnerabilities

    def generate_recommendations(self, security_headers: List[SecurityHeader], vulnerabilities: List[str]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Add recommendations for missing headers
        missing_critical = [h for h in security_headers if not h.present and h.severity in ['high', 'critical']]
        missing_medium = [h for h in security_headers if not h.present and h.severity == 'medium']
        
        if missing_critical:
            recommendations.append("CRITICAL: Implement missing high-priority security headers immediately")
            for header in missing_critical:
                if header.recommendation:
                    recommendations.append(f"• {header.recommendation}")
        
        if missing_medium:
            recommendations.append("MEDIUM: Consider implementing these additional security headers")
            for header in missing_medium:
                if header.recommendation:
                    recommendations.append(f"• {header.recommendation}")
        
        # Add specific recommendations based on vulnerabilities
        if any('unsafe-inline' in vuln for vuln in vulnerabilities):
            recommendations.append("Remove 'unsafe-inline' from Content Security Policy and use nonces or hashes")
        
        if any('Server information' in vuln for vuln in vulnerabilities):
            recommendations.append("Configure server to hide version information")
        
        if any('X-Powered-By' in vuln for vuln in vulnerabilities):
            recommendations.append("Remove or customize X-Powered-By header to prevent technology disclosure")
        
        if any('Secure' in vuln for vuln in vulnerabilities):
            recommendations.append("Add 'Secure' flag to all cookies on HTTPS sites")
        
        if any('HttpOnly' in vuln for vuln in vulnerabilities):
            recommendations.append("Add 'HttpOnly' flag to cookies to prevent XSS access")
        
        return recommendations

    def calculate_security_score(self, security_headers: List[SecurityHeader], vulnerabilities: List[str]) -> int:
        """Calculate a security score out of 100."""
        base_score = 100
        
        # Deduct points for missing headers
        for header in security_headers:
            if not header.present:
                if header.severity == 'critical':
                    base_score -= 25
                elif header.severity == 'high':
                    base_score -= 15
                elif header.severity == 'medium':
                    base_score -= 10
                elif header.severity == 'low':
                    base_score -= 5
        
        # Deduct points for vulnerabilities
        base_score -= len(vulnerabilities) * 5
        
        return max(0, base_score)

    async def scan_additional_paths(self, base_url: str) -> Dict[str, Any]:
        """Scan additional common paths for security headers."""
        common_paths = ['/admin', '/api', '/login', '/dashboard', '/wp-admin']
        path_results = {}
        
        for path in common_paths:
            try:
                test_url = urllib.parse.urljoin(base_url, path)
                headers, status, final_url = await self.fetch_headers(test_url, follow_redirects=False)
                path_results[path] = {
                    'status': status,
                    'headers_count': len(headers),
                    'has_security_headers': any(h in headers for h in ['strict-transport-security', 'content-security-policy'])
                }
            except Exception:
                path_results[path] = {'status': 'error', 'headers_count': 0, 'has_security_headers': False}
        
        return path_results


async def execute_tool(input_data: HttpSecurityScannerInput) -> HttpSecurityScannerOutput:
    """Execute the HTTP Security Headers Scanner."""
    start_time = datetime.now()
    
    try:
        # Normalize the URL
        normalized_url = HttpSecurityScanner(input_data.timeout).normalize_url(input_data.url)
        
        async with HttpSecurityScanner(input_data.timeout) as scanner:
            # Fetch headers from the main URL
            headers, http_status, final_url = await scanner.fetch_headers(
                normalized_url, 
                input_data.follow_redirects
            )
            
            # Analyze security headers
            security_headers = scanner.analyze_security_headers(headers)
            
            # Check for additional vulnerabilities
            vulnerabilities = scanner.check_additional_vulnerabilities(headers, normalized_url)
            
            # Generate recommendations
            recommendations = scanner.generate_recommendations(security_headers, vulnerabilities)
            
            # Calculate security score
            security_score = scanner.calculate_security_score(security_headers, vulnerabilities)
            
            # Get missing headers list
            missing_headers = [h.name for h in security_headers if not h.present]
            
            # Scan additional paths if requested
            additional_paths = {}
            if input_data.check_subpaths:
                additional_paths = await scanner.scan_additional_paths(normalized_url)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Create findings summary
            findings = {
                "total_headers_checked": len(security_headers),
                "present_headers_count": len([h for h in security_headers if h.present]),
                "missing_headers_count": len(missing_headers),
                "vulnerabilities_count": len(vulnerabilities),
                "security_score": security_score,
                "scan_method": "HTTP headers analysis",
                "final_url": final_url,
                "http_status": http_status,
                "additional_info": f"Scan completed successfully in {duration:.2f} seconds"
            }
            
            if additional_paths:
                findings["additional_paths_scanned"] = additional_paths
            
            return HttpSecurityScannerOutput(
                url=input_data.url,
                timestamp=start_time,
                duration=duration,
                status="success",
                http_status=http_status,
                security_headers=security_headers,
                missing_headers=missing_headers,
                vulnerabilities=vulnerabilities,
                recommendations=recommendations,
                security_score=security_score,
                findings=findings
            )
            
    except Exception as e:
        logger.error(f"HTTP security scan failed: {e}")
        duration = (datetime.now() - start_time).total_seconds()
        
        return HttpSecurityScannerOutput(
            url=input_data.url,
            timestamp=start_time,
            duration=duration,
            status="error",
            http_status=None,
            security_headers=[],
            missing_headers=[],
            vulnerabilities=[f"Scan error: {str(e)}"],
            recommendations=["Check URL accessibility and try again"],
            security_score=0,
            findings={
                "error": str(e),
                "additional_info": "Scan failed due to error"
            }
        )
