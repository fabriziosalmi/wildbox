"""
Cookie Security Scanner - Analyzes HTTP cookies for security misconfigurations.
"""

import asyncio
import aiohttp
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

try:
    from schemas import CookieScannerInput, CookieScannerOutput
except ImportError:
    from app.tools.cookie_scanner.schemas import CookieScannerInput, CookieScannerOutput

logger = logging.getLogger(__name__)


class CookieSecurityScanner:
    """Scanner for analyzing HTTP cookie security attributes."""
    
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=30)
    
    async def scan_cookies(self, url: str, follow_redirects: bool = True) -> Dict[str, Any]:
        """
        Scan cookies from the given URL and analyze their security attributes.
        
        Args:
            url: The URL to scan for cookies
            follow_redirects: Whether to follow HTTP redirects
            
        Returns:
            Dictionary containing cookie analysis results
        """
        results = {
            "url": url,
            "cookies": [],
            "security_summary": {
                "total_cookies": 0,
                "secure_cookies": 0,
                "httponly_cookies": 0,
                "samesite_cookies": 0,
                "cookies_with_expiry": 0,
                "insecure_cookies": 0
            },
            "vulnerabilities": [],
            "recommendations": []
        }
        
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout
            ) as session:
                # Make request and capture response headers
                async with session.get(
                    url,
                    allow_redirects=follow_redirects
                ) as response:
                    # Extract cookies from Set-Cookie headers
                    set_cookie_headers = response.headers.getall('Set-Cookie', [])
                    
                    for cookie_header in set_cookie_headers:
                        cookie_info = self._parse_cookie_header(cookie_header)
                        if cookie_info:
                            results["cookies"].append(cookie_info)
                    
                    # Analyze cookies and generate security summary
                    self._analyze_cookies(results)
                    
        except asyncio.TimeoutError:
            logger.error(f"Timeout scanning cookies for {url}")
            results["error"] = "Request timeout"
        except aiohttp.ClientError as e:
            logger.error(f"Client error scanning cookies for {url}: {e}")
            results["error"] = f"Client error: {str(e)}"
        except Exception as e:
            logger.error(f"Error scanning cookies for {url}: {e}")
            results["error"] = f"Unexpected error: {str(e)}"
        
        return results
    
    def _parse_cookie_header(self, cookie_header: str) -> Optional[Dict[str, Any]]:
        """Parse a Set-Cookie header and extract cookie attributes."""
        try:
            # Split cookie header into parts
            parts = [part.strip() for part in cookie_header.split(';')]
            if not parts:
                return None
            
            # First part is name=value
            name_value = parts[0].split('=', 1)
            if len(name_value) != 2:
                return None
            
            cookie_name, cookie_value = name_value
            
            cookie_info = {
                "name": cookie_name.strip(),
                "value": cookie_value.strip(),
                "attributes": {},
                "security_flags": {
                    "secure": False,
                    "httponly": False,
                    "samesite": None,
                    "has_expiry": False
                },
                "issues": []
            }
            
            # Parse attributes
            for part in parts[1:]:
                if '=' in part:
                    attr_name, attr_value = part.split('=', 1)
                    attr_name = attr_name.strip().lower()
                    attr_value = attr_value.strip()
                    cookie_info["attributes"][attr_name] = attr_value
                    
                    # Check for security attributes
                    if attr_name == "samesite":
                        cookie_info["security_flags"]["samesite"] = attr_value.lower()
                    elif attr_name in ["expires", "max-age"]:
                        cookie_info["security_flags"]["has_expiry"] = True
                else:
                    attr_name = part.strip().lower()
                    cookie_info["attributes"][attr_name] = True
                    
                    # Check for security flags
                    if attr_name == "secure":
                        cookie_info["security_flags"]["secure"] = True
                    elif attr_name == "httponly":
                        cookie_info["security_flags"]["httponly"] = True
            
            # Identify security issues
            self._identify_cookie_issues(cookie_info)
            
            return cookie_info
            
        except Exception as e:
            logger.error(f"Error parsing cookie header: {e}")
            return None
    
    def _identify_cookie_issues(self, cookie_info: Dict[str, Any]) -> None:
        """Identify security issues with a cookie."""
        flags = cookie_info["security_flags"]
        issues = []
        
        # Check for missing Secure flag
        if not flags["secure"]:
            issues.append({
                "severity": "medium",
                "issue": "Missing Secure flag",
                "description": "Cookie can be transmitted over unencrypted HTTP connections"
            })
        
        # Check for missing HttpOnly flag
        if not flags["httponly"]:
            issues.append({
                "severity": "medium",
                "issue": "Missing HttpOnly flag",
                "description": "Cookie is accessible via JavaScript, vulnerable to XSS attacks"
            })
        
        # Check for missing SameSite attribute
        if flags["samesite"] is None:
            issues.append({
                "severity": "low",
                "issue": "Missing SameSite attribute",
                "description": "Cookie vulnerable to CSRF attacks"
            })
        elif flags["samesite"] == "none" and not flags["secure"]:
            issues.append({
                "severity": "high",
                "issue": "SameSite=None without Secure",
                "description": "SameSite=None requires Secure flag for cross-site requests"
            })
        
        # Check for missing expiry
        if not flags["has_expiry"]:
            issues.append({
                "severity": "low",
                "issue": "Session cookie without expiry",
                "description": "Cookie persists until browser closes, consider adding expiry"
            })
        
        # Check for sensitive-looking cookie names without proper protection
        sensitive_names = ["session", "auth", "token", "login", "user", "admin"]
        if any(name in cookie_info["name"].lower() for name in sensitive_names):
            if not flags["secure"] or not flags["httponly"]:
                issues.append({
                    "severity": "high",
                    "issue": "Potentially sensitive cookie lacks protection",
                    "description": "Cookie appears to contain sensitive data but lacks proper security flags"
                })
        
        cookie_info["issues"] = issues
    
    def _analyze_cookies(self, results: Dict[str, Any]) -> None:
        """Analyze all cookies and generate security summary."""
        summary = results["security_summary"]
        vulnerabilities = []
        recommendations = []
        
        summary["total_cookies"] = len(results["cookies"])
        
        for cookie in results["cookies"]:
            flags = cookie["security_flags"]
            
            if flags["secure"]:
                summary["secure_cookies"] += 1
            if flags["httponly"]:
                summary["httponly_cookies"] += 1
            if flags["samesite"]:
                summary["samesite_cookies"] += 1
            if flags["has_expiry"]:
                summary["cookies_with_expiry"] += 1
            if cookie["issues"]:
                summary["insecure_cookies"] += 1
                
                # Collect high-severity issues as vulnerabilities
                for issue in cookie["issues"]:
                    if issue["severity"] == "high":
                        vulnerabilities.append({
                            "cookie": cookie["name"],
                            "vulnerability": issue["issue"],
                            "description": issue["description"]
                        })
        
        # Generate recommendations
        if summary["secure_cookies"] < summary["total_cookies"]:
            recommendations.append("Add 'Secure' flag to all cookies to prevent transmission over HTTP")
        
        if summary["httponly_cookies"] < summary["total_cookies"]:
            recommendations.append("Add 'HttpOnly' flag to prevent JavaScript access and XSS attacks")
        
        if summary["samesite_cookies"] < summary["total_cookies"]:
            recommendations.append("Add 'SameSite' attribute to prevent CSRF attacks")
        
        if vulnerabilities:
            recommendations.append("Address high-severity cookie security issues immediately")
        
        results["vulnerabilities"] = vulnerabilities
        results["recommendations"] = recommendations


async def scan_cookies(request: CookieScannerInput) -> CookieScannerOutput:
    """
    Main function to scan cookies for security issues.
    
    Args:
        request: CookieScannerInput object containing scan parameters
        
    Returns:
        CookieScannerOutput object containing scan results
    """
    scanner = CookieSecurityScanner()
    
    try:
        # Perform cookie scan
        results = await scanner.scan_cookies(
            url=request.url,
            follow_redirects=request.follow_redirects
        )
        
        return CookieScannerOutput(
            success=True,
            target_url=results["url"],
            timestamp=datetime.now(),
            total_cookies=results["security_summary"]["total_cookies"],
            secure_cookies=results["security_summary"]["secure_cookies"],
            insecure_cookies=results["security_summary"]["insecure_cookies"],
            cookies=[],  # Would need to convert to CookieAnalysis objects
            overall_security_score=100 - results["security_summary"]["insecure_cookies"] * 10,  # Simple scoring
            recommendations=results["recommendations"],
            message="Cookie security scan completed successfully"
        )
        
    except Exception as e:
        logger.error(f"Cookie scan failed: {e}")
        return CookieScannerOutput(
            success=False,
            target_url=request.target_url,
            timestamp=datetime.now(),
            total_cookies=0,
            secure_cookies=0,
            insecure_cookies=0,
            cookies=[],
            overall_security_score=0,
            recommendations=[],
            message="Cookie security scan failed",
            error=f"Cookie scan failed: {str(e)}"
        )


async def execute_tool(input_data: CookieScannerInput) -> CookieScannerOutput:
    """Main entry point for the cookie scanner tool"""
    return await scan_cookies(input_data)

# Tool metadata
TOOL_INFO = {
    "name": "cookie_scanner",
    "display_name": "Cookie Security Scanner",
    "description": "Analyzes HTTP cookies for security misconfigurations and vulnerabilities",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "web_security"
}
