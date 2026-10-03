"""
HTTP Header Security Analyzer Tool

This tool analyzes HTTP response headers for security misconfigurations and vulnerabilities.
It checks for missing security headers, weak configurations, and provides recommendations.
"""

import asyncio
import aiohttp
import ssl
import sys
import os
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ...utils.tool_utils import RateLimiter
from ...tool_config import ToolConfig
from ...input_validation import InputSanitizer
from ...safe_http import guarded_session
from ...tool_errors import RUN_ERRORS, ToolRunError
from .schemas import HeaderAnalysis, HeaderAnalyzerInput, HeaderAnalyzerOutput, SecurityHeaderInfo
# Tool metadata
TOOL_INFO = {
    "name": "header_analyzer",
    "display_name": "HTTP Header Security Analyzer",
    "description": "Analyzes HTTP response headers for security misconfigurations and vulnerabilities",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "web_security"
}


class HeaderSecurityAnalyzer:
    """HTTP Header Security Analyzer"""
    
    SECURITY_HEADERS = {
        'strict-transport-security': {
            'name': 'HTTP Strict Transport Security (HSTS)',
            'critical': True,
            'description': 'Prevents protocol downgrade attacks and cookie hijacking'
        },
        'content-security-policy': {
            'name': 'Content Security Policy (CSP)',
            'critical': True,
            'description': 'Prevents XSS attacks by controlling resource loading'
        },
        'x-frame-options': {
            'name': 'X-Frame-Options',
            'critical': True,
            'description': 'Prevents clickjacking attacks'
        },
        'x-content-type-options': {
            'name': 'X-Content-Type-Options',
            'critical': True,
            'description': 'Prevents MIME type confusion attacks'
        },
        'referrer-policy': {
            'name': 'Referrer Policy',
            'critical': False,
            'description': 'Controls how much referrer information is shared'
        },
        'permissions-policy': {
            'name': 'Permissions Policy',
            'critical': False,
            'description': 'Controls access to browser features and APIs'
        },
        'x-xss-protection': {
            'name': 'X-XSS-Protection',
            'critical': False,
            'description': 'Legacy XSS protection (mostly deprecated)'
        },
        'expect-ct': {
            'name': 'Expect-CT',
            'critical': False,
            'description': 'Certificate Transparency monitoring'
        }
    }
    
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=30)
        # Initialize rate limiter for external requests
        self.rate_limiter = RateLimiter(max_requests=10, time_window=60)
    
    async def analyze_headers(self, url: str, follow_redirects: bool = True) -> Dict[str, Any]:
        """Analyze HTTP headers for security issues"""
        try:
            # Validate URL
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")

            # SSRF protection: the shared guard checks the URL (every address
            # the host resolves to must be public), and the guarded session
            # checks every connection again, redirect hops included.
            InputSanitizer.validate_url(url)

            async with guarded_session(timeout=self.timeout) as session:
                # Apply rate limiting before making external request
                await self.rate_limiter.acquire()
                
                # Make request
                async with session.get(
                    url,
                    allow_redirects=follow_redirects,
                    headers={'User-Agent': 'HeaderAnalyzer/1.0'}
                ) as response:
                    headers = dict(response.headers)
                    status_code = response.status
                    final_url = str(response.url)
                    
                    # Analyze headers
                    analysis = self._analyze_security_headers(headers)
                    
                    return {
                        'url': final_url,
                        'status_code': status_code,
                        'headers': headers,
                        'analysis': analysis,
                        'security_score': self._calculate_security_score(analysis),
                        'recommendations': self._generate_recommendations(analysis)
                    }
                    
        except asyncio.TimeoutError:
            raise ToolRunError(f"Request timeout for {url}")
        except aiohttp.ClientError as e:
            raise ToolRunError(f"Network error: {str(e)}")
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            raise ToolRunError(f"Analysis failed: {str(e)}")
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers"""
        # Convert headers to lowercase for case-insensitive comparison
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        analysis = {
            'present_headers': {},
            'missing_headers': {},
            'header_issues': {},
            'insecure_headers': {}
        }
        
        # Check each security header
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name in lower_headers:
                value = lower_headers[header_name]
                analysis['present_headers'][header_name] = {
                    'value': value,
                    'info': header_info,
                    'issues': self._check_header_value(header_name, value)
                }
            else:
                analysis['missing_headers'][header_name] = header_info
        
        # Check for insecure headers
        analysis['insecure_headers'] = self._check_insecure_headers(lower_headers)
        
        # Check for information disclosure
        analysis['information_disclosure'] = self._check_information_disclosure(lower_headers)
        
        return analysis
    
    def _check_header_value(self, header_name: str, value: str) -> List[str]:
        """Check specific header values for issues"""
        issues = []
        
        if header_name == 'strict-transport-security':
            if 'max-age' not in value.lower():
                issues.append("Missing max-age directive")
            elif 'max-age=0' in value.lower():
                issues.append("HSTS disabled with max-age=0")
            else:
                # Extract max-age value
                try:
                    max_age_part = [part for part in value.split(';') if 'max-age' in part.lower()][0]
                    max_age = int(max_age_part.split('=')[1].strip())
                    if max_age < 31536000:  # Less than 1 year
                        issues.append(f"Short max-age value: {max_age} seconds (recommended: 31536000+)")
                except (IndexError, ValueError):
                    issues.append("Invalid max-age format")
            
            if 'includesubdomains' not in value.lower():
                issues.append("Missing includeSubDomains directive")
        
        elif header_name == 'content-security-policy':
            if "'unsafe-inline'" in value:
                issues.append("Allows unsafe-inline scripts/styles")
            if "'unsafe-eval'" in value:
                issues.append("Allows unsafe-eval")
            if 'data:' in value and 'script-src' in value:
                issues.append("Allows data: URIs in script-src")
        
        elif header_name == 'x-frame-options':
            valid_values = ['deny', 'sameorigin']
            if value.lower() not in valid_values and not value.lower().startswith('allow-from'):
                issues.append(f"Invalid value: {value}")
        
        elif header_name == 'x-content-type-options':
            if value.lower() != 'nosniff':
                issues.append(f"Invalid value: {value} (should be 'nosniff')")
        
        elif header_name == 'x-xss-protection':
            if value == '0':
                issues.append("XSS protection disabled")
            elif value != '1; mode=block':
                issues.append("Weak XSS protection configuration")
        
        return issues
    
    def _check_insecure_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Check for headers that might disclose sensitive information"""
        insecure = {}
        
        # Server header
        if 'server' in headers:
            server_value = headers['server']
            if any(tech in server_value.lower() for tech in ['apache', 'nginx', 'iis', 'tomcat']):
                insecure['server'] = f"Server information disclosed: {server_value}"
        
        # X-Powered-By header
        if 'x-powered-by' in headers:
            insecure['x-powered-by'] = f"Technology stack disclosed: {headers['x-powered-by']}"
        
        # X-AspNet-Version
        if 'x-aspnet-version' in headers:
            insecure['x-aspnet-version'] = f"ASP.NET version disclosed: {headers['x-aspnet-version']}"
        
        # X-AspNetMvc-Version
        if 'x-aspnetmvc-version' in headers:
            insecure['x-aspnetmvc-version'] = f"ASP.NET MVC version disclosed: {headers['x-aspnetmvc-version']}"
        
        return insecure
    
    def _check_information_disclosure(self, headers: Dict[str, str]) -> List[str]:
        """Check for information disclosure issues"""
        issues = []
        
        # Check for detailed error information
        if 'x-debug-token' in headers:
            issues.append("Debug token present - possible development environment")
        
        # Check for cache control issues
        if 'cache-control' in headers:
            cache_value = headers['cache-control'].lower()
            if 'no-store' not in cache_value and 'private' not in cache_value:
                issues.append("Potentially cacheable sensitive content")
        
        # Check for CORS issues
        if 'access-control-allow-origin' in headers:
            cors_value = headers['access-control-allow-origin']
            if cors_value == '*':
                issues.append("Overly permissive CORS policy (allows all origins)")
        
        return issues
    
    def _calculate_security_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate a security score based on the analysis"""
        score = 100
        
        # Deduct points for missing critical headers
        critical_missing = sum(1 for header_info in analysis['missing_headers'].values() 
                             if header_info['critical'])
        score -= critical_missing * 15
        
        # Deduct points for missing non-critical headers
        non_critical_missing = sum(1 for header_info in analysis['missing_headers'].values() 
                                 if not header_info['critical'])
        score -= non_critical_missing * 5
        
        # Deduct points for header issues
        total_issues = sum(len(header['issues']) for header in analysis['present_headers'].values())
        score -= total_issues * 10
        
        # Deduct points for insecure headers
        score -= len(analysis['insecure_headers']) * 8
        
        # Deduct points for information disclosure
        score -= len(analysis['information_disclosure']) * 5
        
        return max(0, score)
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Missing headers
        for header_name, header_info in analysis['missing_headers'].items():
            if header_info['critical']:
                recommendations.append(f"CRITICAL: Add {header_info['name']} header")
            else:
                recommendations.append(f"Add {header_info['name']} header")
        
        # Header issues
        for header_name, header_data in analysis['present_headers'].items():
            for issue in header_data['issues']:
                recommendations.append(f"Fix {header_data['info']['name']}: {issue}")
        
        # Insecure headers
        for header_name, issue in analysis['insecure_headers'].items():
            recommendations.append(f"Remove or sanitize {header_name.upper()} header: {issue}")
        
        # Information disclosure
        for issue in analysis['information_disclosure']:
            recommendations.append(f"Address information disclosure: {issue}")
        
        return recommendations


async def execute_tool(params: HeaderAnalyzerInput) -> HeaderAnalyzerOutput:
    """Main entry point for the header analyzer tool.

    The URL arrives as pydantic's HttpUrl, which urlparse cannot take, and the
    output was built with fields HeaderAnalyzerOutput does not have, so every
    run failed (#611). The analysis is now passed a string and reported in
    the output's own fields.
    """
    analyzer = HeaderSecurityAnalyzer()
    url = str(params.url)

    try:
        result = await analyzer.analyze_headers(url=url, follow_redirects=params.follow_redirects)
    except RUN_ERRORS as e:
        return HeaderAnalyzerOutput(
            success=False,
            target=url,
            error=str(e),
            error_message=str(e),
            message="HTTP header analysis failed",
        )

    analysis = result["analysis"]
    present = [
        SecurityHeaderInfo(
            name=data["info"]["name"],
            value=data["value"],
            present=True,
            recommendation="; ".join(data["issues"]) or None,
            severity="medium" if data["issues"] else "low",
            description=data["info"]["description"],
        )
        for data in analysis["present_headers"].values()
    ]
    missing = [
        SecurityHeaderInfo(
            name=info["name"],
            present=False,
            recommendation=f"Add the {info['name']} header",
            severity="high" if info["critical"] else "medium",
            description=info["description"],
        )
        for info in analysis["missing_headers"].values()
    ]
    vulnerabilities = (
        [
            {"type": f"Missing {h.name}", "severity": h.severity, "description": h.description}
            for h in missing
        ]
        + [
            {"type": f"Weak {h.name}", "severity": h.severity, "description": h.recommendation}
            for h in present
            if h.recommendation
        ]
        + [
            {"type": "Information disclosure", "severity": "low", "description": str(item)}
            for item in analysis.get("information_disclosure", [])
        ]
    )

    return HeaderAnalyzerOutput(
        success=True,
        target=url,
        results=HeaderAnalysis(
            url=result["url"],
            status_code=result["status_code"],
            headers={str(k): str(v) for k, v in result["headers"].items()},
            security_headers=present,
            missing_headers=missing,
            security_score=int(result["security_score"]),
            vulnerabilities=vulnerabilities,
            recommendations=result["recommendations"],
        ),
        message="HTTP header analysis completed",
    )


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        test_input = HeaderAnalyzerInput(
            url="https://example.com",
            follow_redirects=True
        )
        result = await execute_tool(test_input)
        print(f"Success: {result.success}")
        if result.success:
            print(f"Security Score: {result.results.security_score}")
            print(f"Missing Headers: {[h.name for h in result.results.missing_headers]}")
            print(f"Recommendations: {len(result.results.recommendations)}")
        else:
            print(f"Error: {result.error}")
    
    asyncio.run(test())
