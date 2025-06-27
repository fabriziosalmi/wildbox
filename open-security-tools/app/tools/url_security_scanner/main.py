"""
URL Security Scanner Tool

This tool analyzes URLs for security risks including malicious patterns,
reputation checking, and redirect analysis.
"""

import re
import urllib.parse
import asyncio
import aiohttp
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import ipaddress
import sys
import os

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
    from schemas import (
        URLSecurityInput, URLSecurityOutput, URLComponents, SecurityAnalysis,
        RedirectAnalysis, ReputationAnalysis
    )
except ImportError:
    from schemas import (
        URLSecurityInput, URLSecurityOutput, URLComponents, SecurityAnalysis,
        RedirectAnalysis, ReputationAnalysis
    )


class URLSecurityScanner:
    """URL security scanner with comprehensive threat detection"""
    
    def __init__(self):
        # Initialize rate limiter for external requests
        self.rate_limiter = RateLimiter(max_requests=10, time_window=60)
    
    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = [
        r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly',  # URL shorteners
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}',  # Double URL encoding
        r'javascript:|data:|vbscript:',  # Dangerous schemes
        r'\.tk$|\.ml$|\.ga$|\.cf$',  # Suspicious TLDs
        r'[a-zA-Z0-9]{20,}',  # Very long random strings
        r'phishing|malware|virus|trojan|scam',  # Suspicious keywords
        r'urgent|verify|suspend|update.*account|click.*here',  # Phishing keywords
        r'[0-9]{16}',  # Potential credit card numbers
        r'(login|signin|bank|paypal|amazon|microsoft|google).*[0-9]+',  # Fake brand domains
    ]
    
    # Common URL shortening services
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'rb.gy', 'cutt.ly'
    }
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download',
        '.work', '.men', '.win', '.bid', '.cricket', '.science', '.party'
    }
    
    # Common legitimate domains (whitelist)
    LEGITIMATE_DOMAINS = {
        'google.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'twitter.com',
        'linkedin.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
        'reddit.com', 'youtube.com', 'apple.com', 'paypal.com', 'ebay.com'
    }
    
    def __init__(self):
        pass
    
    def __init__(self):
        # Initialize rate limiter for external requests
        self.rate_limiter = RateLimiter(max_requests=10, time_window=60)

    def parse_url(self, url: str) -> URLComponents:
        """Parse URL into components"""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Extract domain and subdomain
            domain_parts = parsed.netloc.split('.')
            if len(domain_parts) >= 2:
                domain = '.'.join(domain_parts[-2:])
                subdomain = '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else None
            else:
                domain = parsed.netloc
                subdomain = None
            
            return URLComponents(
                scheme=parsed.scheme,
                domain=domain,
                subdomain=subdomain,
                path=parsed.path,
                query=parsed.query,
                fragment=parsed.fragment,
                port=parsed.port
            )
        except Exception as e:
            raise ValueError(f"Failed to parse URL: {str(e)}")
    
    def analyze_security(self, url: str, components: URLComponents) -> SecurityAnalysis:
        """Analyze URL for security issues"""
        
        suspicious_patterns = []
        encoding_issues = []
        
        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_patterns.append(f"Suspicious pattern: {pattern}")
        
        # Check for URL encoding issues
        if '%' in url:
            # Check for double encoding
            if re.search(r'%25[0-9a-fA-F]{2}', url):
                encoding_issues.append("Double URL encoding detected")
            
            # Check for suspicious encoded characters
            suspicious_encoded = ['%00', '%0a', '%0d', '%09', '%20%20']
            for encoded in suspicious_encoded:
                if encoded in url.lower():
                    encoding_issues.append(f"Suspicious encoded character: {encoded}")
        
        # Check if domain is an IP address
        is_ip_domain = False
        try:
            ipaddress.ip_address(components.domain)
            is_ip_domain = True
            suspicious_patterns.append("Domain is an IP address")
        except ValueError:
            pass
        
        # Check for suspicious TLD
        has_suspicious_tld = any(components.domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            suspicious_patterns.append("Suspicious top-level domain")
        
        # Check if it's a URL shortener
        is_shortened = any(shortener in components.domain for shortener in self.URL_SHORTENERS)
        
        # Check for homograph attacks (basic check)
        if re.search(r'[а-я]|[α-ω]', components.domain):  # Cyrillic or Greek chars
            suspicious_patterns.append("Potential homograph attack (non-Latin characters)")
        
        # Check path for suspicious patterns
        if '/wp-admin' in components.path or '/admin' in components.path:
            suspicious_patterns.append("Admin path detected")
        
        if re.search(r'\.(exe|bat|cmd|scr|pif|com)$', components.path, re.IGNORECASE):
            suspicious_patterns.append("Executable file extension in path")
        
        # Estimate domain age (simplified - would need WHOIS in real implementation)
        domain_age_days = None
        if components.domain in self.LEGITIMATE_DOMAINS:
            domain_age_days = 7300  # Assume 20+ years for well-known domains
        
        return SecurityAnalysis(
            is_https=components.scheme == 'https',
            has_suspicious_patterns=len(suspicious_patterns) > 0,
            suspicious_patterns=suspicious_patterns,
            domain_age_days=domain_age_days,
            is_shortened_url=is_shortened,
            has_suspicious_tld=has_suspicious_tld,
            encoding_issues=encoding_issues
        )
    
    async def analyze_redirects(self, url: str, max_redirects: int, timeout: int) -> RedirectAnalysis:
        """Analyze redirect chain"""
        
        redirect_chain = [url]
        current_url = url
        redirect_count = 0
        security_issues = []
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                connector=aiohttp.TCPConnector(ssl=False)  # Allow self-signed certs for analysis
            ) as session:
                
                while redirect_count < max_redirects:
                    try:
                        # Apply rate limiting before making external request
                        await self.rate_limiter.acquire()
                        
                        async with session.head(
                            current_url,
                            allow_redirects=False,
                            headers={'User-Agent': 'URL-Security-Scanner/1.0'}
                        ) as response:
                            
                            if response.status in [301, 302, 303, 307, 308]:
                                redirect_location = response.headers.get('Location')
                                if not redirect_location:
                                    break
                                
                                # Handle relative redirects
                                if redirect_location.startswith('/'):
                                    parsed_current = urllib.parse.urlparse(current_url)
                                    redirect_location = f"{parsed_current.scheme}://{parsed_current.netloc}{redirect_location}"
                                elif not redirect_location.startswith(('http://', 'https://')):
                                    parsed_current = urllib.parse.urlparse(current_url)
                                    base_url = f"{parsed_current.scheme}://{parsed_current.netloc}"
                                    redirect_location = urllib.parse.urljoin(base_url, redirect_location)
                                
                                redirect_chain.append(redirect_location)
                                
                                # Check for security issues in redirect
                                if not redirect_location.startswith('https://') and current_url.startswith('https://'):
                                    security_issues.append("HTTPS to HTTP downgrade in redirect")
                                
                                # Check for open redirect patterns
                                parsed_redirect = urllib.parse.urlparse(redirect_location)
                                if parsed_redirect.netloc != urllib.parse.urlparse(current_url).netloc:
                                    security_issues.append("Cross-domain redirect detected")
                                
                                current_url = redirect_location
                                redirect_count += 1
                            else:
                                break
                    
                    except asyncio.TimeoutError:
                        security_issues.append("Timeout during redirect analysis")
                        break
                    except Exception as e:
                        security_issues.append(f"Error following redirect: {str(e)}")
                        break
                
        except Exception as e:
            security_issues.append(f"Failed to analyze redirects: {str(e)}")
        
        # Check for suspicious redirect patterns
        has_suspicious_redirects = False
        for redirect_url in redirect_chain[1:]:  # Skip original URL
            components = self.parse_url(redirect_url)
            analysis = self.analyze_security(redirect_url, components)
            if analysis.has_suspicious_patterns:
                has_suspicious_redirects = True
                security_issues.append(f"Suspicious redirect destination: {redirect_url}")
        
        return RedirectAnalysis(
            redirect_count=redirect_count,
            redirect_chain=redirect_chain,
            final_url=current_url,
            has_suspicious_redirects=has_suspicious_redirects,
            redirect_security_issues=security_issues
        )
    
    def analyze_reputation(self, url: str, components: URLComponents) -> ReputationAnalysis:
        """Analyze URL reputation (simplified implementation)"""
        
        threat_categories = []
        blacklist_matches = []
        whitelist_matches = []
        reputation_score = 50  # Neutral starting score
        
        # Check against whitelist (legitimate domains)
        if components.domain in self.LEGITIMATE_DOMAINS:
            whitelist_matches.append("Known legitimate domain")
            reputation_score += 30
        
        # Check for suspicious indicators
        if components.domain.count('-') > 3:
            threat_categories.append("Suspicious domain structure")
            reputation_score -= 10
        
        if re.search(r'\d{4,}', components.domain):
            threat_categories.append("Many numbers in domain")
            reputation_score -= 5
        
        if len(components.domain.split('.')[0]) > 20:
            threat_categories.append("Unusually long domain name")
            reputation_score -= 10
        
        # Check for homograph attacks
        if not components.domain.isascii():
            threat_categories.append("Non-ASCII characters in domain")
            blacklist_matches.append("Potential homograph attack")
            reputation_score -= 20
        
        # Check for suspicious TLD
        has_suspicious_tld = any(components.domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS)
        if has_suspicious_tld:
            threat_categories.append("Suspicious TLD")
            reputation_score -= 15
        
        # Check for URL shorteners
        if any(shortener in components.domain for shortener in self.URL_SHORTENERS):
            threat_categories.append("URL shortener")
            reputation_score -= 5  # Not necessarily malicious, but reduces trust
        
        # Check for suspicious keywords in URL
        suspicious_keywords = [
            'phishing', 'malware', 'virus', 'scam', 'fake', 'fraud',
            'urgent', 'verify', 'suspend', 'unlock', 'secure'
        ]
        
        url_lower = url.lower()
        for keyword in suspicious_keywords:
            if keyword in url_lower:
                threat_categories.append(f"Suspicious keyword: {keyword}")
                reputation_score -= 15
        
        # Ensure score is within bounds
        reputation_score = max(0, min(100, reputation_score))
        
        # Determine if malicious based on score and indicators
        is_malicious = reputation_score < 30 or len(blacklist_matches) > 0
        
        return ReputationAnalysis(
            is_malicious=is_malicious,
            threat_categories=threat_categories,
            reputation_score=reputation_score,
            blacklist_matches=blacklist_matches,
            whitelist_matches=whitelist_matches
        )
    
    def calculate_overall_risk(self, security_analysis: SecurityAnalysis,
                              redirect_analysis: Optional[RedirectAnalysis],
                              reputation_analysis: Optional[ReputationAnalysis]) -> Tuple[float, str]:
        """Calculate overall risk score and level"""
        
        risk_score = 0
        
        # Security analysis factors
        if not security_analysis.is_https:
            risk_score += 15
        
        risk_score += len(security_analysis.suspicious_patterns) * 10
        risk_score += len(security_analysis.encoding_issues) * 5
        
        if security_analysis.is_shortened_url:
            risk_score += 10
        
        if security_analysis.has_suspicious_tld:
            risk_score += 15
        
        # Redirect analysis factors
        if redirect_analysis:
            if redirect_analysis.has_suspicious_redirects:
                risk_score += 20
            risk_score += len(redirect_analysis.redirect_security_issues) * 5
            
            # Excessive redirects are suspicious
            if redirect_analysis.redirect_count > 5:
                risk_score += 10
        
        # Reputation analysis factors
        if reputation_analysis:
            if reputation_analysis.is_malicious:
                risk_score += 30
            
            # Invert reputation score (lower reputation = higher risk)
            risk_score += (100 - reputation_analysis.reputation_score) * 0.3
            
            risk_score += len(reputation_analysis.threat_categories) * 5
        
        # Cap the risk score
        risk_score = min(100, risk_score)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 35:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return risk_score, risk_level
    
    def generate_recommendations(self, security_analysis: SecurityAnalysis,
                               redirect_analysis: Optional[RedirectAnalysis],
                               reputation_analysis: Optional[ReputationAnalysis],
                               risk_level: str) -> List[str]:
        """Generate security recommendations"""
        
        recommendations = []
        
        # HTTPS recommendations
        if not security_analysis.is_https:
            recommendations.append("Avoid visiting HTTP URLs; prefer HTTPS for security")
        
        # Suspicious patterns
        if security_analysis.has_suspicious_patterns:
            recommendations.append("Exercise extreme caution - URL contains suspicious patterns")
            recommendations.append("Verify the legitimacy of this URL through official channels")
        
        # URL shorteners
        if security_analysis.is_shortened_url:
            recommendations.append("Be cautious with shortened URLs - expand them to see the destination")
        
        # Encoding issues
        if security_analysis.encoding_issues:
            recommendations.append("URL contains suspicious encoding - potential attack attempt")
        
        # Redirect issues
        if redirect_analysis and redirect_analysis.has_suspicious_redirects:
            recommendations.append("Redirect chain contains suspicious URLs")
            recommendations.append("Verify the final destination before proceeding")
        
        # Reputation issues
        if reputation_analysis and reputation_analysis.is_malicious:
            recommendations.append("URL flagged as potentially malicious - avoid visiting")
        
        # General recommendations based on risk level
        if risk_level == "critical":
            recommendations.append("DO NOT visit this URL - high risk of malicious content")
            recommendations.append("Report this URL to security authorities if received via email/message")
        elif risk_level == "high":
            recommendations.append("Strongly advise against visiting this URL")
            recommendations.append("Use additional security measures if you must visit")
        elif risk_level == "medium":
            recommendations.append("Exercise caution when visiting this URL")
            recommendations.append("Ensure your security software is up to date")
        else:
            recommendations.append("URL appears relatively safe, but always stay vigilant")
        
        # Always include general security advice
        recommendations.append("Never enter sensitive information on suspicious websites")
        recommendations.append("Keep your browser and security software updated")
        
        return recommendations


async def execute_tool(input_data: URLSecurityInput) -> URLSecurityOutput:
    """Execute the URL security scanner tool"""
    
    try:
        scanner = URLSecurityScanner()
        analysis_timestamp = datetime.now(timezone.utc)
        
        # Parse URL
        components = scanner.parse_url(input_data.url)
        
        # Perform security analysis
        security_analysis = scanner.analyze_security(input_data.url, components)
        
        # Analyze redirects if enabled
        redirect_analysis = None
        if input_data.check_redirects:
            redirect_analysis = await scanner.analyze_redirects(
                input_data.url,
                input_data.max_redirects,
                input_data.timeout
            )
        
        # Analyze reputation if enabled
        reputation_analysis = None
        if input_data.check_reputation:
            reputation_analysis = scanner.analyze_reputation(input_data.url, components)
        
        # Calculate overall risk
        risk_score, risk_level = scanner.calculate_overall_risk(
            security_analysis, redirect_analysis, reputation_analysis
        )
        
        # Generate recommendations
        recommendations = scanner.generate_recommendations(
            security_analysis, redirect_analysis, reputation_analysis, risk_level
        )
        
        return URLSecurityOutput(
            success=True,
            original_url=input_data.url,
            url_components=components,
            security_analysis=security_analysis,
            redirect_analysis=redirect_analysis,
            reputation_analysis=reputation_analysis,
            overall_risk_score=risk_score,
            risk_level=risk_level,
            recommendations=recommendations,
            analysis_timestamp=analysis_timestamp
        )
        
    except Exception as e:
        return URLSecurityOutput(
            success=False,
            original_url=input_data.url,
            url_components=URLComponents(
                scheme="", domain="", subdomain=None, path="", 
                query=None, fragment=None, port=None
            ),
            security_analysis=SecurityAnalysis(
                is_https=False,
                has_suspicious_patterns=False,
                suspicious_patterns=[],
                domain_age_days=None,
                is_shortened_url=False,
                has_suspicious_tld=False,
                encoding_issues=[]
            ),
            redirect_analysis=None,
            reputation_analysis=None,
            overall_risk_score=0.0,
            risk_level="unknown",
            recommendations=[],
            analysis_timestamp=datetime.now(timezone.utc),
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "url_security_scanner",
    "display_name": "URL Security Scanner",
    "description": "Comprehensive URL security analysis including threat detection and reputation checking",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "web_security"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        # Test with a suspicious URL
        test_input = URLSecurityInput(
            url="http://bit.ly/suspicious-link",
            check_reputation=True,
            analyze_structure=True,
            check_redirects=True,
            max_redirects=5
        )
        
        result = await execute_tool(test_input)
        print(f"URL Security Analysis Success: {result.success}")
        print(f"Original URL: {result.original_url}")
        print(f"Risk Level: {result.risk_level}")
        print(f"Risk Score: {result.overall_risk_score:.1f}")
        print(f"Is HTTPS: {result.security_analysis.is_https}")
        print(f"Suspicious Patterns: {len(result.security_analysis.suspicious_patterns)}")
        print(f"Recommendations: {len(result.recommendations)}")
        
        if result.reputation_analysis:
            print(f"Reputation Score: {result.reputation_analysis.reputation_score}")
            print(f"Is Malicious: {result.reputation_analysis.is_malicious}")
    
    asyncio.run(test())
