"""
URL Shortener Analyzer Tool

This tool analyzes shortened URLs to reveal their redirect chains, final destinations,
and performs security analysis to detect potential threats.
"""

import asyncio
import aiohttp
import ssl
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Any, Optional
from datetime import datetime
import time
import re

try:
    from .schemas import URLShortenerInput, URLShortenerOutput, RedirectHop, SecurityAnalysis
except ImportError:
    from schemas import URLShortenerInput, URLShortenerOutput, RedirectHop, SecurityAnalysis


class URLShortenerAnalyzer:
    """URL Shortener Security Analyzer"""
    
    # Known URL shortener services
    SHORTENER_SERVICES = {
        'bit.ly': 'Bitly',
        'tinyurl.com': 'TinyURL',
        't.co': 'Twitter',
        'goo.gl': 'Google (deprecated)',
        'short.link': 'Short.link',
        'rebrand.ly': 'Rebrandly',
        'ow.ly': 'Hootsuite',
        'buff.ly': 'Buffer',
        'is.gd': 'is.gd',
        'v.gd': 'v.gd',
        'tiny.cc': 'Tiny.cc',
        'lnkd.in': 'LinkedIn',
        'youtu.be': 'YouTube',
        'amzn.to': 'Amazon',
        'fb.me': 'Facebook',
        'git.io': 'GitHub'
    }
    
    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = [
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        r'[a-z0-9]{8,}\.tk$',  # Suspicious .tk domains
        r'[a-z0-9]{8,}\.ml$',  # Suspicious .ml domains
        r'[a-z0-9]{8,}\.ga$',  # Suspicious .ga domains
        r'[a-z0-9]{8,}\.cf$',  # Suspicious .cf domains
        r'secure-?update',     # Fake security updates
        r'verify-?account',    # Account verification scams
        r'paypal.*login',      # PayPal phishing
        r'amazon.*signin',     # Amazon phishing
        r'microsoft.*login',   # Microsoft phishing
        r'google.*login',      # Google phishing
        r'facebook.*login',    # Facebook phishing
        r'download.*exe',      # Executable downloads
        r'download.*zip',      # Archive downloads
    ]
    
    # Phishing indicators
    PHISHING_KEYWORDS = [
        'login', 'signin', 'verify', 'confirm', 'secure', 'update',
        'suspended', 'limited', 'urgent', 'immediate', 'action',
        'click', 'winner', 'congratulations', 'prize', 'lottery'
    ]
    
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=30)
    
    async def analyze_url(self, url: str, follow_redirects: bool = True, 
                         max_redirects: int = 10, timeout: int = 10,
                         check_reputation: bool = True) -> Dict[str, Any]:
        """Analyze a shortened URL"""
        
        redirect_chain = []
        current_url = str(url)
        
        # Create SSL context that allows self-signed certificates
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        custom_timeout = aiohttp.ClientTimeout(total=timeout)
        
        try:
            async with aiohttp.ClientSession(
                timeout=custom_timeout,
                connector=connector
            ) as session:
                
                step = 0
                
                while step < max_redirects:
                    start_time = time.time()
                    
                    try:
                        async with session.head(
                            current_url,
                            allow_redirects=False,
                            headers={'User-Agent': 'URLAnalyzer/1.0 (Security Scanner)'}
                        ) as response:
                            response_time = time.time() - start_time
                            
                            hop = RedirectHop(
                                step=step,
                                url=current_url,
                                status_code=response.status,
                                method='HEAD',
                                headers=dict(response.headers),
                                response_time=round(response_time, 3)
                            )
                            redirect_chain.append(hop)
                            
                            # Check if this is a redirect
                            if response.status in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location')
                                if location:
                                    # Handle relative URLs
                                    if location.startswith('/'):
                                        parsed = urlparse(current_url)
                                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                                    elif not location.startswith('http'):
                                        current_url = f"{current_url.rstrip('/')}/{location}"
                                    else:
                                        current_url = location
                                    step += 1
                                else:
                                    break
                            else:
                                break
                                
                    except aiohttp.ClientError as e:
                        # If HEAD fails, try GET
                        try:
                            async with session.get(
                                current_url,
                                allow_redirects=False,
                                headers={'User-Agent': 'URLAnalyzer/1.0 (Security Scanner)'}
                            ) as response:
                                response_time = time.time() - start_time
                                
                                hop = RedirectHop(
                                    step=step,
                                    url=current_url,
                                    status_code=response.status,
                                    method='GET',
                                    headers=dict(response.headers),
                                    response_time=round(response_time, 3)
                                )
                                redirect_chain.append(hop)
                                break
                        except Exception:
                            break
                
                # Analyze the redirect chain for security issues
                security_analysis = self._analyze_security(redirect_chain, check_reputation)
                
                # Detect shortener service
                shortener_service = self._detect_shortener_service(str(url))
                
                return {
                    'redirect_chain': redirect_chain,
                    'final_url': current_url if redirect_chain else str(url),
                    'total_redirects': len(redirect_chain) - 1 if redirect_chain else 0,
                    'shortener_service': shortener_service,
                    'security_analysis': security_analysis
                }
                
        except asyncio.TimeoutError:
            raise Exception(f"Request timeout for {url}")
        except Exception as e:
            raise Exception(f"Analysis failed: {str(e)}")
    
    def _detect_shortener_service(self, url: str) -> Optional[str]:
        """Detect the URL shortener service"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        for service_domain, service_name in self.SHORTENER_SERVICES.items():
            if domain == service_domain or domain.endswith(f".{service_domain}"):
                return service_name
        
        return None
    
    def _analyze_security(self, redirect_chain: List[RedirectHop], check_reputation: bool) -> SecurityAnalysis:
        """Analyze the security of the redirect chain"""
        threats_detected = []
        phishing_indicators = []
        malware_indicators = []
        risk_level = "low"
        is_suspicious = False
        
        for hop in redirect_chain:
            url = hop.url.lower()
            
            # Check for suspicious patterns
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, url):
                    threats_detected.append(f"Suspicious pattern detected: {pattern}")
                    is_suspicious = True
            
            # Check for phishing indicators
            for keyword in self.PHISHING_KEYWORDS:
                if keyword in url:
                    phishing_indicators.append(f"Phishing keyword: {keyword}")
                    is_suspicious = True
            
            # Check for IP addresses instead of domains
            parsed = urlparse(hop.url)
            if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', parsed.netloc):
                threats_detected.append("Direct IP address usage (suspicious)")
                is_suspicious = True
            
            # Check for suspicious TLDs
            if any(tld in parsed.netloc for tld in ['.tk', '.ml', '.ga', '.cf']):
                threats_detected.append("Suspicious top-level domain")
                is_suspicious = True
            
            # Check for multiple subdomains (potential typosquatting)
            if parsed.netloc.count('.') > 2:
                threats_detected.append("Multiple subdomains (potential typosquatting)")
                is_suspicious = True
            
            # Check for non-standard ports
            if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
                threats_detected.append(f"Non-standard port: {parsed.port}")
                is_suspicious = True
        
        # Determine risk level
        threat_count = len(threats_detected) + len(phishing_indicators) + len(malware_indicators)
        
        if threat_count >= 5:
            risk_level = "critical"
        elif threat_count >= 3:
            risk_level = "high"
        elif threat_count >= 1:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Check for excessive redirects
        if len(redirect_chain) > 5:
            threats_detected.append("Excessive redirect chain (potential cloaking)")
            is_suspicious = True
            risk_level = "high"
        
        # Simple reputation scoring (would integrate with real services in production)
        reputation_score = 100 - (threat_count * 15)
        reputation_score = max(0, min(100, reputation_score))
        
        return SecurityAnalysis(
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            threats_detected=threats_detected,
            reputation_score=reputation_score if check_reputation else None,
            phishing_indicators=phishing_indicators,
            malware_indicators=malware_indicators
        )


async def execute_tool(params: URLShortenerInput) -> URLShortenerOutput:
    """Main entry point for the URL shortener analyzer tool"""
    analyzer = URLShortenerAnalyzer()
    
    try:
        # Perform URL analysis
        result = await analyzer.analyze_url(
            url=str(params.shortened_url),
            follow_redirects=params.follow_redirects,
            max_redirects=params.max_redirects,
            timeout=params.timeout,
            check_reputation=params.check_reputation
        )
        
        return URLShortenerOutput(
            success=True,
            original_url=str(params.shortened_url),
            final_url=result['final_url'],
            redirect_chain=result['redirect_chain'],
            total_redirects=result['total_redirects'],
            shortener_service=result['shortener_service'],
            security_analysis=result['security_analysis'],
            timestamp=datetime.now(),
            error=None
        )
        
    except Exception as e:
        return URLShortenerOutput(
            success=False,
            original_url=str(params.shortened_url),
            final_url=None,
            redirect_chain=[],
            total_redirects=0,
            shortener_service=None,
            security_analysis=SecurityAnalysis(
                is_suspicious=False,
                risk_level="unknown",
                threats_detected=[],
                reputation_score=None,
                phishing_indicators=[],
                malware_indicators=[]
            ),
            timestamp=datetime.now(),
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "url_analyzer",
    "display_name": "URL Shortener Analyzer",
    "description": "Analyzes shortened URLs to reveal redirect chains and detect security threats",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "web_security"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        test_input = URLShortenerInput(
            shortened_url="https://bit.ly/3example",
            follow_redirects=True,
            max_redirects=5
        )
        result = await execute_tool(test_input)
        print(f"Success: {result.success}")
        if result.success:
            print(f"Final URL: {result.final_url}")
            print(f"Total Redirects: {result.total_redirects}")
            print(f"Risk Level: {result.security_analysis.risk_level}")
        else:
            print(f"Error: {result.error}")
    
    asyncio.run(test())
