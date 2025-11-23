"""
Email Security Analyzer Tool

This tool analyzes email headers and performs comprehensive email security
assessment including SPF, DKIM, DMARC, and reputation analysis.
"""

import re
import socket
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from email.parser import HeaderParser
from email import policy

try:
    from schemas import (
        EmailSecurityInput, EmailSecurityOutput, SPFAnalysis, DKIMAnalysis,
        DMARCAnalysis, EmailRouting, ReputationAnalysis, PhishingIndicators
    )
except ImportError:
    from schemas import (
        EmailSecurityInput, EmailSecurityOutput, SPFAnalysis, DKIMAnalysis,
        DMARCAnalysis, EmailRouting, ReputationAnalysis, PhishingIndicators
    )


class EmailSecurityAnalyzer:
    """Email security analyzer with comprehensive authentication and reputation checking"""
    
    # Known malicious domains (for demonstration)
    MALICIOUS_DOMAINS = {
        'phishing-example.com', 'malware-site.org', 'fake-bank.net',
        'suspicious-domain.tk', 'scam-alert.ml'
    }
    
    # Trusted domains
    TRUSTED_DOMAINS = {
        'gmail.com', 'outlook.com', 'yahoo.com', 'apple.com', 'microsoft.com',
        'amazon.com', 'google.com', 'facebook.com', 'twitter.com'
    }
    
    # Phishing keywords
    PHISHING_KEYWORDS = [
        'urgent', 'immediate', 'suspend', 'verify', 'confirm', 'update',
        'click here', 'act now', 'limited time', 'expires', 'winner',
        'congratulations', 'prize', 'lottery', 'inheritance', 'tax refund'
    ]
    
    # Brand impersonation patterns
    BRAND_PATTERNS = {
        'paypal': r'p[a4@]yp[a4@]l|p[4@]ypal',
        'amazon': r'[a4@]m[a4@]z[o0]n|[a4@]mazon',
        'microsoft': r'm[i1]cr[o0]s[o0]ft|m[i1]cro5oft',
        'apple': r'[a4@]ppl[e3]|[a4@]pp1e',
        'google': r'g[o0][o0]gl[e3]|g00gle'
    }
    
    def __init__(self):
        pass
    
    def parse_email_headers(self, headers_text: str) -> Dict[str, Any]:
        """Parse email headers and extract key information"""
        
        try:
            # Parse headers
            parser = HeaderParser(policy=policy.default)
            headers = parser.parsestr(headers_text)
            
            # Extract key fields
            sender_email = headers.get('From', '')
            sender_domain = ''
            sender_ip = None
            
            # Extract email from "From" field
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender_email)
            if email_match:
                sender_email = email_match.group()
                sender_domain = sender_email.split('@')[1]
            
            # Extract sender IP from Received headers
            received_headers = headers.get_all('Received') or []
            for received in received_headers:
                ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
                if ip_match:
                    sender_ip = ip_match.group(1)
                    break
            
            return {
                'headers': headers,
                'sender_email': sender_email,
                'sender_domain': sender_domain,
                'sender_ip': sender_ip,
                'received_headers': received_headers
            }
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            raise ValueError(f"Failed to parse email headers: {str(e)}")
    
    def analyze_spf(self, sender_domain: str, sender_ip: Optional[str]) -> SPFAnalysis:
        """Analyze SPF records and authentication"""
        
        spf_record = None
        spf_result = "none"
        issues = []
        authorized_senders = []
        
        try:
            # Simulate SPF record lookup
            if sender_domain in self.TRUSTED_DOMAINS:
                spf_record = f"v=spf1 include:_spf.{sender_domain} ~all"
                spf_result = "pass"
                authorized_senders = [f"_spf.{sender_domain}"]
            elif sender_domain in self.MALICIOUS_DOMAINS:
                spf_record = None
                spf_result = "fail"
                issues.append("No SPF record found for suspicious domain")
            else:
                # Simulate mixed results
                import random
                if random.random() < 0.7:  # 70% have SPF records
                    spf_record = f"v=spf1 a mx include:{sender_domain} ~all"
                    spf_result = random.choice(["pass", "pass", "softfail", "neutral"])
                    authorized_senders = [f"a:{sender_domain}", f"mx:{sender_domain}"]
                else:
                    spf_result = "none"
                    issues.append("No SPF record found")
            
            # Check for common SPF issues
            if spf_record:
                if "~all" not in spf_record and "-all" not in spf_record:
                    issues.append("SPF record lacks proper 'all' mechanism")
                if spf_record.count("include:") > 10:
                    issues.append("Too many SPF includes (DNS lookup limit)")
                if "redirect=" in spf_record and ("include:" in spf_record or "a" in spf_record):
                    issues.append("SPF record contains both redirect and other mechanisms")
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            issues.append(f"SPF lookup failed: {str(e)}")
        
        return SPFAnalysis(
            spf_record_found=spf_record is not None,
            spf_record=spf_record,
            spf_result=spf_result,
            spf_issues=issues,
            authorized_senders=authorized_senders
        )
    
    def analyze_dkim(self, headers: Dict[str, Any]) -> DKIMAnalysis:
        """Analyze DKIM signatures"""
        
        dkim_header = headers['headers'].get('DKIM-Signature')
        
        if not dkim_header:
            return DKIMAnalysis(
                dkim_signature_found=False,
                dkim_valid=False,
                dkim_domain=None,
                dkim_selector=None,
                dkim_algorithm=None,
                dkim_issues=["No DKIM signature found"]
            )
        
        # Parse DKIM signature
        dkim_parts = {}
        for part in dkim_header.split(';'):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                dkim_parts[key.strip()] = value.strip()
        
        domain = dkim_parts.get('d', '')
        selector = dkim_parts.get('s', '')
        algorithm = dkim_parts.get('a', '')
        
        # Simulate DKIM validation
        issues = []
        is_valid = True
        
        if domain != headers['sender_domain']:
            issues.append("DKIM domain doesn't match sender domain")
            is_valid = False
        
        if algorithm and 'sha1' in algorithm.lower():
            issues.append("DKIM uses weak SHA-1 algorithm")
        
        # Simulate validation based on domain reputation
        if domain in self.MALICIOUS_DOMAINS:
            is_valid = False
            issues.append("DKIM signature validation failed")
        elif domain not in self.TRUSTED_DOMAINS:
            # Random chance of validation failure
            import random
            if random.random() < 0.2:  # 20% chance of failure
                is_valid = False
                issues.append("DKIM signature validation failed")
        
        return DKIMAnalysis(
            dkim_signature_found=True,
            dkim_valid=is_valid,
            dkim_domain=domain,
            dkim_selector=selector,
            dkim_algorithm=algorithm,
            dkim_issues=issues
        )
    
    def analyze_dmarc(self, sender_domain: str, spf_result: str, dkim_valid: bool) -> DMARCAnalysis:
        """Analyze DMARC policy and alignment"""
        
        dmarc_record = None
        dmarc_policy = None
        issues = []
        
        try:
            # Simulate DMARC record lookup
            if sender_domain in self.TRUSTED_DOMAINS:
                dmarc_record = f"v=DMARC1; p=reject; rua=mailto:dmarc@{sender_domain}; ruf=mailto:dmarc@{sender_domain}; sp=reject; adkim=s; aspf=s"
                dmarc_policy = "reject"
            elif sender_domain in self.MALICIOUS_DOMAINS:
                dmarc_record = None
                issues.append("No DMARC record found for suspicious domain")
            else:
                # Simulate mixed DMARC policies
                import random
                if random.random() < 0.6:  # 60% have DMARC records
                    policy = random.choice(["none", "quarantine", "reject"])
                    dmarc_record = f"v=DMARC1; p={policy}; rua=mailto:dmarc@{sender_domain}"
                    dmarc_policy = policy
                else:
                    issues.append("No DMARC record found")
            
            # Check DMARC alignment
            spf_aligned = spf_result in ["pass"]
            dkim_aligned = dkim_valid
            
            # Determine DMARC compliance
            dmarc_compliance = spf_aligned or dkim_aligned  # At least one must pass
            
            if dmarc_policy == "none" and not issues:
                issues.append("DMARC policy is set to 'none' (monitoring only)")
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            issues.append(f"DMARC lookup failed: {str(e)}")
            spf_aligned = False
            dkim_aligned = False
            dmarc_compliance = False
        
        return DMARCAnalysis(
            dmarc_record_found=dmarc_record is not None,
            dmarc_record=dmarc_record,
            dmarc_policy=dmarc_policy,
            dmarc_alignment={"spf": spf_aligned, "dkim": dkim_aligned},
            dmarc_issues=issues,
            dmarc_compliance=dmarc_compliance
        )
    
    def analyze_email_routing(self, received_headers: List[str]) -> EmailRouting:
        """Analyze email routing path"""
        
        routing_path = []
        suspicious_hops = []
        geo_locations = []
        
        for received in received_headers:
            # Extract server information
            server_match = re.search(r'from\s+([^\s]+)', received)
            if server_match:
                server = server_match.group(1)
                routing_path.append(server)
                
                # Check for suspicious patterns
                if any(pattern in server.lower() for pattern in ['tor', 'proxy', 'vpn', 'anonymous']):
                    suspicious_hops.append(f"Suspicious server: {server}")
                
                # Simulate geolocation
                import random
                geo_locations.append(random.choice(['US', 'GB', 'CA', 'DE', 'FR', 'JP', 'AU']))
        
        # Calculate delivery delay
        delivery_delay = None
        if len(received_headers) >= 2:
            # Simulate delivery delay calculation
            import random
            delivery_delay = random.uniform(0.1, 24.0)  # Random delay between 0.1-24 hours
        
        return EmailRouting(
            hop_count=len(routing_path),
            routing_path=routing_path,
            suspicious_hops=suspicious_hops,
            geo_locations=geo_locations,
            delivery_delay=delivery_delay
        )
    
    def analyze_reputation(self, sender_domain: str, sender_ip: Optional[str]) -> ReputationAnalysis:
        """Analyze sender reputation"""
        
        # Domain reputation
        if sender_domain in self.TRUSTED_DOMAINS:
            domain_reputation = "good"
            sender_score = 90
        elif sender_domain in self.MALICIOUS_DOMAINS:
            domain_reputation = "malicious"
            sender_score = 10
        else:
            # Random reputation for demo
            import random
            reputations = ["good", "neutral", "poor"]
            weights = [0.5, 0.3, 0.2]
            domain_reputation = random.choices(reputations, weights=weights)[0]
            
            if domain_reputation == "good":
                sender_score = random.uniform(70, 90)
            elif domain_reputation == "neutral":
                sender_score = random.uniform(40, 70)
            else:
                sender_score = random.uniform(10, 40)
        
        # IP reputation
        ip_reputation = "unknown"
        if sender_ip:
            try:
                ip = ipaddress.ip_address(sender_ip)
                if ip.is_private:
                    ip_reputation = "private"
                elif sender_domain in self.TRUSTED_DOMAINS:
                    ip_reputation = "good"
                elif sender_domain in self.MALICIOUS_DOMAINS:
                    ip_reputation = "malicious"
                else:
                    ip_reputation = "neutral"
            except ValueError:
                ip_reputation = "invalid"
        
        # Simulate blacklist/whitelist checks
        blacklist_status = {}
        whitelist_status = {}
        
        blacklists = ["Spamhaus", "SURBL", "URIBL", "Barracuda"]
        whitelists = ["Microsoft SNDS", "Gmail Postmaster", "Sender Score"]
        
        for bl in blacklists:
            blacklist_status[bl] = sender_domain in self.MALICIOUS_DOMAINS
        
        for wl in whitelists:
            whitelist_status[wl] = sender_domain in self.TRUSTED_DOMAINS
        
        # Simulate domain age
        domain_age_days = None
        if sender_domain in self.TRUSTED_DOMAINS:
            domain_age_days = 7300  # ~20 years
        elif sender_domain in self.MALICIOUS_DOMAINS:
            domain_age_days = 30    # New domain
        else:
            import random
            domain_age_days = random.randint(90, 3650)  # 3 months to 10 years
        
        return ReputationAnalysis(
            domain_reputation=domain_reputation,
            ip_reputation=ip_reputation,
            sender_score=sender_score,
            blacklist_status=blacklist_status,
            whitelist_status=whitelist_status,
            domain_age_days=domain_age_days
        )
    
    def detect_phishing_indicators(self, headers: Dict[str, Any], content: str = "") -> PhishingIndicators:
        """Detect phishing indicators"""
        
        suspicious_patterns = []
        domain_spoofing = False
        suspicious_links = []
        brand_impersonation = None
        urgency_indicators = []
        social_engineering = []
        
        sender_domain = headers['sender_domain'].lower()
        
        # Check for domain spoofing
        for brand, pattern in self.BRAND_PATTERNS.items():
            if re.search(pattern, sender_domain, re.IGNORECASE):
                if brand not in sender_domain:
                    domain_spoofing = True
                    brand_impersonation = brand
                    suspicious_patterns.append(f"Domain mimics {brand}")
        
        # Check for suspicious patterns in domain
        if re.search(r'\d{4,}', sender_domain):
            suspicious_patterns.append("Domain contains many numbers")
        
        if sender_domain.count('-') > 3:
            suspicious_patterns.append("Domain has excessive hyphens")
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
        if any(sender_domain.endswith(tld) for tld in suspicious_tlds):
            suspicious_patterns.append("Suspicious top-level domain")
        
        # Analyze subject line for urgency
        subject = headers['headers'].get('Subject', '').lower()
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in subject:
                urgency_indicators.append(f"Urgent keyword: {keyword}")
        
        # Look for social engineering tactics
        if any(word in subject for word in ['winner', 'prize', 'lottery']):
            social_engineering.append("Prize/lottery scam indicators")
        
        if any(word in subject for word in ['suspend', 'verify', 'confirm']):
            social_engineering.append("Account verification pressure")
        
        # Simulate link analysis
        import random
        if random.random() < 0.3:  # 30% chance of suspicious links
            suspicious_links.append("http://suspicious-link.example.com")
        
        return PhishingIndicators(
            suspicious_patterns=suspicious_patterns,
            domain_spoofing=domain_spoofing,
            suspicious_links=suspicious_links,
            brand_impersonation=brand_impersonation,
            urgency_indicators=urgency_indicators,
            social_engineering=social_engineering
        )
    
    def calculate_security_score(self, spf: SPFAnalysis, dkim: DKIMAnalysis, 
                                dmarc: DMARCAnalysis, reputation: ReputationAnalysis,
                                phishing: PhishingIndicators) -> Tuple[float, str]:
        """Calculate overall security score and risk level"""
        
        score = 50  # Base score
        
        # SPF scoring
        if spf.spf_result == "pass":
            score += 20
        elif spf.spf_result == "softfail":
            score += 10
        elif spf.spf_result == "fail":
            score -= 20
        
        # DKIM scoring
        if dkim.dkim_signature_found:
            if dkim.dkim_valid:
                score += 15
            else:
                score -= 10
        
        # DMARC scoring
        if dmarc.dmarc_record_found:
            if dmarc.dmarc_compliance:
                score += 15
            if dmarc.dmarc_policy == "reject":
                score += 10
            elif dmarc.dmarc_policy == "quarantine":
                score += 5
        
        # Reputation scoring
        if reputation.domain_reputation == "good":
            score += 20
        elif reputation.domain_reputation == "malicious":
            score -= 40
        elif reputation.domain_reputation == "poor":
            score -= 20
        
        # Phishing indicators
        score -= len(phishing.suspicious_patterns) * 5
        score -= len(phishing.urgency_indicators) * 3
        score -= len(phishing.social_engineering) * 5
        
        if phishing.domain_spoofing:
            score -= 30
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        
        # Determine risk level
        if score >= 80:
            risk_level = "low"
        elif score >= 60:
            risk_level = "medium"
        elif score >= 30:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        return score, risk_level
    
    def generate_recommendations(self, spf: SPFAnalysis, dkim: DKIMAnalysis,
                               dmarc: DMARCAnalysis, reputation: ReputationAnalysis,
                               phishing: PhishingIndicators, risk_level: str) -> List[str]:
        """Generate security recommendations"""
        
        recommendations = []
        
        # Risk-based recommendations
        if risk_level == "critical":
            recommendations.append("URGENT: This email shows critical security risks - treat as highly suspicious")
        elif risk_level == "high":
            recommendations.append("High risk email - exercise extreme caution")
        
        # Authentication recommendations
        if not spf.spf_record_found:
            recommendations.append("Sender domain lacks SPF record - treat with caution")
        elif spf.spf_result in ["fail", "softfail"]:
            recommendations.append("SPF authentication failed - email may be spoofed")
        
        if not dkim.dkim_signature_found:
            recommendations.append("No DKIM signature found - authenticity cannot be verified")
        elif not dkim.dkim_valid:
            recommendations.append("DKIM signature validation failed - email may be tampered")
        
        if not dmarc.dmarc_record_found:
            recommendations.append("Sender domain lacks DMARC policy")
        elif not dmarc.dmarc_compliance:
            recommendations.append("Email fails DMARC authentication")
        
        # Reputation recommendations
        if reputation.domain_reputation in ["malicious", "poor"]:
            recommendations.append("Sender has poor reputation - avoid interaction")
        
        # Phishing recommendations
        if phishing.domain_spoofing:
            recommendations.append("PHISHING ALERT: Domain appears to spoof legitimate brand")
        
        if phishing.suspicious_patterns:
            recommendations.append("Multiple suspicious patterns detected")
        
        # General recommendations
        recommendations.extend([
            "Verify sender identity through alternative means",
            "Do not click links or download attachments if suspicious",
            "Report phishing attempts to security team",
            "Keep email security software updated"
        ])
        
        return recommendations
    
    async def analyze_email(self, headers_text: str, sender_email: Optional[str] = None,
                           check_spf: bool = True, check_dkim: bool = True,
                           check_dmarc: bool = True) -> Dict[str, Any]:
        """Perform comprehensive email security analysis"""
        
        # Parse headers
        parsed_headers = self.parse_email_headers(headers_text)
        
        # Use provided sender email if available
        if sender_email:
            parsed_headers['sender_email'] = sender_email
            parsed_headers['sender_domain'] = sender_email.split('@')[1]
        
        # Perform authentication checks
        spf_analysis = SPFAnalysis(
            spf_record_found=False, spf_record=None, spf_result="none",
            spf_issues=[], authorized_senders=[]
        )
        if check_spf:
            spf_analysis = self.analyze_spf(
                parsed_headers['sender_domain'], 
                parsed_headers['sender_ip']
            )
        
        dkim_analysis = DKIMAnalysis(
            dkim_signature_found=False, dkim_valid=False, dkim_domain=None,
            dkim_selector=None, dkim_algorithm=None, dkim_issues=[]
        )
        if check_dkim:
            dkim_analysis = self.analyze_dkim(parsed_headers)
        
        dmarc_analysis = DMARCAnalysis(
            dmarc_record_found=False, dmarc_record=None, dmarc_policy=None,
            dmarc_alignment={}, dmarc_issues=[], dmarc_compliance=False
        )
        if check_dmarc:
            dmarc_analysis = self.analyze_dmarc(
                parsed_headers['sender_domain'],
                spf_analysis.spf_result,
                dkim_analysis.dkim_valid
            )
        
        # Analyze routing, reputation, and phishing indicators
        email_routing = self.analyze_email_routing(parsed_headers['received_headers'])
        reputation_analysis = self.analyze_reputation(
            parsed_headers['sender_domain'],
            parsed_headers['sender_ip']
        )
        phishing_indicators = self.detect_phishing_indicators(parsed_headers)
        
        # Calculate security score
        security_score, risk_level = self.calculate_security_score(
            spf_analysis, dkim_analysis, dmarc_analysis, 
            reputation_analysis, phishing_indicators
        )
        
        # Generate authentication summary
        auth_summary = {
            "SPF": spf_analysis.spf_result,
            "DKIM": "pass" if dkim_analysis.dkim_valid else "fail",
            "DMARC": "pass" if dmarc_analysis.dmarc_compliance else "fail"
        }
        
        # Generate recommendations
        recommendations = self.generate_recommendations(
            spf_analysis, dkim_analysis, dmarc_analysis,
            reputation_analysis, phishing_indicators, risk_level
        )
        
        return {
            'parsed_headers': parsed_headers,
            'spf_analysis': spf_analysis,
            'dkim_analysis': dkim_analysis,
            'dmarc_analysis': dmarc_analysis,
            'email_routing': email_routing,
            'reputation_analysis': reputation_analysis,
            'phishing_indicators': phishing_indicators,
            'security_score': security_score,
            'risk_level': risk_level,
            'auth_summary': auth_summary,
            'recommendations': recommendations
        }


async def execute_tool(input_data: EmailSecurityInput) -> EmailSecurityOutput:
    """Execute the email security analyzer tool"""
    
    try:
        analyzer = EmailSecurityAnalyzer()
        
        # Perform analysis
        results = await analyzer.analyze_email(
            input_data.email_headers,
            input_data.sender_email,
            input_data.check_spf,
            input_data.check_dkim,
            input_data.check_dmarc
        )
        
        parsed = results['parsed_headers']
        
        return EmailSecurityOutput(
            success=True,
            sender_email=parsed['sender_email'],
            sender_domain=parsed['sender_domain'],
            sender_ip=parsed['sender_ip'],
            spf_analysis=results['spf_analysis'],
            dkim_analysis=results['dkim_analysis'],
            dmarc_analysis=results['dmarc_analysis'],
            email_routing=results['email_routing'],
            reputation_analysis=results['reputation_analysis'],
            phishing_indicators=results['phishing_indicators'],
            security_score=results['security_score'],
            risk_level=results['risk_level'],
            authentication_summary=results['auth_summary'],
            recommendations=results['recommendations'],
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        return EmailSecurityOutput(
            success=False,
            sender_email="",
            sender_domain="",
            sender_ip=None,
            spf_analysis=SPFAnalysis(
                spf_record_found=False, spf_record=None, spf_result="none",
                spf_issues=[], authorized_senders=[]
            ),
            dkim_analysis=DKIMAnalysis(
                dkim_signature_found=False, dkim_valid=False, dkim_domain=None,
                dkim_selector=None, dkim_algorithm=None, dkim_issues=[]
            ),
            dmarc_analysis=DMARCAnalysis(
                dmarc_record_found=False, dmarc_record=None, dmarc_policy=None,
                dmarc_alignment={}, dmarc_issues=[], dmarc_compliance=False
            ),
            email_routing=EmailRouting(
                hop_count=0, routing_path=[], suspicious_hops=[],
                geo_locations=[], delivery_delay=None
            ),
            reputation_analysis=ReputationAnalysis(
                domain_reputation="unknown", ip_reputation="unknown", sender_score=0.0,
                blacklist_status={}, whitelist_status={}, domain_age_days=None
            ),
            phishing_indicators=PhishingIndicators(
                suspicious_patterns=[], domain_spoofing=False, suspicious_links=[],
                brand_impersonation=None, urgency_indicators=[], social_engineering=[]
            ),
            security_score=0.0,
            risk_level="unknown",
            authentication_summary={},
            recommendations=[],
            analysis_timestamp=datetime.now(timezone.utc),
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "email_security_analyzer",
    "display_name": "Email Security Analyzer",
    "description": "Comprehensive email security analysis including SPF, DKIM, DMARC, and phishing detection",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "email_security"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        sample_headers = """From: user@example.com
To: recipient@gmail.com
Subject: Urgent: Verify your account
Date: Sun, 15 Jun 2025 16:00:00 +0000
Received: from mail.example.com [192.168.1.1] by gmail.com
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=default; c=relaxed/relaxed
"""
        
        test_input = EmailSecurityInput(
            email_headers=sample_headers,
            check_spf=True,
            check_dkim=True,
            check_dmarc=True,
            analyze_reputation=True
        )
        
        result = await execute_tool(test_input)
        print(f"Email Analysis Success: {result.success}")
        print(f"Sender: {result.sender_email}")
        print(f"Security Score: {result.security_score}")
        print(f"Risk Level: {result.risk_level}")
        print(f"SPF: {result.authentication_summary.get('SPF', 'unknown')}")
        print(f"DKIM: {result.authentication_summary.get('DKIM', 'unknown')}")
        print(f"DMARC: {result.authentication_summary.get('DMARC', 'unknown')}")
    
    asyncio.run(test())
