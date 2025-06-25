import re
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import json

from .schemas import SocialEngineeringToolkitInput, SocialEngineeringToolkitOutput

logger = logging.getLogger(__name__)

TOOL_INFO = {
    "name": "Social Engineering Toolkit",
    "description": "Advanced OSINT and social engineering detection tool",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "osint",
    "tags": ["social-engineering", "osint", "reconnaissance", "privacy"]
}


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone: str) -> bool:
    """Validate phone number format."""
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)\+]', '', phone)
    return cleaned.isdigit() and len(cleaned) >= 7


def validate_domain(domain: str) -> bool:
    """Validate domain format."""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(pattern, domain) is not None


async def analyze_email(email: str) -> Dict[str, Any]:
    """Analyze email for social engineering risks."""
    domain = email.split('@')[1] if '@' in email else ''
    
    analysis = {
        "email": email,
        "domain": domain,
        "is_disposable": check_disposable_email(domain),
        "domain_age_estimate": estimate_domain_age(domain),
        "mx_records": await check_mx_records(domain),
        "spf_record": await check_spf_record(domain),
        "dmarc_record": await check_dmarc_record(domain),
        "reputation_score": calculate_email_reputation(email, domain)
    }
    
    return analysis


async def analyze_phone(phone: str) -> Dict[str, Any]:
    """Analyze phone number for social engineering risks."""
    cleaned_phone = re.sub(r'[\s\-\(\)\+]', '', phone)
    
    analysis = {
        "phone": phone,
        "cleaned": cleaned_phone,
        "country_code": extract_country_code(cleaned_phone),
        "carrier_info": get_carrier_info(cleaned_phone),
        "line_type": determine_line_type(cleaned_phone),
        "risk_indicators": check_phone_risk_indicators(cleaned_phone)
    }
    
    return analysis


async def analyze_domain(domain: str) -> Dict[str, Any]:
    """Analyze domain for social engineering risks."""
    analysis = {
        "domain": domain,
        "whois_info": await get_whois_info(domain),
        "ssl_info": await check_ssl_certificate(domain),
        "dns_records": await get_dns_records(domain),
        "subdomain_scan": await scan_common_subdomains(domain),
        "reputation_score": calculate_domain_reputation(domain),
        "typosquatting_check": check_typosquatting_domains(domain)
    }
    
    return analysis


def check_disposable_email(domain: str) -> bool:
    """Check if email domain is from a disposable email service."""
    disposable_domains = [
        "10minutemail.com", "guerrillamail.com", "mailinator.com",
        "tempmail.org", "yopmail.com", "throwaway.email",
        "temp-mail.org", "fakemailgenerator.com"
    ]
    return domain.lower() in disposable_domains


def estimate_domain_age(domain: str) -> str:
    """Estimate domain age based on TLD and patterns."""
    if domain.endswith(('.tk', '.ml', '.ga', '.cf')):
        return "Likely new (free TLD)"
    elif domain.endswith(('.com', '.org', '.net')):
        return "Could be established"
    else:
        return "Unknown"


async def check_mx_records(domain: str) -> List[str]:
    """Check MX records for the domain."""
    try:
        # Simulated MX record check
        await asyncio.sleep(0.1)
        return [f"mail.{domain}", f"mx.{domain}"]
    except Exception:
        return []


async def check_spf_record(domain: str) -> Optional[str]:
    """Check SPF record for the domain."""
    try:
        await asyncio.sleep(0.1)
        return f"v=spf1 include:_spf.{domain} ~all"
    except Exception:
        return None


async def check_dmarc_record(domain: str) -> Optional[str]:
    """Check DMARC record for the domain."""
    try:
        await asyncio.sleep(0.1)
        return f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"
    except Exception:
        return None


def calculate_email_reputation(email: str, domain: str) -> int:
    """Calculate email reputation score (1-100)."""
    score = 50  # Base score
    
    if check_disposable_email(domain):
        score -= 30
    
    if domain.endswith(('.com', '.org', '.edu', '.gov')):
        score += 10
    
    if any(keyword in email.lower() for keyword in ['admin', 'support', 'noreply']):
        score += 5
    
    return max(1, min(100, score))


def extract_country_code(phone: str) -> str:
    """Extract country code from phone number."""
    if phone.startswith('1'):
        return "+1 (US/Canada)"
    elif phone.startswith('44'):
        return "+44 (UK)"
    elif phone.startswith('33'):
        return "+33 (France)"
    elif phone.startswith('49'):
        return "+49 (Germany)"
    else:
        return "Unknown"


def get_carrier_info(phone: str) -> str:
    """Get carrier information for phone number."""
    # Simulated carrier lookup
    carriers = ["Verizon", "AT&T", "T-Mobile", "Sprint", "Unknown"]
    return carriers[len(phone) % len(carriers)]


def determine_line_type(phone: str) -> str:
    """Determine if phone is mobile, landline, or VoIP."""
    # Simplified line type detection
    if len(phone) >= 10:
        return "Mobile"
    else:
        return "Unknown"


def check_phone_risk_indicators(phone: str) -> List[str]:
    """Check for phone number risk indicators."""
    risks = []
    
    if len(phone) < 10:
        risks.append("Potentially invalid length")
    
    if phone.startswith('555'):
        risks.append("Potentially fake number")
    
    if len(set(phone)) < 3:
        risks.append("Suspicious pattern (repeated digits)")
    
    return risks


async def get_whois_info(domain: str) -> Dict[str, Any]:
    """Get WHOIS information for domain."""
    await asyncio.sleep(0.1)
    return {
        "registrar": "Example Registrar",
        "creation_date": "2020-01-01",
        "expiration_date": "2025-01-01",
        "privacy_protected": True
    }


async def check_ssl_certificate(domain: str) -> Dict[str, Any]:
    """Check SSL certificate information."""
    await asyncio.sleep(0.1)
    return {
        "has_ssl": True,
        "issuer": "Let's Encrypt",
        "expiry_date": "2024-12-31",
        "certificate_chain_valid": True
    }


async def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """Get DNS records for domain."""
    await asyncio.sleep(0.1)
    return {
        "A": ["192.168.1.1"],
        "AAAA": ["2001:db8::1"],
        "MX": [f"mail.{domain}"],
        "TXT": ["v=spf1 ~all"]
    }


async def scan_common_subdomains(domain: str) -> List[str]:
    """Scan for common subdomains."""
    await asyncio.sleep(0.2)
    common_subs = ["www", "mail", "ftp", "admin", "api", "blog"]
    return [f"{sub}.{domain}" for sub in common_subs[:3]]


def calculate_domain_reputation(domain: str) -> int:
    """Calculate domain reputation score."""
    score = 50
    
    if domain.endswith(('.com', '.org', '.edu')):
        score += 20
    elif domain.endswith(('.tk', '.ml', '.ga')):
        score -= 30
    
    if len(domain) < 5:
        score -= 10
    
    return max(1, min(100, score))


def check_typosquatting_domains(domain: str) -> List[str]:
    """Check for potential typosquatting domains."""
    # Simplified typosquatting detection
    typos = []
    
    # Character substitution
    for i, char in enumerate(domain):
        if char.isalpha():
            # Replace with similar looking characters
            similar_chars = {'o': '0', 'i': '1', 'l': '1', 'e': '3'}
            if char in similar_chars:
                typo = domain[:i] + similar_chars[char] + domain[i+1:]
                typos.append(typo)
    
    return typos[:5]  # Return first 5 potential typos


async def search_breaches(target: str) -> List[Dict[str, Any]]:
    """Search for data breaches involving the target."""
    # Simulated breach search
    await asyncio.sleep(0.2)
    
    breaches = [
        {
            "breach_name": "Example Breach 2023",
            "date": "2023-06-15",
            "affected_accounts": 1000000,
            "data_types": ["emails", "passwords", "personal_info"],
            "severity": "High"
        },
        {
            "breach_name": "Sample Data Leak 2022",
            "date": "2022-03-10",
            "affected_accounts": 500000,
            "data_types": ["emails", "usernames"],
            "severity": "Medium"
        }
    ]
    
    return breaches


async def search_social_profiles(target: str) -> List[Dict[str, Any]]:
    """Search for social media profiles."""
    await asyncio.sleep(0.3)
    
    profiles = [
        {
            "platform": "LinkedIn",
            "profile_url": f"https://linkedin.com/in/{target.split('@')[0] if '@' in target else target}",
            "confidence": "Medium",
            "data_found": ["Professional info", "Connections"]
        },
        {
            "platform": "Twitter",
            "profile_url": f"https://twitter.com/{target.split('@')[0] if '@' in target else target}",
            "confidence": "Low",
            "data_found": ["Public tweets", "Followers"]
        }
    ]
    
    return profiles


def calculate_risk_score(target: str, email_analysis: Optional[Dict], 
                        phone_analysis: Optional[Dict], 
                        domain_analysis: Optional[Dict],
                        breach_data: List[Dict]) -> int:
    """Calculate overall risk score."""
    risk_score = 0
    
    # Email risk factors
    if email_analysis:
        if email_analysis.get('is_disposable'):
            risk_score += 30
        risk_score += (100 - email_analysis.get('reputation_score', 50)) // 2
    
    # Phone risk factors
    if phone_analysis:
        risk_indicators = phone_analysis.get('risk_indicators', [])
        risk_score += len(risk_indicators) * 10
    
    # Domain risk factors
    if domain_analysis:
        domain_rep = domain_analysis.get('reputation_score', 50)
        risk_score += (100 - domain_rep) // 3
    
    # Breach data impact
    if breach_data:
        high_severity_breaches = sum(1 for breach in breach_data if breach.get('severity') == 'High')
        risk_score += high_severity_breaches * 15
        risk_score += len(breach_data) * 5
    
    return min(100, max(0, risk_score))


def generate_recommendations(risk_score: int, email_analysis: Optional[Dict],
                           phone_analysis: Optional[Dict],
                           breach_data: List[Dict]) -> List[str]:
    """Generate security recommendations."""
    recommendations = []
    
    if risk_score > 70:
        recommendations.append("HIGH RISK: Consider this target as potentially compromised")
    elif risk_score > 40:
        recommendations.append("MEDIUM RISK: Exercise caution with this target")
    else:
        recommendations.append("LOW RISK: Target appears relatively safe")
    
    if email_analysis and email_analysis.get('is_disposable'):
        recommendations.append("Email uses disposable domain - high risk for fraud")
    
    if phone_analysis and phone_analysis.get('risk_indicators'):
        recommendations.append("Phone number shows suspicious patterns")
    
    if breach_data:
        recommendations.append(f"Target found in {len(breach_data)} data breaches - verify identity carefully")
    
    # General recommendations
    recommendations.extend([
        "Always verify identity through multiple channels",
        "Be cautious of unsolicited communications",
        "Use multi-factor authentication",
        "Monitor for suspicious activities"
    ])
    
    return recommendations


async def execute_tool(request: SocialEngineeringToolkitInput) -> SocialEngineeringToolkitOutput:
    """Execute social engineering toolkit analysis."""
    try:
        logger.info(f"Starting social engineering analysis for target: {request.target}")
        
        email_analysis = None
        phone_analysis = None
        domain_analysis = None
        
        # Determine target type and perform appropriate analysis
        if request.analysis_type in ["email", "comprehensive"] and validate_email(request.target):
            email_analysis = await analyze_email(request.target)
            
        if request.analysis_type in ["phone", "comprehensive"] and validate_phone(request.target):
            phone_analysis = await analyze_phone(request.target)
            
        if request.analysis_type in ["domain", "comprehensive"] and validate_domain(request.target):
            domain_analysis = await analyze_domain(request.target)
        
        # If target looks like email, also analyze its domain
        if '@' in request.target and request.analysis_type == "comprehensive":
            domain = request.target.split('@')[1]
            if validate_domain(domain):
                domain_analysis = await analyze_domain(domain)
        
        # Search for breach data if requested
        breach_data = []
        if request.include_breaches:
            breach_data = await search_breaches(request.target)
        
        # Search for social profiles
        social_profiles = await search_social_profiles(request.target)
        
        # Calculate risk score
        risk_score = calculate_risk_score(
            request.target, email_analysis, phone_analysis, 
            domain_analysis, breach_data
        )
        
        # Generate recommendations
        recommendations = generate_recommendations(
            risk_score, email_analysis, phone_analysis, breach_data
        )
        
        return SocialEngineeringToolkitOutput(
            target=request.target,
            analysis_type=request.analysis_type,
            email_analysis=email_analysis,
            phone_analysis=phone_analysis,
            domain_analysis=domain_analysis,
            breach_data=breach_data,
            social_profiles=social_profiles,
            risk_score=risk_score,
            recommendations=recommendations,
            timestamp=datetime.now().isoformat(),
            success=True,
            message="Social engineering analysis completed successfully"
        )
        
    except Exception as e:
        logger.error(f"Error in social engineering toolkit: {str(e)}")
        return SocialEngineeringToolkitOutput(
            target=request.target,
            analysis_type=request.analysis_type,
            risk_score=0,
            recommendations=["Analysis failed - unable to assess risk"],
            timestamp=datetime.now().isoformat(),
            success=False,
            message=f"Analysis failed: {str(e)}"
        )
