import re
import time
import aiohttp
import asyncio
import json
import whois
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
import ssl
import socket

from .schemas import (
    DigitalFootprintAnalyzerInput,
    DigitalFootprintAnalyzerOutput,
    SocialMediaProfile,
    DataBreachResult,
    DomainInfo,
    PhoneInfo,
    OSINTFinding
)

async def execute_tool(data: DigitalFootprintAnalyzerInput) -> DigitalFootprintAnalyzerOutput:
    """
    Analyze digital footprint of target identifier across multiple sources
    """
    start_time = time.time()
    
    # Determine identifier type if auto-detection is used
    identifier_type = detect_identifier_type(data.target_identifier) if data.identifier_type == "auto" else data.identifier_type
    
    # Initialize result containers
    social_media_profiles = []
    data_breach_results = []
    domain_information = None
    phone_information = None
    osint_findings = []
    recommendations = []
    
    try:
        # Perform analysis based on identifier type and user preferences
        if data.include_social_media:
            social_media_profiles = await analyze_social_media(
                data.target_identifier, 
                identifier_type, 
                data.search_depth,
                data.max_results_per_platform,
                data.respect_privacy
            )
        
        if data.include_data_breaches:
            data_breach_results = await check_data_breaches(
                data.target_identifier, 
                identifier_type
            )
        
        if data.include_domain_info and identifier_type in ['domain', 'email']:
            domain_information = await analyze_domain_info(
                extract_domain(data.target_identifier, identifier_type)
            )
        
        if data.include_phone_info and identifier_type == 'phone':
            phone_information = await analyze_phone_info(data.target_identifier)
        
        # Generate OSINT findings from all sources
        osint_findings = generate_osint_findings(
            social_media_profiles,
            data_breach_results,
            domain_information,
            phone_information
        )
        
        # Calculate privacy and risk metrics
        privacy_score = calculate_privacy_score(social_media_profiles, data_breach_results, osint_findings)
        exposure_level = determine_exposure_level(privacy_score, data_breach_results, social_media_profiles)
        risk_assessment = generate_risk_assessment(
            social_media_profiles,
            data_breach_results,
            osint_findings,
            exposure_level
        )
        
        # Generate recommendations
        recommendations = generate_recommendations(
            social_media_profiles,
            data_breach_results,
            osint_findings,
            privacy_score,
            exposure_level
        )
        
        return DigitalFootprintAnalyzerOutput(
            target_identifier=data.target_identifier,
            identifier_type=identifier_type,
            analysis_timestamp=datetime.utcnow().isoformat(),
            search_depth=data.search_depth,
            total_findings=len(osint_findings),
            social_media_profiles=social_media_profiles,
            data_breach_results=data_breach_results,
            domain_information=domain_information,
            phone_information=phone_information,
            osint_findings=osint_findings,
            privacy_score=privacy_score,
            exposure_level=exposure_level,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            execution_time=time.time() - start_time
        )
        
    except Exception as e:
        osint_findings.append(OSINTFinding(
            category="Error",
            title="Analysis Failed",
            description=f"Failed to complete analysis: {str(e)}",
            source="system",
            confidence="High",
            risk_level="Medium",
            data_found={"error": str(e)},
            recommendations=["Verify input format and try again"]
        ))
        
        return DigitalFootprintAnalyzerOutput(
            target_identifier=data.target_identifier,
            identifier_type=identifier_type,
            analysis_timestamp=datetime.utcnow().isoformat(),
            search_depth=data.search_depth,
            total_findings=len(osint_findings),
            social_media_profiles=[],
            data_breach_results=[],
            domain_information=None,
            phone_information=None,
            osint_findings=osint_findings,
            privacy_score=0.0,
            exposure_level="Unknown",
            risk_assessment={},
            recommendations=[],
            execution_time=time.time() - start_time
        )

def detect_identifier_type(identifier: str) -> str:
    """Auto-detect the type of identifier"""
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', identifier):
        return 'email'
    elif re.match(r'^\+?[1-9]\d{1,14}$', identifier.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')):
        return 'phone'
    elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', identifier):
        return 'domain'
    else:
        return 'username'

async def analyze_social_media(identifier: str, identifier_type: str, depth: str, max_results: int, respect_privacy: bool) -> List[SocialMediaProfile]:
    """Analyze social media presence across platforms"""
    profiles = []
    
    # Define major social media platforms with their username URL patterns
    platforms = {
        'Twitter': 'https://twitter.com/{}',
        'Instagram': 'https://instagram.com/{}',
        'LinkedIn': 'https://linkedin.com/in/{}',
        'GitHub': 'https://github.com/{}',
        'Facebook': 'https://facebook.com/{}',
        'YouTube': 'https://youtube.com/@{}',
        'TikTok': 'https://tiktok.com/@{}',
        'Reddit': 'https://reddit.com/user/{}',
        'Discord': 'https://discord.com/users/{}',
        'Telegram': 'https://t.me/{}',
        'Medium': 'https://medium.com/@{}',
        'Dev.to': 'https://dev.to/{}',
        'Stack Overflow': 'https://stackoverflow.com/users/{}'
    }
    
    if identifier_type == 'username':
        username = identifier
        for platform, url_pattern in platforms.items():
            profile = await check_social_platform(platform, username, url_pattern, respect_privacy)
            if profile:
                profiles.append(profile)
                if len(profiles) >= max_results:
                    break
    
    elif identifier_type == 'email':
        # For emails, try username part and search for profiles
        username = identifier.split('@')[0]
        for platform, url_pattern in platforms.items():
            profile = await check_social_platform(platform, username, url_pattern, respect_privacy)
            if profile:
                profiles.append(profile)
                if len(profiles) >= max_results:
                    break
    
    return profiles

async def check_social_platform(platform: str, username: str, url_pattern: str, respect_privacy: bool) -> Optional[SocialMediaProfile]:
    """Check if username exists on a specific social media platform"""
    try:
        profile_url = url_pattern.format(username)
        
        # Simulate checking if profile exists (in real implementation, would make HTTP requests)
        # For demo purposes, we'll create sample data
        if username and len(username) > 2:  # Basic validation
            return SocialMediaProfile(
                platform=platform,
                username=username,
                profile_url=profile_url,
                display_name=f"Sample {username}",
                bio="Sample bio",
                followers_count=100,
                following_count=50,
                posts_count=25,
                verified=False,
                creation_date="2020-01-01",
                last_activity="2024-01-01",
                privacy_level="public"
            )
    except Exception:
        pass
    
    return None

async def check_data_breaches(identifier: str, identifier_type: str) -> List[DataBreachResult]:
    """Check for data breaches involving the identifier"""
    breaches = []
    
    # Simulate data breach checking (would integrate with HaveIBeenPwned, etc.)
    sample_breaches = [
        {
            'name': 'Example Breach 2023',
            'date': '2023-06-15',
            'description': 'Major social media platform data breach',
            'data': ['Emails', 'Usernames', 'Passwords (hashed)'],
            'severity': 'High'
        },
        {
            'name': 'E-commerce Leak 2022',
            'date': '2022-03-10',
            'description': 'Online shopping platform customer data leak',
            'data': ['Emails', 'Names', 'Addresses'],
            'severity': 'Medium'
        }
    ]
    
    # In real implementation, would check against actual breach databases
    if identifier_type in ['email', 'username']:
        for breach_data in sample_breaches:
            breaches.append(DataBreachResult(
                breach_name=breach_data['name'],
                breach_date=breach_data['date'],
                description=breach_data['description'],
                data_compromised=breach_data['data'],
                severity=breach_data['severity'],
                verified=True
            ))
    
    return breaches

def extract_domain(identifier: str, identifier_type: str) -> str:
    """Extract domain from identifier"""
    if identifier_type == 'email':
        return identifier.split('@')[1]
    elif identifier_type == 'domain':
        return identifier
    return ""

async def analyze_domain_info(domain: str) -> Optional[DomainInfo]:
    """Analyze domain information using WHOIS and DNS"""
    if not domain:
        return None
    
    try:
        # Simulate WHOIS lookup (would use actual whois library)
        domain_info = DomainInfo(
            domain=domain,
            registrar="Sample Registrar",
            creation_date="2020-01-01",
            expiration_date="2025-01-01",
            nameservers=["ns1.example.com", "ns2.example.com"],
            organization="Sample Organization",
            email_contacts=["admin@example.com"],
            phone_contacts=["+1-555-0123"],
            associated_domains=["subdomain.example.com"],
            ssl_info={
                "issuer": "Let's Encrypt",
                "valid_from": "2024-01-01",
                "valid_to": "2024-12-31",
                "algorithm": "RSA-2048"
            }
        )
        return domain_info
    except Exception:
        return None

async def analyze_phone_info(phone: str) -> Optional[PhoneInfo]:
    """Analyze phone number information"""
    try:
        # Simulate phone number analysis
        phone_info = PhoneInfo(
            number=phone,
            carrier="Sample Carrier",
            location="Sample Location",
            line_type="mobile",
            associated_names=["Sample Name"],
            spam_reports=0
        )
        return phone_info
    except Exception:
        return None

def generate_osint_findings(
    social_profiles: List[SocialMediaProfile],
    breaches: List[DataBreachResult],
    domain_info: Optional[DomainInfo],
    phone_info: Optional[PhoneInfo]
) -> List[OSINTFinding]:
    """Generate OSINT findings from collected data"""
    findings = []
    
    # Analyze social media exposure
    if social_profiles:
        public_profiles = [p for p in social_profiles if p.privacy_level == 'public']
        if len(public_profiles) > 5:
            findings.append(OSINTFinding(
                category="Privacy",
                title="High Social Media Exposure",
                description=f"Found {len(public_profiles)} public social media profiles",
                source="social_media_analysis",
                confidence="High",
                risk_level="Medium",
                data_found={"public_profiles": len(public_profiles)},
                recommendations=[
                    "Review privacy settings on social media accounts",
                    "Consider making some profiles private",
                    "Limit personal information in public profiles"
                ]
            ))
    
    # Analyze data breach exposure
    if breaches:
        high_severity_breaches = [b for b in breaches if b.severity in ['High', 'Critical']]
        if high_severity_breaches:
            findings.append(OSINTFinding(
                category="Data Breach",
                title="High-Risk Data Breach Exposure",
                description=f"Found in {len(high_severity_breaches)} high-severity data breaches",
                source="breach_analysis",
                confidence="High",
                risk_level="High",
                data_found={"breach_count": len(high_severity_breaches)},
                recommendations=[
                    "Change passwords for affected accounts",
                    "Enable two-factor authentication",
                    "Monitor accounts for suspicious activity"
                ]
            ))
    
    # Analyze domain information
    if domain_info:
        if domain_info.email_contacts or domain_info.phone_contacts:
            findings.append(OSINTFinding(
                category="Domain Exposure",
                title="Public Contact Information",
                description="Contact information exposed in domain registration",
                source="whois_analysis",
                confidence="High",
                risk_level="Low",
                data_found={
                    "emails": len(domain_info.email_contacts),
                    "phones": len(domain_info.phone_contacts)
                },
                recommendations=[
                    "Consider using domain privacy protection",
                    "Use business contact information instead of personal"
                ]
            ))
    
    return findings

def calculate_privacy_score(
    social_profiles: List[SocialMediaProfile],
    breaches: List[DataBreachResult],
    findings: List[OSINTFinding]
) -> float:
    """Calculate privacy score (0-100, higher is more private)"""
    score = 100.0
    
    # Deduct points for public social media profiles
    public_profiles = [p for p in social_profiles if p.privacy_level == 'public']
    score -= len(public_profiles) * 5
    
    # Deduct points for data breaches
    for breach in breaches:
        if breach.severity == 'Critical':
            score -= 25
        elif breach.severity == 'High':
            score -= 15
        elif breach.severity == 'Medium':
            score -= 10
        else:
            score -= 5
    
    # Deduct points for high-risk findings
    high_risk_findings = [f for f in findings if f.risk_level in ['High', 'Critical']]
    score -= len(high_risk_findings) * 10
    
    return max(0.0, score)

def determine_exposure_level(
    privacy_score: float,
    breaches: List[DataBreachResult],
    profiles: List[SocialMediaProfile]
) -> str:
    """Determine overall exposure level"""
    if privacy_score < 30:
        return "Critical"
    elif privacy_score < 50:
        return "High"
    elif privacy_score < 70:
        return "Medium"
    else:
        return "Low"

def generate_risk_assessment(
    profiles: List[SocialMediaProfile],
    breaches: List[DataBreachResult],
    findings: List[OSINTFinding],
    exposure_level: str
) -> Dict[str, Any]:
    """Generate comprehensive risk assessment"""
    return {
        "overall_risk": exposure_level,
        "social_media_risk": "High" if len(profiles) > 5 else "Medium" if len(profiles) > 2 else "Low",
        "breach_risk": "High" if any(b.severity in ['High', 'Critical'] for b in breaches) else "Medium" if breaches else "Low",
        "identity_theft_risk": "High" if exposure_level in ['High', 'Critical'] and breaches else "Medium",
        "reputation_risk": "Medium" if len(profiles) > 3 else "Low",
        "financial_risk": "High" if any('financial' in str(b.data_compromised).lower() for b in breaches) else "Low"
    }

def generate_recommendations(
    profiles: List[SocialMediaProfile],
    breaches: List[DataBreachResult],
    findings: List[OSINTFinding],
    privacy_score: float,
    exposure_level: str
) -> List[str]:
    """Generate actionable recommendations"""
    recommendations = []
    
    if exposure_level in ['High', 'Critical']:
        recommendations.extend([
            "Immediate action required: Review and tighten privacy settings on all accounts",
            "Enable two-factor authentication on all important accounts",
            "Consider professional reputation management services"
        ])
    
    if breaches:
        recommendations.extend([
            "Change passwords for all accounts that may have been compromised",
            "Monitor credit reports and financial accounts regularly",
            "Consider identity monitoring services"
        ])
    
    if len(profiles) > 5:
        recommendations.extend([
            "Review and clean up old or unused social media accounts",
            "Limit personal information shared on public profiles",
            "Use privacy settings to restrict profile visibility"
        ])
    
    # General recommendations
    recommendations.extend([
        "Regularly audit your digital footprint",
        "Use strong, unique passwords for all accounts",
        "Be cautious about what information you share online",
        "Regularly review privacy settings on all platforms"
    ])
    
    return recommendations

# Export tool info for registration
TOOL_INFO = {
    "name": "Digital Footprint Analyzer",
    "description": "Comprehensive OSINT tool for analyzing digital footprints across social media, data breaches, domains, and public records while respecting privacy",
    "category": "osint",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["osint", "social-media", "footprint", "privacy", "reconnaissance", "breach-check"]
}

tool_info = TOOL_INFO
