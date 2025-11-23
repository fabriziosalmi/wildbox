import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import json
import random
import hashlib

from schemas import CTLogScannerInput, CTLogScannerOutput, CertificateInfo

logger = logging.getLogger(__name__)

TOOL_INFO = {
    "name": "Certificate Transparency Log Scanner",
    "description": "Scan Certificate Transparency logs for domain certificates and security analysis",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "reconnaissance",
    "tags": ["certificates", "ct-logs", "ssl", "tls", "surveillance"]
}


class CTLogAPI:
    """Simulated Certificate Transparency Log API."""
    
    def __init__(self):
        self.common_issuers = [
            "Let's Encrypt Authority X3",
            "DigiCert Inc",
            "GlobalSign Organization Validation CA - SHA256 - G2",
            "Cloudflare Inc ECC CA-3",
            "Amazon",
            "GeoTrust RSA CA 2018",
            "Sectigo RSA Domain Validation Secure Server CA"
        ]
        
        self.key_algorithms = ["RSA", "ECDSA", "DSA"]
        self.signature_algorithms = [
            "sha256WithRSAEncryption",
            "ecdsa-with-SHA256",
            "sha1WithRSAEncryption"
        ]
    
    async def search_certificates(self, domain: str, include_subdomains: bool = True, 
                                 max_results: int = 100, days_back: int = 365) -> List[Dict[str, Any]]:
        """Search CT logs for certificates."""
        await asyncio.sleep(0.3)  # Simulate API delay
        
        certificates = []
        num_certs = min(max_results, random.randint(5, 50))
        
        # Generate simulated certificates
        for i in range(num_certs):
            cert_data = await self.generate_certificate_data(domain, include_subdomains, days_back)
            certificates.append(cert_data)
        
        return certificates
    
    async def generate_certificate_data(self, domain: str, include_subdomains: bool, days_back: int) -> Dict[str, Any]:
        """Generate simulated certificate data."""
        
        # Generate certificate dates
        not_before = datetime.now() - timedelta(days=random.randint(1, days_back))
        not_after = not_before + timedelta(days=random.randint(30, 395))
        is_expired = not_after < datetime.now()
        
        # Generate subject alternative names
        san_list = [domain]
        if include_subdomains:
            subdomains = [
                f"www.{domain}",
                f"mail.{domain}",
                f"api.{domain}",
                f"admin.{domain}",
                f"blog.{domain}",
                f"shop.{domain}",
                f"dev.{domain}",
                f"staging.{domain}"
            ]
            # Add random subdomains
            num_sans = random.randint(1, min(8, len(subdomains)))
            san_list.extend(random.sample(subdomains, num_sans))
        
        # Choose issuer and algorithms
        issuer = random.choice(self.common_issuers)
        key_algorithm = random.choice(self.key_algorithms)
        signature_algorithm = random.choice(self.signature_algorithms)
        
        # Generate key size based on algorithm
        if key_algorithm == "RSA":
            key_size = random.choice([2048, 3072, 4096])
        elif key_algorithm == "ECDSA":
            key_size = random.choice([256, 384, 521])
        else:
            key_size = 2048
        
        # Generate serial number and fingerprint
        serial_number = f"{random.randint(100000000000000000, 999999999999999999):X}"
        fingerprint_data = f"{domain}_{serial_number}_{issuer}".encode()
        fingerprint_sha256 = hashlib.sha256(fingerprint_data).hexdigest()
        
        # Check if self-signed (less common)
        is_self_signed = issuer == domain and random.random() < 0.05
        
        return {
            "serial_number": serial_number,
            "issuer": issuer if not is_self_signed else domain,
            "subject": f"CN={domain}",
            "subject_alt_names": san_list,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "key_algorithm": key_algorithm,
            "signature_algorithm": signature_algorithm,
            "key_size": key_size,
            "fingerprint_sha256": fingerprint_sha256,
            "ct_log_entry_id": f"{random.randint(1000000, 9999999)}",
            "log_timestamp": (not_before + timedelta(hours=random.randint(1, 24))).isoformat()
        }


def analyze_subdomains(certificates: List[CertificateInfo]) -> Dict[str, Any]:
    """Analyze subdomain patterns from certificates."""
    all_domains = set()
    
    for cert in certificates:
        all_domains.update(cert.subject_alt_names)
    
    # Extract subdomains
    subdomains = set()
    for domain in all_domains:
        if '.' in domain:
            parts = domain.split('.')
            if len(parts) > 2:  # It's a subdomain
                subdomains.add(domain)
    
    # Categorize subdomains
    categorized = {
        "web_services": [],
        "email_services": [],
        "development": [],
        "api_services": [],
        "admin_interfaces": [],
        "other": []
    }
    
    for subdomain in subdomains:
        lower_sub = subdomain.lower()
        if any(word in lower_sub for word in ['www', 'web', 'site']):
            categorized["web_services"].append(subdomain)
        elif any(word in lower_sub for word in ['mail', 'smtp', 'imap', 'pop']):
            categorized["email_services"].append(subdomain)
        elif any(word in lower_sub for word in ['dev', 'test', 'staging', 'qa']):
            categorized["development"].append(subdomain)
        elif any(word in lower_sub for word in ['api', 'service', 'rest']):
            categorized["api_services"].append(subdomain)
        elif any(word in lower_sub for word in ['admin', 'manage', 'control']):
            categorized["admin_interfaces"].append(subdomain)
        else:
            categorized["other"].append(subdomain)
    
    return {
        "total_unique_domains": len(all_domains),
        "total_subdomains": len(subdomains),
        "categorized_subdomains": categorized,
        "most_common_patterns": extract_common_patterns(list(subdomains))
    }


def extract_common_patterns(subdomains: List[str]) -> List[str]:
    """Extract common subdomain patterns."""
    patterns = {}
    
    for subdomain in subdomains:
        # Extract the first part before the main domain
        parts = subdomain.split('.')
        if len(parts) >= 2:
            pattern = parts[0]
            patterns[pattern] = patterns.get(pattern, 0) + 1
    
    # Return top 10 most common patterns
    sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
    return [pattern for pattern, count in sorted_patterns[:10]]


def analyze_issuers(certificates: List[CertificateInfo]) -> Dict[str, Any]:
    """Analyze certificate issuers."""
    issuer_counts = {}
    issuer_timeline = {}
    
    for cert in certificates:
        issuer = cert.issuer
        issuer_counts[issuer] = issuer_counts.get(issuer, 0) + 1
        
        # Track issuer usage over time
        cert_date = datetime.fromisoformat(cert.not_before)
        year_month = f"{cert_date.year}-{cert_date.month:02d}"
        
        if issuer not in issuer_timeline:
            issuer_timeline[issuer] = {}
        issuer_timeline[issuer][year_month] = issuer_timeline[issuer].get(year_month, 0) + 1
    
    # Sort by usage
    sorted_issuers = sorted(issuer_counts.items(), key=lambda x: x[1], reverse=True)
    
    return {
        "total_issuers": len(issuer_counts),
        "issuer_distribution": dict(sorted_issuers),
        "most_used_issuer": sorted_issuers[0] if sorted_issuers else None,
        "issuer_timeline": issuer_timeline,
        "free_vs_paid": classify_issuers(issuer_counts.keys())
    }


def classify_issuers(issuers: List[str]) -> Dict[str, List[str]]:
    """Classify issuers as free or paid services."""
    free_issuers = []
    paid_issuers = []
    
    for issuer in issuers:
        if "Let's Encrypt" in issuer:
            free_issuers.append(issuer)
        else:
            paid_issuers.append(issuer)
    
    return {
        "free_cas": free_issuers,
        "commercial_cas": paid_issuers
    }


def analyze_timeline(certificates: List[CertificateInfo]) -> Dict[str, Any]:
    """Analyze certificate timeline patterns."""
    issuance_dates = []
    expiry_dates = []
    cert_lifespans = []
    
    for cert in certificates:
        not_before = datetime.fromisoformat(cert.not_before)
        not_after = datetime.fromisoformat(cert.not_after)
        
        issuance_dates.append(not_before)
        expiry_dates.append(not_after)
        
        lifespan = (not_after - not_before).days
        cert_lifespans.append(lifespan)
    
    # Sort dates
    issuance_dates.sort()
    expiry_dates.sort()
    
    # Calculate patterns
    renewal_pattern = analyze_renewal_patterns(issuance_dates)
    
    return {
        "earliest_certificate": issuance_dates[0].isoformat() if issuance_dates else None,
        "latest_certificate": issuance_dates[-1].isoformat() if issuance_dates else None,
        "average_lifespan_days": sum(cert_lifespans) // len(cert_lifespans) if cert_lifespans else 0,
        "renewal_pattern": renewal_pattern,
        "certificates_expiring_soon": len([cert for cert in certificates if not cert.is_expired and 
                                         datetime.fromisoformat(cert.not_after) < datetime.now() + timedelta(days=30)]),
        "expired_certificates": len([cert for cert in certificates if cert.is_expired])
    }


def analyze_renewal_patterns(issuance_dates: List[datetime]) -> Dict[str, Any]:
    """Analyze certificate renewal patterns."""
    if len(issuance_dates) < 2:
        return {"pattern": "insufficient_data"}
    
    # Calculate gaps between renewals
    gaps = []
    for i in range(1, len(issuance_dates)):
        gap = (issuance_dates[i] - issuance_dates[i-1]).days
        gaps.append(gap)
    
    if not gaps:
        return {"pattern": "single_certificate"}
    
    avg_gap = sum(gaps) // len(gaps)
    
    if avg_gap < 30:
        pattern = "frequent_renewal"
    elif avg_gap < 90:
        pattern = "regular_renewal"
    else:
        pattern = "infrequent_renewal"
    
    return {
        "pattern": pattern,
        "average_renewal_gap_days": avg_gap,
        "renewal_frequency": f"Every {avg_gap} days on average"
    }


def generate_security_insights(certificates: List[CertificateInfo]) -> Dict[str, Any]:
    """Generate security insights from certificate analysis."""
    insights = {
        "algorithm_security": {},
        "key_strength": {},
        "issuer_trust": {},
        "certificate_hygiene": {}
    }
    
    # Analyze algorithms
    algorithms = {}
    key_sizes = {}
    weak_algorithms = []
    
    for cert in certificates:
        # Track signature algorithms
        sig_alg = cert.signature_algorithm
        algorithms[sig_alg] = algorithms.get(sig_alg, 0) + 1
        
        # Check for weak algorithms
        if "sha1" in sig_alg.lower():
            weak_algorithms.append(cert.serial_number)
        
        # Track key sizes
        if cert.key_size:
            key_combo = f"{cert.key_algorithm}-{cert.key_size}"
            key_sizes[key_combo] = key_sizes.get(key_combo, 0) + 1
    
    insights["algorithm_security"] = {
        "signature_algorithms": algorithms,
        "weak_algorithms_found": len(weak_algorithms),
        "weak_algorithm_certs": weak_algorithms[:5]  # Show first 5
    }
    
    insights["key_strength"] = {
        "key_size_distribution": key_sizes,
        "recommended_compliance": analyze_key_compliance(key_sizes)
    }
    
    # Analyze issuer trust
    self_signed_count = len([cert for cert in certificates if cert.is_self_signed])
    insights["issuer_trust"] = {
        "self_signed_certificates": self_signed_count,
        "trusted_ca_percentage": ((len(certificates) - self_signed_count) / len(certificates) * 100) if certificates else 0
    }
    
    # Certificate hygiene
    expired_count = len([cert for cert in certificates if cert.is_expired])
    insights["certificate_hygiene"] = {
        "expired_certificates": expired_count,
        "active_certificates": len(certificates) - expired_count,
        "expiration_hygiene": "Good" if expired_count < len(certificates) * 0.1 else "Needs attention"
    }
    
    return insights


def analyze_key_compliance(key_sizes: Dict[str, int]) -> Dict[str, str]:
    """Analyze key size compliance with current standards."""
    compliance = {}
    
    for key_combo, count in key_sizes.items():
        key_type, size_str = key_combo.split('-')
        size = int(size_str)
        
        if key_type == "RSA":
            if size >= 2048:
                compliance[key_combo] = "Compliant"
            else:
                compliance[key_combo] = "Weak"
        elif key_type == "ECDSA":
            if size >= 256:
                compliance[key_combo] = "Compliant"
            else:
                compliance[key_combo] = "Weak"
        else:
            compliance[key_combo] = "Unknown"
    
    return compliance


def detect_suspicious_patterns(certificates: List[CertificateInfo], subdomain_analysis: Dict[str, Any]) -> List[str]:
    """Detect suspicious patterns in certificates."""
    suspicious = []
    
    # Check for excessive subdomains
    subdomain_count = subdomain_analysis.get("total_subdomains", 0)
    if subdomain_count > 50:
        suspicious.append(f"Unusually high number of subdomains ({subdomain_count}) - possible subdomain enumeration")
    
    # Check for self-signed certificates
    self_signed = [cert for cert in certificates if cert.is_self_signed]
    if len(self_signed) > 3:
        suspicious.append(f"Multiple self-signed certificates ({len(self_signed)}) - possible testing or malicious activity")
    
    # Check for rapid certificate issuance
    recent_certs = []
    recent_threshold = datetime.now() - timedelta(days=7)
    
    for cert in certificates:
        if datetime.fromisoformat(cert.not_before) > recent_threshold:
            recent_certs.append(cert)
    
    if len(recent_certs) > 10:
        suspicious.append(f"High recent certificate issuance ({len(recent_certs)} in last 7 days) - possible automation or compromise")
    
    # Check for suspicious subdomain patterns
    admin_subdomains = subdomain_analysis.get("categorized_subdomains", {}).get("admin_interfaces", [])
    if len(admin_subdomains) > 5:
        suspicious.append(f"Multiple admin interfaces detected ({len(admin_subdomains)}) - increased attack surface")
    
    # Check for development/staging exposure
    dev_subdomains = subdomain_analysis.get("categorized_subdomains", {}).get("development", [])
    if len(dev_subdomains) > 3:
        suspicious.append(f"Development/staging environments exposed ({len(dev_subdomains)}) - potential information disclosure")
    
    # Check for weak algorithms
    weak_certs = [cert for cert in certificates if "sha1" in cert.signature_algorithm.lower()]
    if weak_certs:
        suspicious.append(f"Certificates using weak SHA-1 signature algorithm ({len(weak_certs)}) - security risk")
    
    return suspicious


def generate_recommendations(certificates: List[CertificateInfo], 
                           suspicious_patterns: List[str],
                           security_insights: Dict[str, Any]) -> List[str]:
    """Generate security recommendations."""
    recommendations = []
    
    # Certificate hygiene
    expired_count = security_insights.get("certificate_hygiene", {}).get("expired_certificates", 0)
    if expired_count > 0:
        recommendations.append(f"Remove or renew {expired_count} expired certificates to maintain security hygiene")
    
    # Algorithm recommendations
    weak_alg_count = security_insights.get("algorithm_security", {}).get("weak_algorithms_found", 0)
    if weak_alg_count > 0:
        recommendations.append("Upgrade certificates using weak signature algorithms (SHA-1) to SHA-256 or better")
    
    # Key size recommendations
    key_compliance = security_insights.get("key_strength", {}).get("recommended_compliance", {})
    weak_keys = [combo for combo, status in key_compliance.items() if status == "Weak"]
    if weak_keys:
        recommendations.append("Upgrade certificates with weak key sizes to meet current security standards")
    
    # Self-signed certificate recommendations
    self_signed_count = security_insights.get("issuer_trust", {}).get("self_signed_certificates", 0)
    if self_signed_count > 0:
        recommendations.append("Replace self-signed certificates with trusted CA-issued certificates for production use")
    
    # Subdomain management
    if any("subdomain" in pattern for pattern in suspicious_patterns):
        recommendations.append("Review and minimize exposed subdomains to reduce attack surface")
    
    # Monitoring recommendations
    recommendations.extend([
        "Implement certificate expiration monitoring and automated renewal",
        "Regularly scan CT logs for unauthorized certificates",
        "Monitor for suspicious certificate issuance patterns",
        "Implement Certificate Authority Authorization (CAA) DNS records"
    ])
    
    return recommendations


async def execute_tool(request: CTLogScannerInput) -> CTLogScannerOutput:
    """Execute Certificate Transparency log scanning."""
    try:
        logger.info(f"Starting CT log scan for domain: {request.domain}")
        
        # Initialize CT log API
        ct_api = CTLogAPI()
        
        # Search for certificates
        raw_certificates = await ct_api.search_certificates(
            request.domain,
            request.include_subdomains,
            request.max_results,
            request.days_back
        )
        
        # Convert to CertificateInfo objects and filter
        certificates = []
        for cert_data in raw_certificates:
            cert_info = CertificateInfo(**cert_data)
            
            # Filter out expired certificates if not requested
            if not request.include_expired and cert_info.is_expired:
                continue
                
            certificates.append(cert_info)
        
        # Perform analysis
        subdomain_analysis = analyze_subdomains(certificates)
        issuer_analysis = analyze_issuers(certificates)
        timeline_analysis = analyze_timeline(certificates)
        security_insights = generate_security_insights(certificates)
        
        # Detect suspicious patterns
        suspicious_patterns = detect_suspicious_patterns(certificates, subdomain_analysis)
        
        # Generate recommendations
        recommendations = generate_recommendations(certificates, suspicious_patterns, security_insights)
        
        return CTLogScannerOutput(
            domain=request.domain,
            certificates_found=certificates,
            subdomain_analysis=subdomain_analysis,
            issuer_analysis=issuer_analysis,
            timeline_analysis=timeline_analysis,
            security_insights=security_insights,
            suspicious_patterns=suspicious_patterns,
            recommendations=recommendations,
            total_certificates=len(certificates),
            search_timestamp=datetime.now().isoformat(),
            success=True,
            message=f"Found {len(certificates)} certificates for domain {request.domain}"
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Error in CT log scanner: {str(e)}")
        return CTLogScannerOutput(
            domain=request.domain,
            certificates_found=[],
            subdomain_analysis={},
            issuer_analysis={},
            timeline_analysis={},
            security_insights={},
            suspicious_patterns=[],
            recommendations=[],
            total_certificates=0,
            search_timestamp=datetime.now().isoformat(),
            success=False,
            message=f"CT log scan failed: {str(e)}"
        )
