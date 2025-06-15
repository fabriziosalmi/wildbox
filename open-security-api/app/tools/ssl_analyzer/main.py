"""SSL/TLS Analyzer Tool - Analyzes SSL/TLS configuration and certificates."""

import ssl
import socket
from datetime import datetime, timezone
from typing import List, Dict
try:
    from .schemas import SSLAnalyzerInput, SSLAnalyzerOutput, CertificateInfo, SSLVulnerability
except ImportError:
    from schemas import SSLAnalyzerInput, SSLAnalyzerOutput, CertificateInfo, SSLVulnerability

def analyze_certificate(cert_der: bytes) -> CertificateInfo:
    """Analyze SSL certificate."""
    import cryptography.x509 as x509
    from cryptography.hazmat.backends import default_backend
    
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    
    # Extract subject information
    subject = {}
    for attribute in cert.subject:
        subject[attribute.oid._name] = attribute.value
    
    # Extract issuer information
    issuer = {}
    for attribute in cert.issuer:
        issuer[attribute.oid._name] = attribute.value
    
    # Extract SAN domains
    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                san_domains.append(name.value)
    except x509.ExtensionNotFound:
        pass
    
    # Calculate days until expiry
    now = datetime.now(timezone.utc)
    days_until_expiry = (cert.not_valid_after - now).days
    
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        serial_number=str(cert.serial_number),
        not_before=cert.not_valid_before.replace(tzinfo=timezone.utc),
        not_after=cert.not_valid_after.replace(tzinfo=timezone.utc),
        days_until_expiry=days_until_expiry,
        signature_algorithm=cert.signature_algorithm_oid._name,
        public_key_size=cert.public_key().key_size,
        san_domains=san_domains
    )

def check_vulnerabilities(ssl_version: str, cipher_suite: str, cert_info: CertificateInfo) -> List[SSLVulnerability]:
    """Check for SSL/TLS vulnerabilities."""
    vulnerabilities = []
    
    # Check for weak SSL/TLS versions
    if "SSLv2" in ssl_version or "SSLv3" in ssl_version:
        vulnerabilities.append(SSLVulnerability(
            name="Weak SSL/TLS Version",
            severity="high",
            description=f"Using deprecated {ssl_version} protocol"
        ))
    elif "TLSv1.0" in ssl_version or "TLSv1.1" in ssl_version:
        vulnerabilities.append(SSLVulnerability(
            name="Outdated TLS Version",
            severity="medium",
            description=f"Using outdated {ssl_version} protocol"
        ))
    
    # Check for weak ciphers
    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL"]
    for weak_cipher in weak_ciphers:
        if weak_cipher in cipher_suite:
            vulnerabilities.append(SSLVulnerability(
                name="Weak Cipher Suite",
                severity="high",
                description=f"Using weak cipher: {weak_cipher}"
            ))
    
    # Check certificate expiry
    if cert_info.days_until_expiry < 0:
        vulnerabilities.append(SSLVulnerability(
            name="Expired Certificate",
            severity="critical",
            description="SSL certificate has expired"
        ))
    elif cert_info.days_until_expiry < 30:
        vulnerabilities.append(SSLVulnerability(
            name="Certificate Expiring Soon",
            severity="medium",
            description=f"Certificate expires in {cert_info.days_until_expiry} days"
        ))
    
    # Check key size
    if cert_info.public_key_size < 2048:
        vulnerabilities.append(SSLVulnerability(
            name="Weak Key Size",
            severity="high",
            description=f"RSA key size is {cert_info.public_key_size} bits (minimum recommended: 2048)"
        ))
    
    # Check signature algorithm
    if "sha1" in cert_info.signature_algorithm.lower():
        vulnerabilities.append(SSLVulnerability(
            name="Weak Signature Algorithm",
            severity="medium",
            description="Certificate uses SHA-1 signature algorithm"
        ))
    
    return vulnerabilities

def calculate_security_score(ssl_version: str, cipher_suite: str, vulnerabilities: List[SSLVulnerability]) -> int:
    """Calculate security score based on configuration."""
    score = 100
    
    # Deduct points for vulnerabilities
    for vuln in vulnerabilities:
        if vuln.severity == "critical":
            score -= 25
        elif vuln.severity == "high":
            score -= 15
        elif vuln.severity == "medium":
            score -= 10
        elif vuln.severity == "low":
            score -= 5
    
    return max(0, score)

def generate_recommendations(vulnerabilities: List[SSLVulnerability], ssl_version: str) -> List[str]:
    """Generate security recommendations."""
    recommendations = []
    
    if any("TLS" not in ssl_version or "1.2" not in ssl_version for vuln in vulnerabilities):
        recommendations.append("Upgrade to TLS 1.2 or higher")
    
    if any("weak cipher" in vuln.description.lower() for vuln in vulnerabilities):
        recommendations.append("Configure strong cipher suites (AES-GCM, ChaCha20-Poly1305)")
    
    if any("expired" in vuln.name.lower() for vuln in vulnerabilities):
        recommendations.append("Renew SSL certificate immediately")
    
    if any("key size" in vuln.name.lower() for vuln in vulnerabilities):
        recommendations.append("Use RSA keys of 2048 bits or higher, or ECDSA keys")
    
    recommendations.extend([
        "Enable HTTP Strict Transport Security (HSTS)",
        "Implement Certificate Transparency monitoring",
        "Regular security assessments and certificate monitoring"
    ])
    
    return recommendations

def execute_tool(input_data: SSLAnalyzerInput) -> SSLAnalyzerOutput:
    """Execute the SSL/TLS analyzer tool."""
    timestamp = datetime.now()
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect to target
        with socket.create_connection((input_data.target, input_data.port), timeout=input_data.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=input_data.target) as ssock:
                # Get SSL information
                ssl_version = ssock.version()
                cipher_suite = ssock.cipher()[0] if ssock.cipher() else "Unknown"
                
                # Get certificate
                cert_der = ssock.getpeercert_chain()[0].to_bytes()
                cert_info = analyze_certificate(cert_der)
                
                # Check vulnerabilities
                vulnerabilities = check_vulnerabilities(ssl_version, cipher_suite, cert_info)
                
                # Calculate security score
                security_score = calculate_security_score(ssl_version, cipher_suite, vulnerabilities)
                
                # Generate recommendations
                recommendations = generate_recommendations(vulnerabilities, ssl_version)
                
                return SSLAnalyzerOutput(
                    target=input_data.target,
                    port=input_data.port,
                    timestamp=timestamp,
                    ssl_version=ssl_version,
                    cipher_suite=cipher_suite,
                    certificate=cert_info,
                    vulnerabilities=vulnerabilities,
                    security_score=security_score,
                    recommendations=recommendations
                )
                
    except Exception as e:
        # Return basic output with error information
        return SSLAnalyzerOutput(
            target=input_data.target,
            port=input_data.port,
            timestamp=timestamp,
            ssl_version="Unknown",
            cipher_suite="Unknown",
            certificate=CertificateInfo(
                subject={},
                issuer={},
                serial_number="Unknown",
                not_before=timestamp,
                not_after=timestamp,
                days_until_expiry=0,
                signature_algorithm="Unknown",
                public_key_size=0,
                san_domains=[]
            ),
            vulnerabilities=[SSLVulnerability(
                name="Connection Error",
                severity="critical",
                description=f"Failed to connect: {str(e)}"
            )],
            security_score=0,
            recommendations=["Check target accessibility and SSL configuration"]
        )

# Tool metadata
TOOL_INFO = {
    "name": "ssl_analyzer",
    "display_name": "SSL/TLS Analyzer",
    "description": "Analyzes SSL/TLS configuration, certificates, and security vulnerabilities",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "security_analysis"
}
