"""
Certificate Authority Analyzer Tool

This tool analyzes SSL/TLS certificates, certificate chains, and certificate authorities
with comprehensive security assessment.
"""

import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import re

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from schemas import (
        CAAnalyzerInput, CAAnalyzerOutput, CertificateInfo, CertificateChainAnalysis,
        RevocationStatus, SecurityAnalysis
    )
except ImportError:
    from schemas import (
        CAAnalyzerInput, CAAnalyzerOutput, CertificateInfo, CertificateChainAnalysis,
        RevocationStatus, SecurityAnalysis
    )

# Tool metadata
TOOL_INFO = {
    "name": "Certificate Authority Analyzer",
    "description": "Comprehensive SSL/TLS certificate and Certificate Authority analysis tool that examines certificate chains, validates trust paths, checks revocation status, and analyzes security configurations",
    "category": "cryptography",
    "author": "Wildbox Security",
    "version": "1.0.0",
    "input_schema": CAAnalyzerInput,
    "output_schema": CAAnalyzerOutput,
    "tags": ["ssl", "tls", "certificates", "ca", "pki", "x509", "ocsp", "crl", "certificate-transparency"]
}


class CAAnalyzer:
    """Certificate Authority and SSL/TLS certificate analyzer"""
    
    # Weak signature algorithms
    WEAK_SIGNATURE_ALGORITHMS = [
        'md2', 'md4', 'md5', 'sha1withRSA', 'sha1WithRSAEncryption'
    ]
    
    # Minimum key sizes
    MIN_KEY_SIZES = {
        'rsa': 2048,
        'dsa': 2048,
        'ec': 256
    }
    
    # Trusted root CAs (subset)
    TRUSTED_ROOT_CAS = [
        'DigiCert', 'Let\'s Encrypt', 'Sectigo', 'GlobalSign', 'Entrust',
        'VeriSign', 'Thawte', 'GeoTrust', 'RapidSSL', 'Comodo'
    ]
    
    def __init__(self):
        pass
    
    def get_certificate_chain(self, hostname: str, port: int = 443, timeout: int = 30) -> List[bytes]:
        """Retrieve SSL certificate chain from server"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate chain
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get peer certificate chain
                    peer_cert_der = ssock.getpeercert_chain()
                    if peer_cert_der:
                        return [cert.public_bytes(encoding=ssl.Encoding.DER) for cert in peer_cert_der]
                    
                    # Fallback to just peer certificate
                    peer_cert = ssock.getpeercert_chain()
                    if peer_cert:
                        return [peer_cert[0].public_bytes(encoding=ssl.Encoding.DER)]
            
            return []
        except Exception as e:
            raise Exception(f"Failed to retrieve certificate chain: {str(e)}")
    
    def parse_certificate(self, cert_der: bytes) -> Dict[str, Any]:
        """Parse certificate and extract information"""
        if not CRYPTO_AVAILABLE:
            raise Exception("cryptography library not available for certificate parsing")
        
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Extract subject
            subject = {}
            for attribute in cert.subject:
                subject[attribute.oid._name] = attribute.value
            
            # Extract issuer
            issuer = {}
            for attribute in cert.issuer:
                issuer[attribute.oid._name] = attribute.value
            
            # Extract SAN (Subject Alternative Names)
            san_domains = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        san_domains.append(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # Get public key info
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                public_key_size = public_key.key_size
                if hasattr(public_key, 'algorithm'):
                    public_key_algorithm = public_key.algorithm.name
                else:
                    public_key_algorithm = type(public_key).__name__.lower().replace('publickey', '')
            else:
                public_key_size = 0
                public_key_algorithm = "unknown"
            
            # Calculate fingerprints
            sha256_fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
            sha1_fingerprint = hashlib.sha1(cert_der).hexdigest().upper()
            
            return {
                'subject': subject,
                'issuer': issuer,
                'serial_number': str(cert.serial_number),
                'version': cert.version.value,
                'not_before': cert.not_valid_before.replace(tzinfo=timezone.utc),
                'not_after': cert.not_valid_after.replace(tzinfo=timezone.utc),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'public_key_algorithm': public_key_algorithm,
                'public_key_size': public_key_size,
                'san_domains': san_domains,
                'fingerprint_sha256': sha256_fingerprint,
                'fingerprint_sha1': sha1_fingerprint,
                'cert_object': cert
            }
        except Exception as e:
            raise Exception(f"Failed to parse certificate: {str(e)}")
    
    def analyze_certificate_chain(self, chain_data: List[Dict[str, Any]]) -> CertificateChainAnalysis:
        """Analyze the certificate chain"""
        
        if not chain_data:
            return CertificateChainAnalysis(
                chain_length=0,
                root_ca="Unknown",
                intermediate_cas=[],
                is_self_signed=False,
                is_valid_chain=False,
                chain_issues=["No certificate chain found"]
            )
        
        chain_length = len(chain_data)
        chain_issues = []
        
        # Get root CA (last certificate in chain)
        root_cert = chain_data[-1]
        root_ca = root_cert['issuer'].get('commonName', 'Unknown')
        
        # Get intermediate CAs
        intermediate_cas = []
        for cert_data in chain_data[1:-1]:  # Skip leaf and root
            ca_name = cert_data['issuer'].get('commonName', 'Unknown')
            intermediate_cas.append(ca_name)
        
        # Check if self-signed (subject == issuer for leaf certificate)
        leaf_cert = chain_data[0]
        is_self_signed = (leaf_cert['subject'].get('commonName') == 
                         leaf_cert['issuer'].get('commonName'))
        
        # Basic chain validation
        is_valid_chain = True
        
        # Check chain length
        if chain_length < 2 and not is_self_signed:
            chain_issues.append("Incomplete certificate chain")
            is_valid_chain = False
        
        # Check if certificates are expired
        current_time = datetime.now(timezone.utc)
        for i, cert_data in enumerate(chain_data):
            if current_time > cert_data['not_after']:
                chain_issues.append(f"Certificate {i} in chain is expired")
                is_valid_chain = False
            if current_time < cert_data['not_before']:
                chain_issues.append(f"Certificate {i} in chain is not yet valid")
                is_valid_chain = False
        
        # Check signature algorithms
        for i, cert_data in enumerate(chain_data):
            if any(weak_alg in cert_data['signature_algorithm'].lower() 
                  for weak_alg in self.WEAK_SIGNATURE_ALGORITHMS):
                chain_issues.append(f"Certificate {i} uses weak signature algorithm: {cert_data['signature_algorithm']}")
        
        return CertificateChainAnalysis(
            chain_length=chain_length,
            root_ca=root_ca,
            intermediate_cas=intermediate_cas,
            is_self_signed=is_self_signed,
            is_valid_chain=is_valid_chain,
            chain_issues=chain_issues
        )
    
    def check_revocation_status(self, cert_data: Dict[str, Any]) -> RevocationStatus:
        """Check certificate revocation status (simplified implementation)"""
        
        # This is a simplified implementation
        # In a real scenario, you would:
        # 1. Parse CRL Distribution Points from certificate
        # 2. Download and parse CRL
        # 3. Check OCSP responder URLs
        # 4. Query OCSP responder
        
        return RevocationStatus(
            crl_checked=False,  # Would implement CRL checking
            ocsp_checked=False,  # Would implement OCSP checking
            is_revoked=False,  # Default to not revoked
            revocation_reason=None,
            revocation_date=None
        )
    
    def analyze_security(self, cert_data: Dict[str, Any], hostname: str, 
                        verify_hostname: bool = True) -> SecurityAnalysis:
        """Perform comprehensive security analysis"""
        
        current_time = datetime.now(timezone.utc)
        security_issues = []
        
        # Check expiration
        is_expired = current_time > cert_data['not_after']
        if is_expired:
            security_issues.append("Certificate is expired")
        
        # Calculate days until expiry
        days_until_expiry = (cert_data['not_after'] - current_time).days
        if days_until_expiry < 30 and not is_expired:
            security_issues.append(f"Certificate expires in {days_until_expiry} days")
        
        # Check signature algorithm
        is_weak_signature = any(weak_alg in cert_data['signature_algorithm'].lower() 
                               for weak_alg in self.WEAK_SIGNATURE_ALGORITHMS)
        if is_weak_signature:
            security_issues.append(f"Weak signature algorithm: {cert_data['signature_algorithm']}")
        
        # Check key strength
        is_weak_key = False
        key_alg = cert_data['public_key_algorithm'].lower()
        key_size = cert_data['public_key_size']
        
        for alg, min_size in self.MIN_KEY_SIZES.items():
            if alg in key_alg and key_size < min_size:
                is_weak_key = True
                security_issues.append(f"Weak {alg.upper()} key size: {key_size} bits (minimum: {min_size})")
        
        # Check hostname matching
        hostname_matches = True
        if verify_hostname:
            hostname_matches = self.verify_hostname_match(cert_data, hostname)
            if not hostname_matches:
                security_issues.append("Hostname does not match certificate")
        
        # Check for other security issues
        if cert_data['version'] < 3:
            security_issues.append(f"Old certificate version: v{cert_data['version']}")
        
        # Calculate security score
        security_score = 100
        if is_expired:
            security_score -= 50
        elif days_until_expiry < 7:
            security_score -= 30
        elif days_until_expiry < 30:
            security_score -= 15
        
        if is_weak_signature:
            security_score -= 25
        if is_weak_key:
            security_score -= 20
        if not hostname_matches:
            security_score -= 15
        
        security_score = max(0, security_score)
        
        return SecurityAnalysis(
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
            is_weak_signature=is_weak_signature,
            is_weak_key=is_weak_key,
            hostname_matches=hostname_matches,
            has_security_issues=len(security_issues) > 0,
            security_issues=security_issues,
            security_score=security_score
        )
    
    def verify_hostname_match(self, cert_data: Dict[str, Any], hostname: str) -> bool:
        """Verify if hostname matches certificate"""
        
        # Check common name
        common_name = cert_data['subject'].get('commonName', '')
        if common_name.lower() == hostname.lower():
            return True
        
        # Check Subject Alternative Names
        for san_domain in cert_data['san_domains']:
            if san_domain.lower() == hostname.lower():
                return True
            
            # Check wildcard domains
            if san_domain.startswith('*.'):
                wildcard_domain = san_domain[2:]
                if hostname.lower().endswith('.' + wildcard_domain.lower()):
                    return True
        
        return False
    
    def generate_recommendations(self, security_analysis: SecurityAnalysis,
                               chain_analysis: CertificateChainAnalysis) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Certificate expiration
        if security_analysis.is_expired:
            recommendations.append("URGENT: Renew expired certificate immediately")
        elif security_analysis.days_until_expiry < 30:
            recommendations.append("Renew certificate before expiration")
        
        # Signature and key strength
        if security_analysis.is_weak_signature:
            recommendations.append("Upgrade to stronger signature algorithm (SHA-256 or better)")
        if security_analysis.is_weak_key:
            recommendations.append("Generate new certificate with stronger key (RSA 2048+ or ECDSA)")
        
        # Hostname matching
        if not security_analysis.hostname_matches:
            recommendations.append("Ensure certificate Subject or SAN matches the hostname")
        
        # Certificate chain issues
        if not chain_analysis.is_valid_chain:
            recommendations.append("Fix certificate chain issues")
        if chain_analysis.is_self_signed:
            recommendations.append("Consider using a trusted Certificate Authority")
        
        # General recommendations
        recommendations.extend([
            "Monitor certificate expiration dates",
            "Implement Certificate Transparency monitoring",
            "Use HSTS to enforce HTTPS connections",
            "Regular security assessments of SSL/TLS configuration"
        ])
        
        return recommendations
    
    async def analyze_certificate(self, hostname: str, port: int = 443,
                                check_chain: bool = True, check_revocation: bool = True,
                                verify_hostname: bool = True, timeout: int = 30) -> Dict[str, Any]:
        """Perform comprehensive certificate analysis"""
        
        # Get certificate chain
        cert_chain_der = self.get_certificate_chain(hostname, port, timeout)
        if not cert_chain_der:
            raise Exception("No certificates found")
        
        # Parse certificates
        chain_data = []
        for cert_der in cert_chain_der:
            cert_data = self.parse_certificate(cert_der)
            chain_data.append(cert_data)
        
        # Analyze leaf certificate
        leaf_cert = chain_data[0]
        
        # Analyze certificate chain
        chain_analysis = self.analyze_certificate_chain(chain_data)
        
        # Check revocation status
        revocation_status = None
        if check_revocation:
            revocation_status = self.check_revocation_status(leaf_cert)
        
        # Perform security analysis
        security_analysis = self.analyze_security(leaf_cert, hostname, verify_hostname)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(security_analysis, chain_analysis)
        
        return {
            'certificate': leaf_cert,
            'chain_analysis': chain_analysis,
            'revocation_status': revocation_status,
            'security_analysis': security_analysis,
            'recommendations': recommendations
        }


async def execute_tool(input_data: CAAnalyzerInput) -> CAAnalyzerOutput:
    """Execute the CA analyzer tool"""
    
    try:
        analyzer = CAAnalyzer()
        
        # Perform analysis
        results = await analyzer.analyze_certificate(
            input_data.target,
            input_data.port,
            input_data.check_certificate_chain,
            input_data.check_revocation,
            input_data.verify_hostname,
            input_data.timeout
        )
        
        # Create certificate info
        cert_data = results['certificate']
        certificate_info = CertificateInfo(
            subject=cert_data['subject'],
            issuer=cert_data['issuer'],
            serial_number=cert_data['serial_number'],
            version=cert_data['version'],
            not_before=cert_data['not_before'],
            not_after=cert_data['not_after'],
            signature_algorithm=cert_data['signature_algorithm'],
            public_key_algorithm=cert_data['public_key_algorithm'],
            public_key_size=cert_data['public_key_size'],
            san_domains=cert_data['san_domains'],
            fingerprint_sha256=cert_data['fingerprint_sha256'],
            fingerprint_sha1=cert_data['fingerprint_sha1']
        )
        
        return CAAnalyzerOutput(
            success=True,
            target=input_data.target,
            port=input_data.port,
            certificate=certificate_info,
            chain_analysis=results['chain_analysis'],
            revocation_status=results['revocation_status'],
            security_analysis=results['security_analysis'],
            transparency_logs=None,  # Would implement CT log checking
            recommendations=results['recommendations'],
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
    except Exception as e:
        return CAAnalyzerOutput(
            success=False,
            target=input_data.target,
            port=input_data.port,
            certificate=CertificateInfo(
                subject={}, issuer={}, serial_number="", version=0,
                not_before=datetime.now(timezone.utc), not_after=datetime.now(timezone.utc),
                signature_algorithm="", public_key_algorithm="", public_key_size=0,
                san_domains=[], fingerprint_sha256="", fingerprint_sha1=""
            ),
            chain_analysis=CertificateChainAnalysis(
                chain_length=0, root_ca="", intermediate_cas=[], 
                is_self_signed=False, is_valid_chain=False, chain_issues=[]
            ),
            revocation_status=None,
            security_analysis=SecurityAnalysis(
                is_expired=False, days_until_expiry=0, is_weak_signature=False,
                is_weak_key=False, hostname_matches=False, has_security_issues=False,
                security_issues=[], security_score=0.0
            ),
            transparency_logs=None,
            recommendations=[],
            analysis_timestamp=datetime.now(timezone.utc),
            error=str(e)
        )

# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        test_input = CAAnalyzerInput(
            target="google.com",
            port=443,
            check_certificate_chain=True,
            verify_hostname=True
        )
        
        result = await execute_tool(test_input)
        print(f"CA Analysis Success: {result.success}")
        print(f"Target: {result.target}")
        print(f"Certificate Issuer: {result.certificate.issuer.get('commonName', 'Unknown')}")
        print(f"Expires: {result.certificate.not_after}")
        print(f"Security Score: {result.security_analysis.security_score}")
        print(f"Issues: {len(result.security_analysis.security_issues)}")
    
    asyncio.run(test())
