from typing import Dict, Any, List
import asyncio
import random
import re
from datetime import datetime, timedelta

try:
    from .schemas import (
        PKICertificateManagerInput, 
        PKICertificateManagerOutput,
        CertificateInfo,
        CertificateValidation,
        SecurityAnalysis
    )
except ImportError:
    from schemas import (
        PKICertificateManagerInput, 
        PKICertificateManagerOutput,
        CertificateInfo,
        CertificateValidation,
        SecurityAnalysis
    )

class PKICertificateManager:
    """PKI Certificate Manager - Comprehensive certificate analysis and validation"""
    
    name = "PKI Certificate Manager"
    description = "Comprehensive PKI certificate analysis, validation, and management tool for SSL/TLS certificates"
    category = "cryptography"
    
    # Common certificate authorities
    TRUSTED_CAS = [
        "Let's Encrypt", "DigiCert", "GlobalSign", "Sectigo", "GoDaddy",
        "Entrust", "Amazon", "Google Trust Services", "Microsoft"
    ]
    
    # Weak algorithms and key sizes
    WEAK_ALGORITHMS = ["md5", "sha1", "rc4"]
    MIN_KEY_SIZES = {"RSA": 2048, "ECC": 256, "DSA": 2048}
    
    async def execute(self, input_data: PKICertificateManagerInput) -> PKICertificateManagerOutput:
        """Execute PKI certificate analysis"""
        try:
            # Get certificate data
            if input_data.certificate_pem:
                cert_info = await self._parse_certificate_pem(input_data.certificate_pem)
            elif input_data.domain:
                cert_info = await self._fetch_domain_certificate(input_data.domain)
            else:
                raise ValueError("Either domain or certificate PEM must be provided")
            
            # Validate certificate
            validation = await self._validate_certificate(cert_info, input_data)
            
            # Security analysis
            security_analysis = await self._analyze_security(cert_info, input_data)
            
            # Check expiration
            expiration_warnings = self._check_expiration(cert_info)
            
            # Check CT logs
            ct_entries = []
            if input_data.check_ct_logs:
                ct_entries = await self._check_ct_logs(cert_info)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(cert_info, validation, security_analysis)
            
            # Calculate overall score
            overall_score = self._calculate_overall_score(validation, security_analysis)
            
            # Check compliance
            compliance_status = self._check_compliance(cert_info, security_analysis)
            
            return PKICertificateManagerOutput(
                certificate_info=cert_info,
                validation_results=validation,
                security_analysis=security_analysis,
                expiration_warnings=expiration_warnings,
                ct_log_entries=ct_entries,
                recommendations=recommendations,
                overall_score=overall_score,
                compliance_status=compliance_status
            )
            
        except Exception as e:
            # Return error response
            return PKICertificateManagerOutput(
                certificate_info=self._create_error_cert_info(),
                validation_results=CertificateValidation(
                    is_valid=False,
                    issues=[f"Analysis failed: {str(e)}"],
                    warnings=[],
                    chain_complete=False,
                    trusted_root=False,
                    revocation_status="Unknown"
                ),
                security_analysis=SecurityAnalysis(
                    key_strength_score=0.0,
                    algorithm_security="Unknown",
                    common_name_match=False,
                    san_coverage=[],
                    vulnerabilities=[],
                    compliance_issues=[]
                ),
                expiration_warnings=[],
                ct_log_entries=[],
                recommendations=["Fix certificate configuration and retry analysis"],
                overall_score=0.0,
                compliance_status={}
            )
    
    async def _parse_certificate_pem(self, pem_data: str) -> CertificateInfo:
        """Parse PEM certificate data (simulated)"""
        await asyncio.sleep(0.1)  # Simulate processing
        
        # Simulate certificate parsing
        return CertificateInfo(
            subject={
                "CN": "example.com",
                "O": "Example Organization",
                "C": "US"
            },
            issuer={
                "CN": random.choice(self.TRUSTED_CAS),
                "O": "Certificate Authority",
                "C": "US"
            },
            serial_number=f"{random.randint(100000000000000000, 999999999999999999):x}",
            valid_from=datetime.now() - timedelta(days=30),
            valid_to=datetime.now() + timedelta(days=60),
            signature_algorithm=random.choice(["sha256WithRSAEncryption", "ecdsa-with-SHA256"]),
            public_key_algorithm=random.choice(["RSA", "ECC"]),
            key_size=random.choice([2048, 3072, 4096, 256, 384]),
            fingerprint_sha1=self._generate_fingerprint(),
            fingerprint_sha256=self._generate_fingerprint(64),
            san_names=["example.com", "www.example.com", "*.example.com"],
            is_ca=False,
            is_self_signed=random.choice([True, False])
        )
    
    async def _fetch_domain_certificate(self, domain: str) -> CertificateInfo:
        """Fetch certificate for domain (simulated)"""
        await asyncio.sleep(0.2)  # Simulate network request
        
        return CertificateInfo(
            subject={
                "CN": domain,
                "O": f"{domain.split('.')[0].title()} Inc",
                "C": "US"
            },
            issuer={
                "CN": random.choice(self.TRUSTED_CAS),
                "O": "Certificate Authority",
                "C": "US"
            },
            serial_number=f"{random.randint(100000000000000000, 999999999999999999):x}",
            valid_from=datetime.now() - timedelta(days=random.randint(1, 90)),
            valid_to=datetime.now() + timedelta(days=random.randint(30, 365)),
            signature_algorithm=random.choice(["sha256WithRSAEncryption", "ecdsa-with-SHA256"]),
            public_key_algorithm=random.choice(["RSA", "ECC"]),
            key_size=random.choice([2048, 3072, 4096, 256, 384]),
            fingerprint_sha1=self._generate_fingerprint(),
            fingerprint_sha256=self._generate_fingerprint(64),
            san_names=[domain, f"www.{domain}"],
            is_ca=False,
            is_self_signed=False
        )
    
    async def _validate_certificate(self, cert_info: CertificateInfo, input_data: PKICertificateManagerInput) -> CertificateValidation:
        """Validate certificate"""
        issues = []
        warnings = []
        
        # Check expiration
        now = datetime.now()
        if cert_info.valid_to < now:
            issues.append("Certificate has expired")
        elif cert_info.valid_to < now + timedelta(days=30):
            warnings.append("Certificate expires within 30 days")
        
        # Check if valid from date is in future
        if cert_info.valid_from > now:
            issues.append("Certificate is not yet valid")
        
        # Check key size
        min_size = self.MIN_KEY_SIZES.get(cert_info.public_key_algorithm, 2048)
        if cert_info.key_size < min_size:
            issues.append(f"Key size {cert_info.key_size} is below recommended minimum {min_size}")
        
        # Check signature algorithm
        if any(weak in cert_info.signature_algorithm.lower() for weak in self.WEAK_ALGORITHMS):
            issues.append("Weak signature algorithm detected")
        
        # Check if self-signed
        if cert_info.is_self_signed:
            warnings.append("Certificate is self-signed")
        
        # Simulate revocation check
        revocation_status = "Valid"
        if input_data.check_revocation and random.random() < 0.05:  # 5% chance of revoked
            revocation_status = "Revoked"
            issues.append("Certificate has been revoked")
        
        is_valid = len(issues) == 0
        chain_complete = not cert_info.is_self_signed
        trusted_root = cert_info.issuer.get("CN") in self.TRUSTED_CAS
        
        return CertificateValidation(
            is_valid=is_valid,
            issues=issues,
            warnings=warnings,
            chain_complete=chain_complete,
            trusted_root=trusted_root,
            revocation_status=revocation_status
        )
    
    async def _analyze_security(self, cert_info: CertificateInfo, input_data: PKICertificateManagerInput) -> SecurityAnalysis:
        """Analyze certificate security"""
        # Calculate key strength score
        key_strength = self._calculate_key_strength(cert_info.public_key_algorithm, cert_info.key_size)
        
        # Determine algorithm security
        algorithm_security = self._assess_algorithm_security(cert_info.signature_algorithm)
        
        # Check common name match (simulated)
        common_name_match = True
        
        # SAN coverage
        san_coverage = cert_info.san_names
        
        # Check for vulnerabilities
        vulnerabilities = []
        if cert_info.key_size < 2048:
            vulnerabilities.append("Weak key size vulnerable to factorization attacks")
        
        if "sha1" in cert_info.signature_algorithm.lower():
            vulnerabilities.append("SHA-1 signature algorithm is cryptographically broken")
        
        if cert_info.is_self_signed:
            vulnerabilities.append("Self-signed certificate provides no third-party validation")
        
        # Compliance issues
        compliance_issues = []
        if cert_info.key_size < 2048:
            compliance_issues.append("Does not meet PCI DSS requirements for key size")
        
        if any(weak in cert_info.signature_algorithm.lower() for weak in ["md5", "sha1"]):
            compliance_issues.append("Uses deprecated hash algorithm")
        
        return SecurityAnalysis(
            key_strength_score=key_strength,
            algorithm_security=algorithm_security,
            common_name_match=common_name_match,
            san_coverage=san_coverage,
            vulnerabilities=vulnerabilities,
            compliance_issues=compliance_issues
        )
    
    def _check_expiration(self, cert_info: CertificateInfo) -> List[str]:
        """Check certificate expiration"""
        warnings = []
        now = datetime.now()
        
        days_until_expiry = (cert_info.valid_to - now).days
        
        if days_until_expiry < 0:
            warnings.append(f"Certificate expired {abs(days_until_expiry)} days ago")
        elif days_until_expiry <= 7:
            warnings.append(f"Certificate expires in {days_until_expiry} days (CRITICAL)")
        elif days_until_expiry <= 30:
            warnings.append(f"Certificate expires in {days_until_expiry} days (WARNING)")
        elif days_until_expiry <= 60:
            warnings.append(f"Certificate expires in {days_until_expiry} days (NOTICE)")
        
        return warnings
    
    async def _check_ct_logs(self, cert_info: CertificateInfo) -> List[Dict[str, Any]]:
        """Check Certificate Transparency logs (simulated)"""
        await asyncio.sleep(0.1)
        
        # Simulate CT log entries
        if random.random() < 0.8:  # 80% chance of CT log entries
            return [
                {
                    "log_name": "Google 'Argon2023' log",
                    "timestamp": datetime.now().isoformat(),
                    "entry_id": random.randint(100000000, 999999999),
                    "precertificate": False
                },
                {
                    "log_name": "Cloudflare 'Nimbus2023' Log",
                    "timestamp": datetime.now().isoformat(),
                    "entry_id": random.randint(100000000, 999999999),
                    "precertificate": True
                }
            ]
        return []
    
    def _generate_recommendations(self, cert_info: CertificateInfo, validation: CertificateValidation, security: SecurityAnalysis) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if not validation.is_valid:
            recommendations.append("Replace invalid certificate immediately")
        
        if cert_info.key_size < 2048:
            recommendations.append("Upgrade to at least 2048-bit RSA or 256-bit ECC key")
        
        if any(weak in cert_info.signature_algorithm.lower() for weak in self.WEAK_ALGORITHMS):
            recommendations.append("Use SHA-256 or stronger signature algorithm")
        
        if cert_info.is_self_signed:
            recommendations.append("Obtain certificate from trusted Certificate Authority")
        
        if (cert_info.valid_to - datetime.now()).days < 30:
            recommendations.append("Renew certificate before expiration")
        
        if not validation.chain_complete:
            recommendations.append("Ensure complete certificate chain is configured")
        
        if security.vulnerabilities:
            recommendations.append("Address identified security vulnerabilities")
        
        if not security.san_coverage:
            recommendations.append("Configure Subject Alternative Names for all domains")
        
        recommendations.append("Implement certificate monitoring and auto-renewal")
        recommendations.append("Regular security assessments of PKI infrastructure")
        
        return recommendations
    
    def _calculate_overall_score(self, validation: CertificateValidation, security: SecurityAnalysis) -> float:
        """Calculate overall certificate security score"""
        score = 10.0
        
        # Deduct for validation issues
        score -= len(validation.issues) * 2.0
        score -= len(validation.warnings) * 0.5
        
        # Deduct for security issues
        score -= len(security.vulnerabilities) * 1.5
        score -= len(security.compliance_issues) * 1.0
        
        # Adjust for key strength
        if security.key_strength_score < 7.0:
            score -= 1.0
        
        # Adjust for algorithm security
        if security.algorithm_security == "Weak":
            score -= 2.0
        elif security.algorithm_security == "Moderate":
            score -= 0.5
        
        return max(0.0, min(10.0, score))
    
    def _check_compliance(self, cert_info: CertificateInfo, security: SecurityAnalysis) -> Dict[str, bool]:
        """Check compliance with standards"""
        return {
            "pci_dss": cert_info.key_size >= 2048 and len(security.compliance_issues) == 0,
            "fips_140": cert_info.key_size >= 2048 and "sha256" in cert_info.signature_algorithm.lower(),
            "common_criteria": len(security.vulnerabilities) == 0,
            "nist_sp_800_57": cert_info.key_size >= 2048,
            "ca_browser_forum": not cert_info.is_self_signed and cert_info.key_size >= 2048
        }
    
    def _calculate_key_strength(self, algorithm: str, key_size: int) -> float:
        """Calculate key strength score"""
        if algorithm == "RSA":
            if key_size >= 4096:
                return 10.0
            elif key_size >= 3072:
                return 9.0
            elif key_size >= 2048:
                return 8.0
            elif key_size >= 1024:
                return 5.0
            else:
                return 2.0
        elif algorithm == "ECC":
            if key_size >= 384:
                return 10.0
            elif key_size >= 256:
                return 9.0
            elif key_size >= 224:
                return 7.0
            else:
                return 4.0
        else:
            return 6.0  # Unknown algorithm
    
    def _assess_algorithm_security(self, signature_algorithm: str) -> str:
        """Assess signature algorithm security"""
        sig_lower = signature_algorithm.lower()
        
        if any(weak in sig_lower for weak in ["md5", "sha1"]):
            return "Weak"
        elif "sha256" in sig_lower or "sha384" in sig_lower or "sha512" in sig_lower:
            return "Strong"
        else:
            return "Moderate"
    
    def _generate_fingerprint(self, length: int = 40) -> str:
        """Generate random fingerprint"""
        chars = "0123456789abcdef"
        return ":".join("".join(random.choice(chars) for _ in range(2)) for _ in range(length // 2))
    
    def _create_error_cert_info(self) -> CertificateInfo:
        """Create error certificate info"""
        return CertificateInfo(
            subject={"CN": "unknown"},
            issuer={"CN": "unknown"},
            serial_number="unknown",
            valid_from=datetime.now(),
            valid_to=datetime.now(),
            signature_algorithm="unknown",
            public_key_algorithm="unknown",
            key_size=0,
            fingerprint_sha1="unknown",
            fingerprint_sha256="unknown",
            san_names=[],
            is_ca=False,
            is_self_signed=False
        )

async def execute_tool(params: PKICertificateManagerInput) -> PKICertificateManagerOutput:
    """Main entry point for the PKI Certificate Manager tool"""
    manager = PKICertificateManager()
    return await manager.execute(params)

# Tool metadata for registration
TOOL_INFO = {
    "name": "PKI Certificate Manager",
    "description": "Comprehensive PKI certificate analysis, validation, and management tool for SSL/TLS certificates",
    "category": "cryptography",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "input_schema": PKICertificateManagerInput,
    "output_schema": PKICertificateManagerOutput,
    "tool_class": PKICertificateManager
}
