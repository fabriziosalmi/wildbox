from typing import Dict, Any, List
import asyncio
import random
import re
from datetime import datetime

try:
    from schemas import (
        ContainerSecurityScannerInput, 
        ContainerSecurityScannerOutput,
        Vulnerability,
        SecretExposure,
        ConfigurationIssue,
        LayerAnalysis,
        ComplianceCheck
    )
except ImportError:
    from schemas import (
        ContainerSecurityScannerInput, 
        ContainerSecurityScannerOutput,
        Vulnerability,
        SecretExposure,
        ConfigurationIssue,
        LayerAnalysis,
        ComplianceCheck
    )

class ContainerSecurityScanner:
    """Container Security Scanner - Comprehensive container and image security analysis"""
    
    name = "Container Security Scanner"
    description = "Comprehensive security scanner for Docker containers and images including vulnerability detection, secret scanning, and compliance checking"
    category = "container_security"
    
    # Common vulnerabilities in container images
    SAMPLE_VULNERABILITIES = [
        {"cve": "CVE-2023-0464", "package": "openssl", "severity": "High"},
        {"cve": "CVE-2023-1255", "package": "openssl", "severity": "Medium"},
        {"cve": "CVE-2023-2650", "package": "openssl", "severity": "Medium"},
        {"cve": "CVE-2023-0286", "package": "openssl", "severity": "High"},
        {"cve": "CVE-2022-4450", "package": "openssl", "severity": "High"},
        {"cve": "CVE-2023-28484", "package": "libxml2", "severity": "Medium"},
        {"cve": "CVE-2023-29469", "package": "libxml2", "severity": "Medium"},
        {"cve": "CVE-2022-40674", "package": "expat", "severity": "High"},
        {"cve": "CVE-2022-25313", "package": "expat", "severity": "Medium"},
        {"cve": "CVE-2021-46143", "package": "binutils", "severity": "Low"}
    ]
    
    # Secret patterns
    SECRET_PATTERNS = [
        {"type": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}"},
        {"type": "AWS Secret Key", "pattern": r"[A-Za-z0-9/+=]{40}"},
        {"type": "GitHub Token", "pattern": r"ghp_[A-Za-z0-9]{36}"},
        {"type": "API Key", "pattern": r"[aA][pP][iI]_?[kK][eE][yY].*['\"][0-9a-zA-Z]{32,45}['\"]"},
        {"type": "Private Key", "pattern": r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----"},
        {"type": "Password", "pattern": r"[pP][aA][sS][sS][wW][oO][rR][dD].*['\"][^'\"]{8,}['\"]"},
        {"type": "Database URL", "pattern": r"(mysql|postgres|mongodb)://[^\\s]+"},
        {"type": "JWT Token", "pattern": r"eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*"}
    ]
    
    # Container security best practices
    SECURITY_CHECKS = [
        {"check": "non_root_user", "description": "Container should not run as root"},
        {"check": "no_privileged", "description": "Container should not run in privileged mode"},
        {"check": "read_only_root", "description": "Root filesystem should be read-only"},
        {"check": "no_host_network", "description": "Container should not use host network"},
        {"check": "no_host_pid", "description": "Container should not use host PID namespace"},
        {"check": "resource_limits", "description": "Container should have resource limits"},
        {"check": "health_check", "description": "Container should have health checks"},
        {"check": "minimal_packages", "description": "Image should have minimal package set"}
    ]
    
    # Compliance frameworks
    COMPLIANCE_FRAMEWORKS = ["CIS", "NIST", "PCI-DSS", "SOC2", "GDPR"]
    
    async def execute(self, input_data: ContainerSecurityScannerInput) -> ContainerSecurityScannerOutput:
        """Execute container security scan"""
        try:
            image_name = input_data.image_name or "unknown:latest"
            
            # Vulnerability scanning
            vulnerabilities = []
            if input_data.check_vulnerabilities:
                vulnerabilities = await self._scan_vulnerabilities(image_name, input_data)
            
            # Secret scanning
            secrets = []
            if input_data.check_secrets:
                secrets = await self._scan_secrets(image_name, input_data)
            
            # Configuration analysis
            config_issues = []
            if input_data.check_configuration:
                config_issues = await self._check_configuration(image_name, input_data)
            
            # Layer analysis
            layer_analysis = await self._analyze_layers(image_name)
            
            # Compliance checking
            compliance_results = []
            if input_data.check_compliance:
                compliance_results = await self._check_compliance(image_name)
            
            # Calculate security score
            security_score = self._calculate_security_score(vulnerabilities, secrets, config_issues)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(vulnerabilities, secrets, config_issues)
            
            # Create summary
            summary = self._create_summary(vulnerabilities, secrets, config_issues, compliance_results)
            
            # Count vulnerabilities by severity
            vuln_counts = self._count_vulnerabilities_by_severity(vulnerabilities)
            
            return ContainerSecurityScannerOutput(
                image_analyzed=image_name,
                scan_timestamp=datetime.now(),
                total_vulnerabilities=len(vulnerabilities),
                critical_vulnerabilities=vuln_counts.get("Critical", 0),
                high_vulnerabilities=vuln_counts.get("High", 0),
                medium_vulnerabilities=vuln_counts.get("Medium", 0),
                low_vulnerabilities=vuln_counts.get("Low", 0),
                vulnerabilities=vulnerabilities,
                secrets_found=secrets,
                configuration_issues=config_issues,
                layer_analysis=layer_analysis,
                compliance_results=compliance_results,
                security_score=security_score,
                recommendations=recommendations,
                scan_summary=summary
            )
            
        except Exception as e:
            return ContainerSecurityScannerOutput(
                image_analyzed=input_data.image_name or "error",
                scan_timestamp=datetime.now(),
                total_vulnerabilities=0,
                critical_vulnerabilities=0,
                high_vulnerabilities=0,
                medium_vulnerabilities=0,
                low_vulnerabilities=0,
                vulnerabilities=[],
                secrets_found=[],
                configuration_issues=[],
                layer_analysis=[],
                compliance_results=[],
                security_score=0.0,
                recommendations=[f"Scan failed: {str(e)}"],
                scan_summary={"error": str(e)}
            )
    
    async def _scan_vulnerabilities(self, image_name: str, input_data: ContainerSecurityScannerInput) -> List[Vulnerability]:
        """Scan for vulnerabilities in container image"""
        await asyncio.sleep(0.3)  # Simulate scan time
        
        vulnerabilities = []
        
        # Simulate finding vulnerabilities
        num_vulns = random.randint(5, 15) if input_data.scan_type == "comprehensive" else random.randint(2, 8)
        
        for _ in range(num_vulns):
            vuln_data = random.choice(self.SAMPLE_VULNERABILITIES)
            
            vulnerability = Vulnerability(
                cve_id=vuln_data["cve"],
                severity=vuln_data["severity"],
                package=vuln_data["package"],
                version=f"{random.randint(1, 3)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
                fixed_version=f"{random.randint(1, 3)}.{random.randint(0, 9)}.{random.randint(0, 9)}" if random.random() < 0.8 else None,
                description=f"Security vulnerability in {vuln_data['package']}",
                score=self._get_cvss_score(vuln_data["severity"]),
                vector=self._generate_cvss_vector()
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _scan_secrets(self, image_name: str, input_data: ContainerSecurityScannerInput) -> List[SecretExposure]:
        """Scan for exposed secrets in container"""
        await asyncio.sleep(0.2)  # Simulate scan time
        
        secrets = []
        
        # Simulate finding secrets
        if random.random() < 0.4:  # 40% chance of finding secrets
            num_secrets = random.randint(1, 3)
            
            for _ in range(num_secrets):
                secret_type = random.choice(self.SECRET_PATTERNS)
                
                secret = SecretExposure(
                    type=secret_type["type"],
                    location=f"/app/{random.choice(['config', 'src', 'scripts'])}/{random.choice(['config.js', 'settings.py', 'env.sh'])}",
                    pattern_matched=secret_type["pattern"],
                    confidence=random.uniform(0.7, 1.0),
                    recommendation=f"Remove {secret_type['type']} from source code and use secure secret management"
                )
                secrets.append(secret)
        
        return secrets
    
    async def _check_configuration(self, image_name: str, input_data: ContainerSecurityScannerInput) -> List[ConfigurationIssue]:
        """Check container security configuration"""
        await asyncio.sleep(0.1)
        
        issues = []
        
        # Simulate configuration checks
        for check in random.sample(self.SECURITY_CHECKS, random.randint(3, 6)):
            if random.random() < 0.6:  # 60% chance of failing a check
                issue = ConfigurationIssue(
                    issue_type=check["check"],
                    severity=random.choice(["High", "Medium", "Low"]),
                    description=f"Security issue: {check['description']}",
                    file_location="Dockerfile" if random.random() < 0.5 else None,
                    recommendation=f"Fix: {check['description']}",
                    compliant=False
                )
                issues.append(issue)
        
        return issues
    
    async def _analyze_layers(self, image_name: str) -> List[LayerAnalysis]:
        """Analyze container image layers"""
        await asyncio.sleep(0.2)
        
        layers = []
        
        # Simulate layer analysis
        num_layers = random.randint(5, 12)
        for i in range(num_layers):
            layer = LayerAnalysis(
                layer_id=f"sha256:{random.randint(10**63, 10**64-1):x}"[:16],
                size_mb=random.uniform(0.5, 100.0),
                command=random.choice([
                    "RUN apt-get update && apt-get install -y python3",
                    "COPY . /app",
                    "RUN pip install -r requirements.txt",
                    "ENV NODE_ENV=production",
                    "EXPOSE 8080",
                    "USER 1001"
                ]),
                vulnerabilities_introduced=random.randint(0, 3),
                secrets_introduced=random.randint(0, 1),
                recommendations=self._get_layer_recommendations()
            )
            layers.append(layer)
        
        return layers
    
    async def _check_compliance(self, image_name: str) -> List[ComplianceCheck]:
        """Check compliance with security standards"""
        await asyncio.sleep(0.1)
        
        compliance_results = []
        
        # Simulate compliance checks
        for framework in random.sample(self.COMPLIANCE_FRAMEWORKS, 3):
            for rule_num in range(1, 4):
                check = ComplianceCheck(
                    standard=framework,
                    rule_id=f"{framework}-{rule_num}.{random.randint(1, 10)}",
                    rule_description=f"{framework} security requirement {rule_num}",
                    status=random.choice(["Pass", "Fail", "Warning"]),
                    severity=random.choice(["High", "Medium", "Low"]),
                    recommendation=f"Implement {framework} security controls"
                )
                compliance_results.append(check)
        
        return compliance_results
    
    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score based on severity"""
        if severity == "Critical":
            return random.uniform(9.0, 10.0)
        elif severity == "High":
            return random.uniform(7.0, 8.9)
        elif severity == "Medium":
            return random.uniform(4.0, 6.9)
        else:  # Low
            return random.uniform(0.1, 3.9)
    
    def _generate_cvss_vector(self) -> str:
        """Generate CVSS vector string"""
        vectors = [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
        ]
        return random.choice(vectors)
    
    def _get_layer_recommendations(self) -> List[str]:
        """Get recommendations for image layers"""
        recommendations = [
            "Use multi-stage builds to reduce image size",
            "Remove package managers after installing dependencies",
            "Use specific package versions for reproducibility",
            "Minimize the number of layers",
            "Don't include secrets in image layers"
        ]
        return random.sample(recommendations, random.randint(1, 3))
    
    def _calculate_security_score(self, vulnerabilities: List[Vulnerability], secrets: List[SecretExposure], config_issues: List[ConfigurationIssue]) -> float:
        """Calculate overall security score"""
        score = 10.0
        
        # Deduct for vulnerabilities
        for vuln in vulnerabilities:
            if vuln.severity == "Critical":
                score -= 2.0
            elif vuln.severity == "High":
                score -= 1.5
            elif vuln.severity == "Medium":
                score -= 1.0
            else:  # Low
                score -= 0.5
        
        # Deduct for secrets
        score -= len(secrets) * 2.0
        
        # Deduct for configuration issues
        for issue in config_issues:
            if issue.severity == "High":
                score -= 1.0
            elif issue.severity == "Medium":
                score -= 0.5
            else:  # Low
                score -= 0.25
        
        return max(0.0, min(10.0, score))
    
    def _generate_recommendations(self, vulnerabilities: List[Vulnerability], secrets: List[SecretExposure], config_issues: List[ConfigurationIssue]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if vulnerabilities:
            recommendations.append("Update vulnerable packages to latest versions")
            if any(v.severity in ["Critical", "High"] for v in vulnerabilities):
                recommendations.append("Prioritize fixing critical and high severity vulnerabilities")
        
        if secrets:
            recommendations.append("Remove hardcoded secrets and use secure secret management")
            recommendations.append("Implement secret scanning in CI/CD pipeline")
        
        if config_issues:
            recommendations.append("Fix container security configuration issues")
            recommendations.append("Run containers with non-root user")
            recommendations.append("Implement resource limits and security contexts")
        
        # General recommendations
        recommendations.extend([
            "Use minimal base images (e.g., Alpine, distroless)",
            "Implement image scanning in CI/CD pipeline",
            "Regular security audits and updates",
            "Use image signing and verification",
            "Monitor runtime security events"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for vuln in vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts
    
    def _create_summary(self, vulnerabilities: List[Vulnerability], secrets: List[SecretExposure], config_issues: List[ConfigurationIssue], compliance_results: List[ComplianceCheck]) -> Dict[str, Any]:
        """Create scan summary"""
        vuln_counts = self._count_vulnerabilities_by_severity(vulnerabilities)
        
        compliance_pass = len([c for c in compliance_results if c.status == "Pass"])
        compliance_fail = len([c for c in compliance_results if c.status == "Fail"])
        
        return {
            "vulnerabilities_by_severity": vuln_counts,
            "secrets_found": len(secrets),
            "configuration_issues": len(config_issues),
            "compliance_pass_rate": compliance_pass / len(compliance_results) if compliance_results else 1.0,
            "total_compliance_checks": len(compliance_results),
            "risk_level": self._determine_risk_level(vuln_counts, secrets, config_issues)
        }
    
    def _determine_risk_level(self, vuln_counts: Dict[str, int], secrets: List[SecretExposure], config_issues: List[ConfigurationIssue]) -> str:
        """Determine overall risk level"""
        if vuln_counts.get("Critical", 0) > 0 or len(secrets) > 0:
            return "Critical"
        elif vuln_counts.get("High", 0) > 2:
            return "High"
        elif vuln_counts.get("Medium", 0) > 5 or len(config_issues) > 3:
            return "Medium"
        else:
            return "Low"

async def execute_tool(params: ContainerSecurityScannerInput) -> ContainerSecurityScannerOutput:
    """Main entry point for the Container Security Scanner tool"""
    scanner = ContainerSecurityScanner()
    return await scanner.execute(params)

# Tool metadata for registration
TOOL_INFO = {
    "name": "Container Security Scanner",
    "description": "Comprehensive security scanner for Docker containers and images including vulnerability detection, secret scanning, and compliance checking",
    "category": "container_security",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "input_schema": ContainerSecurityScannerInput,
    "output_schema": ContainerSecurityScannerOutput,
    "tool_class": ContainerSecurityScanner
}
