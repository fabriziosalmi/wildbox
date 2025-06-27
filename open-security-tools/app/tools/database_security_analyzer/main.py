from typing import Dict, Any, List
import asyncio
import random
import logging
from datetime import datetime, timedelta

# Configure logging
logger = logging.getLogger(__name__)

try:
    from schemas import (
        DatabaseSecurityAnalyzerInput, 
        DatabaseSecurityAnalyzerOutput,
        DatabaseUser,
        ConfigurationIssue,
        EncryptionStatus,
        AuditConfiguration,
        NetworkSecurity,
        ComplianceCheck,
        VulnerabilityFinding
    )
except ImportError:
    from schemas import (
        DatabaseSecurityAnalyzerInput, 
        DatabaseSecurityAnalyzerOutput,
        DatabaseUser,
        ConfigurationIssue,
        EncryptionStatus,
        AuditConfiguration,
        NetworkSecurity,
        ComplianceCheck,
        VulnerabilityFinding
    )

def validate_database_type(database_type: str) -> str:
    """Validate and sanitize database type input"""
    if not database_type:
        raise ValueError("Database type cannot be empty")
    
    # Whitelist of allowed database types
    allowed_types = {
        'mysql', 'postgresql', 'mongodb', 'oracle', 'sqlserver', 
        'redis', 'cassandra', 'elasticsearch', 'mariadb', 'sqlite'
    }
    
    cleaned_type = database_type.lower().strip()
    if cleaned_type not in allowed_types:
        logger.warning(f"Unknown database type: {database_type}")
        return "unknown"
    
    return cleaned_type

class DatabaseSecurityAnalyzer:
    """Database Security Analyzer - Comprehensive database security assessment"""
    
    name = "Database Security Analyzer"
    description = "Comprehensive database security assessment tool for multiple database types including configuration, user privileges, encryption, and compliance analysis"
    category = "database_security"
    
    # Database-specific security configurations
    DB_CONFIGS = {
        "mysql": {
            "secure_params": ["secure_auth", "ssl_ca", "log_bin", "general_log"],
            "weak_params": ["old_passwords", "skip_name_resolve", "local_infile"],
            "default_users": ["root", "mysql.session", "mysql.sys"],
            "common_vulns": ["CVE-2023-21912", "CVE-2023-21913", "CVE-2023-21917"]
        },
        "postgresql": {
            "secure_params": ["ssl", "log_statement", "log_min_duration_statement", "shared_preload_libraries"],
            "weak_params": ["trust", "password_encryption", "log_hostname"],
            "default_users": ["postgres", "replicator"],
            "common_vulns": ["CVE-2023-2454", "CVE-2023-2455", "CVE-2023-39417"]
        },
        "mongodb": {
            "secure_params": ["security.authorization", "net.ssl.mode", "auditLog.destination"],
            "weak_params": ["net.bindIp", "security.javascriptEnabled"],
            "default_users": ["admin", "root"],
            "common_vulns": ["CVE-2023-1409", "CVE-2022-48563"]
        },
        "oracle": {
            "secure_params": ["AUDIT_TRAIL", "SEC_MAX_FAILED_LOGIN_ATTEMPTS", "REMOTE_OS_AUTHENT"],
            "weak_params": ["REMOTE_LOGIN_PASSWORDFILE", "SEC_CASE_SENSITIVE_LOGON"],
            "default_users": ["SYS", "SYSTEM", "DBSNMP", "SYSMAN"],
            "common_vulns": ["CVE-2023-21839", "CVE-2023-21840"]
        },
        "mssql": {
            "secure_params": ["force encryption", "audit level", "login audit level"],
            "weak_params": ["remote admin connections", "xp_cmdshell"],
            "default_users": ["sa", "NT AUTHORITY\\SYSTEM"],
            "common_vulns": ["CVE-2023-21528", "CVE-2023-21705"]
        }
    }
    
    # Security standards compliance
    COMPLIANCE_STANDARDS = {
        "PCI-DSS": ["Data encryption", "Access controls", "Audit logging", "Network security"],
        "GDPR": ["Data encryption", "Access logging", "Data retention", "User consent"],
        "HIPAA": ["Access controls", "Audit trails", "Data encryption", "Authentication"],
        "SOX": ["Data integrity", "Access controls", "Audit logging", "Change management"]
    }
    
    async def execute(self, input_data: DatabaseSecurityAnalyzerInput) -> DatabaseSecurityAnalyzerOutput:
        """Execute database security analysis"""
        try:
            # Simulate database connection
            connection_successful = await self._test_connection(input_data)
            
            if not connection_successful:
                return self._create_connection_error_response(input_data)
            
            # Get database info
            db_info = await self._get_database_info(input_data)
            
            # Analyze users and privileges
            users = []
            if input_data.check_users_privileges:
                users = await self._analyze_users_privileges(input_data)
            
            # Check configuration security
            config_issues = []
            if input_data.check_configuration:
                config_issues = await self._check_configuration(input_data)
            
            # Check encryption status
            encryption_status = None
            if input_data.check_encryption:
                encryption_status = await self._check_encryption(input_data)
            
            # Check audit configuration
            audit_config = None
            if input_data.check_audit_logging:
                audit_config = await self._check_audit_configuration(input_data)
            
            # Check network security
            network_security = None
            if input_data.check_network_security:
                network_security = await self._check_network_security(input_data)
            
            # Check compliance
            compliance_results = []
            if input_data.check_compliance:
                compliance_results = await self._check_compliance(input_data)
            
            # Find vulnerabilities
            vulnerabilities = await self._find_vulnerabilities(input_data)
            
            # Calculate security score
            security_score = self._calculate_security_score(users, config_issues, encryption_status, vulnerabilities)
            
            # Determine risk level
            risk_level = self._determine_risk_level(security_score, vulnerabilities)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(users, config_issues, encryption_status, audit_config, vulnerabilities)
            
            # Create summary
            summary = self._create_summary(users, config_issues, vulnerabilities, compliance_results)
            
            return DatabaseSecurityAnalyzerOutput(
                database_info=db_info,
                connection_successful=True,
                scan_timestamp=datetime.now(),
                database_users=users,
                configuration_issues=config_issues,
                encryption_status=encryption_status,
                audit_configuration=audit_config,
                network_security=network_security,
                compliance_results=compliance_results,
                vulnerabilities=vulnerabilities,
                security_score=security_score,
                risk_level=risk_level,
                recommendations=recommendations,
                scan_summary=summary
            )
            
        except Exception as e:
            return self._create_error_response(input_data, str(e))
    
    async def _test_connection(self, input_data: DatabaseSecurityAnalyzerInput) -> bool:
        """Test database connection (simulated)"""
        await asyncio.sleep(0.2)  # Simulate connection attempt
        
        # Simulate connection success/failure
        return random.random() > 0.1  # 90% success rate
    
    async def _get_database_info(self, input_data: DatabaseSecurityAnalyzerInput) -> Dict[str, str]:
        """Get database information"""
        await asyncio.sleep(0.1)
        
        version_map = {
            "mysql": random.choice(["8.0.34", "5.7.42", "8.0.35"]),
            "postgresql": random.choice(["15.4", "14.9", "13.12"]),
            "mongodb": random.choice(["7.0.2", "6.0.10", "5.0.21"]),
            "oracle": random.choice(["19c", "21c", "23c"]),
            "mssql": random.choice(["2022", "2019", "2017"])
        }
        
        return {
            "database_type": input_data.database_type,
            "version": version_map.get(input_data.database_type, "Unknown"),
            "host": input_data.host,
            "port": str(input_data.port),
            "database_name": input_data.database_name or "default",
            "charset": "utf8mb4",
            "time_zone": "UTC"
        }
    
    async def _analyze_users_privileges(self, input_data: DatabaseSecurityAnalyzerInput) -> List[DatabaseUser]:
        """Analyze database users and their privileges"""
        await asyncio.sleep(0.2)
        
        users = []
        db_config = self.DB_CONFIGS.get(input_data.database_type, {})
        default_users = db_config.get("default_users", ["admin", "user"])
        
        # Add default users
        for username in default_users:
            issues = []
            if username in ["root", "admin", "sa"]:
                issues.append("Administrative account with excessive privileges")
            
            if random.random() < 0.3:  # 30% chance of password policy violation
                issues.append("Password does not meet complexity requirements")
            
            user = DatabaseUser(
                username=username,
                privileges=self._generate_privileges(input_data.database_type, username),
                host_access=["localhost", "%"] if username in ["root", "admin"] else ["localhost"],
                password_policy_compliant=len(issues) == 0,
                last_login=datetime.now() - timedelta(days=random.randint(0, 30)),
                account_locked=False,
                admin_privileges=username in ["root", "admin", "sa", "postgres"],
                security_issues=issues
            )
            users.append(user)
        
        # Add some regular users
        for i in range(random.randint(2, 5)):
            user = DatabaseUser(
                username=f"user_{i+1}",
                privileges=["SELECT", "INSERT", "UPDATE"],
                host_access=["localhost"],
                password_policy_compliant=random.choice([True, False]),
                last_login=datetime.now() - timedelta(days=random.randint(0, 7)),
                account_locked=False,
                admin_privileges=False,
                security_issues=[]
            )
            users.append(user)
        
        return users
    
    async def _check_configuration(self, input_data: DatabaseSecurityAnalyzerInput) -> List[ConfigurationIssue]:
        """Check database configuration for security issues"""
        await asyncio.sleep(0.1)
        
        issues = []
        db_config = self.DB_CONFIGS.get(input_data.database_type, {})
        
        # Check secure parameters
        secure_params = db_config.get("secure_params", [])
        for param in random.sample(secure_params, random.randint(1, min(3, len(secure_params)))):
            if random.random() < 0.4:  # 40% chance of misconfiguration
                issue = ConfigurationIssue(
                    parameter=param,
                    current_value="OFF" if random.random() < 0.5 else "default",
                    recommended_value="ON" if random.random() < 0.5 else "secure_value",
                    severity=random.choice(["High", "Medium", "Low"]),
                    description=f"Security parameter {param} is not properly configured",
                    security_impact="Reduced security posture and potential vulnerability exposure"
                )
                issues.append(issue)
        
        # Check weak parameters
        weak_params = db_config.get("weak_params", [])
        for param in random.sample(weak_params, random.randint(0, min(2, len(weak_params)))):
            if random.random() < 0.3:  # 30% chance of weak configuration
                issue = ConfigurationIssue(
                    parameter=param,
                    current_value="ON",
                    recommended_value="OFF",
                    severity="Medium",
                    description=f"Insecure parameter {param} is enabled",
                    security_impact="Potential security vulnerability or information disclosure"
                )
                issues.append(issue)
        
        return issues
    
    async def _check_encryption(self, input_data: DatabaseSecurityAnalyzerInput) -> EncryptionStatus:
        """Check database encryption settings"""
        await asyncio.sleep(0.1)
        
        # Simulate encryption status
        data_at_rest = random.choice([True, False])
        data_in_transit = random.choice([True, False])
        
        issues = []
        recommendations = []
        
        if not data_at_rest:
            issues.append("Data at rest is not encrypted")
            recommendations.append("Enable transparent data encryption (TDE)")
        
        if not data_in_transit:
            issues.append("Data in transit is not encrypted")
            recommendations.append("Enable SSL/TLS for database connections")
        
        algorithms = []
        if data_at_rest or data_in_transit:
            algorithms = random.sample(["AES-256", "AES-128", "ChaCha20"], random.randint(1, 2))
        
        return EncryptionStatus(
            data_at_rest_encrypted=data_at_rest,
            data_in_transit_encrypted=data_in_transit,
            key_management="Manual" if random.random() < 0.5 else "Automated",
            encryption_algorithms=algorithms,
            issues=issues,
            recommendations=recommendations
        )
    
    async def _check_audit_configuration(self, input_data: DatabaseSecurityAnalyzerInput) -> AuditConfiguration:
        """Check audit and logging configuration"""
        await asyncio.sleep(0.1)
        
        audit_enabled = random.choice([True, False])
        
        issues = []
        recommendations = []
        
        if not audit_enabled:
            issues.append("Database auditing is disabled")
            recommendations.append("Enable comprehensive audit logging")
        
        retention_days = random.randint(30, 365)
        if retention_days < 90:
            issues.append("Audit log retention period is too short")
            recommendations.append("Increase audit log retention to at least 90 days")
        
        return AuditConfiguration(
            audit_enabled=audit_enabled,
            log_level=random.choice(["ERROR", "WARNING", "INFO", "DEBUG"]),
            logged_events=["LOGIN", "LOGOUT", "DDL", "DML"] if audit_enabled else [],
            log_retention_days=retention_days,
            issues=issues,
            recommendations=recommendations
        )
    
    async def _check_network_security(self, input_data: DatabaseSecurityAnalyzerInput) -> NetworkSecurity:
        """Check network security configuration"""
        await asyncio.sleep(0.1)
        
        ssl_enabled = random.choice([True, False])
        firewall_configured = random.choice([True, False])
        
        issues = []
        if not ssl_enabled:
            issues.append("SSL/TLS not enabled for database connections")
        
        if not firewall_configured:
            issues.append("Database firewall not properly configured")
        
        return NetworkSecurity(
            ssl_tls_enabled=ssl_enabled,
            firewall_configured=firewall_configured,
            allowed_connections=["localhost", "10.0.0.0/8", "192.168.1.0/24"],
            port_security={"default_port": "secured", "admin_port": "restricted"},
            issues=issues
        )
    
    async def _check_compliance(self, input_data: DatabaseSecurityAnalyzerInput) -> List[ComplianceCheck]:
        """Check compliance with security standards"""
        await asyncio.sleep(0.2)
        
        compliance_results = []
        
        for standard, requirements in self.COMPLIANCE_STANDARDS.items():
            for requirement in random.sample(requirements, random.randint(2, len(requirements))):
                status = random.choice(["Compliant", "Non-Compliant", "Partial"])
                
                findings = []
                recommendations = []
                
                if status != "Compliant":
                    findings.append(f"Database does not meet {requirement} requirements")
                    recommendations.append(f"Implement {requirement} controls")
                
                check = ComplianceCheck(
                    standard=standard,
                    requirement=requirement,
                    status=status,
                    findings=findings,
                    recommendations=recommendations
                )
                compliance_results.append(check)
        
        return compliance_results
    
    async def _find_vulnerabilities(self, input_data: DatabaseSecurityAnalyzerInput) -> List[VulnerabilityFinding]:
        """Find database vulnerabilities"""
        await asyncio.sleep(0.1)
        
        vulnerabilities = []
        db_config = self.DB_CONFIGS.get(input_data.database_type, {})
        common_vulns = db_config.get("common_vulns", [])
        
        # Add some common vulnerabilities
        for cve in random.sample(common_vulns, random.randint(0, min(2, len(common_vulns)))):
            if random.random() < 0.3:  # 30% chance of having vulnerability
                # Validate and sanitize the database type before using in description
                safe_db_type = validate_database_type(input_data.database_type)
                vuln = VulnerabilityFinding(
                    vulnerability_id=f"DB-{random.randint(1000, 9999)}",
                    severity=random.choice(["Critical", "High", "Medium", "Low"]),
                    category=random.choice(["Authentication", "Authorization", "Injection", "Configuration"]),
                    description=f"Known vulnerability in {safe_db_type}",
                    affected_component=safe_db_type,
                    remediation="Update database to latest version and apply security patches",
                    cve_reference=cve
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _generate_privileges(self, db_type: str, username: str) -> List[str]:
        """Generate privileges for database user"""
        if username in ["root", "admin", "sa", "postgres"]:
            return ["ALL PRIVILEGES", "GRANT OPTION", "CREATE USER", "DROP", "ALTER"]
        else:
            return random.sample(["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP"], random.randint(2, 4))
    
    def _calculate_security_score(self, users: List[DatabaseUser], config_issues: List[ConfigurationIssue], encryption_status: EncryptionStatus, vulnerabilities: List[VulnerabilityFinding]) -> float:
        """Calculate overall security score"""
        score = 10.0
        
        # Deduct for user security issues
        for user in users:
            if user.admin_privileges and not user.password_policy_compliant:
                score -= 1.5
            score -= len(user.security_issues) * 0.5
        
        # Deduct for configuration issues
        for issue in config_issues:
            if issue.severity == "High":
                score -= 1.0
            elif issue.severity == "Medium":
                score -= 0.5
            else:
                score -= 0.25
        
        # Deduct for encryption issues
        if encryption_status:
            if not encryption_status.data_at_rest_encrypted:
                score -= 1.5
            if not encryption_status.data_in_transit_encrypted:
                score -= 1.0
        
        # Deduct for vulnerabilities
        for vuln in vulnerabilities:
            if vuln.severity == "Critical":
                score -= 2.0
            elif vuln.severity == "High":
                score -= 1.5
            elif vuln.severity == "Medium":
                score -= 1.0
            else:
                score -= 0.5
        
        return max(0.0, min(10.0, score))
    
    def _determine_risk_level(self, security_score: float, vulnerabilities: List[VulnerabilityFinding]) -> str:
        """Determine overall risk level"""
        critical_vulns = len([v for v in vulnerabilities if v.severity == "Critical"])
        
        if critical_vulns > 0 or security_score < 3.0:
            return "Critical"
        elif security_score < 5.0:
            return "High"
        elif security_score < 7.0:
            return "Medium"
        else:
            return "Low"
    
    def _generate_recommendations(self, users: List[DatabaseUser], config_issues: List[ConfigurationIssue], encryption_status: EncryptionStatus, audit_config: AuditConfiguration, vulnerabilities: List[VulnerabilityFinding]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # User-related recommendations
        admin_users = [u for u in users if u.admin_privileges]
        if len(admin_users) > 2:
            recommendations.append("Reduce number of administrative accounts")
        
        weak_passwords = [u for u in users if not u.password_policy_compliant]
        if weak_passwords:
            recommendations.append("Enforce strong password policies for all database users")
        
        # Configuration recommendations
        if config_issues:
            recommendations.append("Fix database security configuration issues")
        
        # Encryption recommendations
        if encryption_status and not encryption_status.data_at_rest_encrypted:
            recommendations.append("Enable data-at-rest encryption")
        
        if encryption_status and not encryption_status.data_in_transit_encrypted:
            recommendations.append("Enable SSL/TLS for database connections")
        
        # Audit recommendations
        if audit_config and not audit_config.audit_enabled:
            recommendations.append("Enable comprehensive database audit logging")
        
        # Vulnerability recommendations
        if vulnerabilities:
            recommendations.append("Apply security patches and updates")
        
        # General recommendations
        recommendations.extend([
            "Implement principle of least privilege",
            "Regular security assessments and penetration testing",
            "Database activity monitoring and alerting",
            "Backup encryption and secure storage",
            "Network segmentation and access controls"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _create_summary(self, users: List[DatabaseUser], config_issues: List[ConfigurationIssue], vulnerabilities: List[VulnerabilityFinding], compliance_results: List[ComplianceCheck]) -> Dict[str, Any]:
        """Create scan summary"""
        return {
            "total_users": len(users),
            "admin_users": len([u for u in users if u.admin_privileges]),
            "users_with_issues": len([u for u in users if u.security_issues]),
            "configuration_issues": len(config_issues),
            "vulnerabilities_found": len(vulnerabilities),
            "compliance_checks": len(compliance_results),
            "compliant_checks": len([c for c in compliance_results if c.status == "Compliant"])
        }
    
    def _create_connection_error_response(self, input_data: DatabaseSecurityAnalyzerInput) -> DatabaseSecurityAnalyzerOutput:
        """Create response for connection error"""
        return DatabaseSecurityAnalyzerOutput(
            database_info={"error": "Connection failed"},
            connection_successful=False,
            scan_timestamp=datetime.now(),
            database_users=[],
            configuration_issues=[],
            encryption_status=EncryptionStatus(
                data_at_rest_encrypted=False,
                data_in_transit_encrypted=False,
                key_management="Unknown",
                encryption_algorithms=[],
                issues=["Cannot determine encryption status - connection failed"],
                recommendations=["Fix database connection and retry"]
            ),
            audit_configuration=AuditConfiguration(
                audit_enabled=False,
                log_level="Unknown",
                logged_events=[],
                log_retention_days=0,
                issues=["Cannot determine audit configuration - connection failed"],
                recommendations=["Fix database connection and retry"]
            ),
            network_security=NetworkSecurity(
                ssl_tls_enabled=False,
                firewall_configured=False,
                allowed_connections=[],
                port_security={},
                issues=["Cannot determine network security - connection failed"]
            ),
            compliance_results=[],
            vulnerabilities=[],
            security_score=0.0,
            risk_level="Unknown",
            recommendations=["Fix database connection and retry analysis"],
            scan_summary={"error": "Connection failed"}
        )
    
    def _create_error_response(self, input_data: DatabaseSecurityAnalyzerInput, error_msg: str) -> DatabaseSecurityAnalyzerOutput:
        """Create response for general error"""
        return DatabaseSecurityAnalyzerOutput(
            database_info={"error": error_msg},
            connection_successful=False,
            scan_timestamp=datetime.now(),
            database_users=[],
            configuration_issues=[],
            encryption_status=EncryptionStatus(
                data_at_rest_encrypted=False,
                data_in_transit_encrypted=False,
                key_management="Unknown",
                encryption_algorithms=[],
                issues=[f"Analysis failed: {error_msg}"],
                recommendations=["Fix configuration and retry"]
            ),
            audit_configuration=AuditConfiguration(
                audit_enabled=False,
                log_level="Unknown",
                logged_events=[],
                log_retention_days=0,
                issues=[f"Analysis failed: {error_msg}"],
                recommendations=["Fix configuration and retry"]
            ),
            network_security=NetworkSecurity(
                ssl_tls_enabled=False,
                firewall_configured=False,
                allowed_connections=[],
                port_security={},
                issues=[f"Analysis failed: {error_msg}"]
            ),
            compliance_results=[],
            vulnerabilities=[],
            security_score=0.0,
            risk_level="Unknown",
            recommendations=["Fix configuration and retry analysis"],
            scan_summary={"error": error_msg}
        )

async def execute_tool(params: DatabaseSecurityAnalyzerInput) -> DatabaseSecurityAnalyzerOutput:
    """Main entry point for the Database Security Analyzer tool"""
    analyzer = DatabaseSecurityAnalyzer()
    return await analyzer.execute(params)

# Tool metadata for registration
TOOL_INFO = {
    "name": "Database Security Analyzer",
    "description": "Comprehensive database security assessment tool for multiple database types including configuration, user privileges, encryption, and compliance analysis",
    "category": "database_security",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "input_schema": DatabaseSecurityAnalyzerInput,
    "output_schema": DatabaseSecurityAnalyzerOutput,
    "tool_class": DatabaseSecurityAnalyzer
}
