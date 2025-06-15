from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class DatabaseSecurityAnalyzerInput(BaseModel):
    """Input schema for Database Security Analyzer tool"""
    database_type: str = Field(description="Database type (mysql, postgresql, mongodb, oracle, mssql)")
    host: str = Field(description="Database host address")
    port: int = Field(description="Database port number")
    database_name: Optional[str] = Field(None, description="Specific database name to analyze")
    username: Optional[str] = Field(None, description="Database username for connection")
    password: Optional[str] = Field(None, description="Database password (will be handled securely)")
    connection_string: Optional[str] = Field(None, description="Full connection string")
    check_configuration: bool = Field(default=True, description="Check database configuration security")
    check_users_privileges: bool = Field(default=True, description="Analyze user accounts and privileges")
    check_encryption: bool = Field(default=True, description="Check encryption settings")
    check_audit_logging: bool = Field(default=True, description="Check audit and logging configuration")
    check_network_security: bool = Field(default=True, description="Check network security settings")
    check_compliance: bool = Field(default=True, description="Check compliance with security standards")
    scan_depth: str = Field(default="standard", description="Scan depth (quick, standard, deep)")

class DatabaseUser(BaseModel):
    username: str
    privileges: List[str]
    host_access: List[str]
    password_policy_compliant: bool
    last_login: Optional[datetime] = None
    account_locked: bool
    admin_privileges: bool
    security_issues: List[str]

class ConfigurationIssue(BaseModel):
    parameter: str
    current_value: str
    recommended_value: str
    severity: str  # Critical, High, Medium, Low
    description: str
    security_impact: str

class EncryptionStatus(BaseModel):
    data_at_rest_encrypted: bool
    data_in_transit_encrypted: bool
    key_management: str
    encryption_algorithms: List[str]
    issues: List[str]
    recommendations: List[str]

class AuditConfiguration(BaseModel):
    audit_enabled: bool
    log_level: str
    logged_events: List[str]
    log_retention_days: int
    issues: List[str]
    recommendations: List[str]

class NetworkSecurity(BaseModel):
    ssl_tls_enabled: bool
    firewall_configured: bool
    allowed_connections: List[str]
    port_security: Dict[str, str]
    issues: List[str]

class ComplianceCheck(BaseModel):
    standard: str  # PCI-DSS, GDPR, HIPAA, SOX
    requirement: str
    status: str  # Compliant, Non-Compliant, Partial
    findings: List[str]
    recommendations: List[str]

class VulnerabilityFinding(BaseModel):
    vulnerability_id: str
    severity: str
    category: str
    description: str
    affected_component: str
    remediation: str
    cve_reference: Optional[str] = None

class DatabaseSecurityAnalyzerOutput(BaseModel):
    """Output schema for Database Security Analyzer tool"""
    database_info: Dict[str, str]
    connection_successful: bool
    scan_timestamp: datetime
    database_users: List[DatabaseUser]
    configuration_issues: List[ConfigurationIssue]
    encryption_status: EncryptionStatus
    audit_configuration: AuditConfiguration
    network_security: NetworkSecurity
    compliance_results: List[ComplianceCheck]
    vulnerabilities: List[VulnerabilityFinding]
    security_score: float
    risk_level: str
    recommendations: List[str]
    scan_summary: Dict[str, Any]

# Tool metadata

