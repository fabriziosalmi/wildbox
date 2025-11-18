"""
Pydantic schemas for CSPM API
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator

from .checks.framework import CloudProvider, CheckSeverity, CheckStatus


class ScanProvider(str, Enum):
    """Supported cloud providers for scanning."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class AWSCredentials(BaseModel):
    """AWS credentials configuration."""
    auth_method: str = Field(default="access_key", description="Authentication method")
    access_key_id: str = Field(..., description="AWS Access Key ID")
    secret_access_key: str = Field(..., description="AWS Secret Access Key")
    region: Optional[str] = Field(default="us-east-1", description="Default AWS region")
    role_arn: Optional[str] = Field(None, description="IAM role ARN for assume role auth")
    external_id: Optional[str] = Field(None, description="External ID for assume role")
    
    @validator('auth_method')
    def validate_auth_method(cls, v):
        allowed_methods = ['access_key', 'assume_role']
        if v not in allowed_methods:
            raise ValueError(f'auth_method must be one of {allowed_methods}')
        return v


class GCPCredentials(BaseModel):
    """GCP credentials configuration."""
    auth_method: str = Field(default="service_account", description="Authentication method")
    project_id: str = Field(..., description="GCP Project ID")
    service_account_key: Optional[Dict[str, Any]] = Field(None, description="Service account key JSON")
    service_account_file: Optional[str] = Field(None, description="Path to service account key file")


class AzureCredentials(BaseModel):
    """Azure credentials configuration."""
    auth_method: str = Field(default="client_secret", description="Authentication method")
    tenant_id: str = Field(..., description="Azure Tenant ID")
    client_id: str = Field(..., description="Azure Client ID")
    client_secret: Optional[str] = Field(None, description="Azure Client Secret")
    subscription_id: str = Field(..., description="Azure Subscription ID")


class ScanRequest(BaseModel):
    """Request to start a CSPM scan."""
    
    provider: ScanProvider = Field(..., description="Cloud provider to scan")
    credentials: Union[AWSCredentials, GCPCredentials, AzureCredentials] = Field(
        ..., description="Provider-specific credentials"
    )
    account_id: str = Field(..., description="Cloud account identifier")
    account_name: Optional[str] = Field(None, description="Friendly name for the account")
    regions: Optional[List[str]] = Field(None, description="Regions to scan (uses defaults if not specified)")
    check_ids: Optional[List[str]] = Field(None, description="Specific check IDs to run (runs all if not specified)")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    class Config:
        json_schema_extra = {
            "example": {
                "provider": "aws",
                "credentials": {
                    "auth_method": "access_key",
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "region": "us-east-1"
                },
                "account_id": "123456789012",
                "account_name": "Production Account",
                "regions": ["us-east-1", "us-west-2"],
                "metadata": {
                    "scan_reason": "monthly_compliance_check",
                    "requested_by": "security_team"
                }
            }
        }


class ScanResponse(BaseModel):
    """Response when starting a scan."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    status: str = Field(..., description="Initial scan status")
    provider: str = Field(..., description="Cloud provider being scanned")
    account_id: str = Field(..., description="Account being scanned")
    started_at: datetime = Field(..., description="Scan start timestamp")
    estimated_duration_minutes: Optional[int] = Field(None, description="Estimated scan duration")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "started",
                "provider": "aws",
                "account_id": "123456789012",
                "started_at": "2024-01-15T10:30:00Z",
                "estimated_duration_minutes": 15
            }
        }


class ScanMetadata(BaseModel):
    """Metadata stored in Redis for a scan."""
    scan_id: str
    provider: str
    account_id: str
    account_name: Optional[str] = None
    status: str
    started_at: datetime
    requested_by: str
    team_id: str
    completed_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    
    @validator('started_at', 'completed_at', 'cancelled_at', pre=True)
    def parse_datetime_from_isoformat(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v)
        return v


class ScanStatusResponse(BaseModel):
    """Response for scan status check."""
    
    scan_id: str = Field(..., description="Scan identifier")
    status: str = Field(..., description="Current scan status")
    provider: str = Field(..., description="Cloud provider")
    account_id: str = Field(..., description="Account ID")
    started_at: datetime = Field(..., description="Scan start time")
    completed_at: Optional[datetime] = Field(None, description="Scan completion time")
    progress: Optional[Dict[str, Any]] = Field(None, description="Scan progress information")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "running",
                "provider": "aws",
                "account_id": "123456789012",
                "started_at": "2024-01-15T10:30:00Z",
                "progress": {
                    "total_checks": 45,
                    "completed_checks": 23,
                    "current_region": "us-east-1"
                }
            }
        }


class CheckResultSchema(BaseModel):
    """Schema for individual check result."""
    
    check_id: str = Field(..., description="Check identifier")
    resource_id: str = Field(..., description="Resource identifier")
    resource_type: str = Field(..., description="Type of resource")
    resource_name: Optional[str] = Field(None, description="Resource friendly name")
    region: Optional[str] = Field(None, description="Resource region")
    status: CheckStatus = Field(..., description="Check result status")
    message: str = Field(..., description="Result message")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional details")
    remediation: Optional[str] = Field(None, description="Remediation guidance")
    compliance_frameworks: List[str] = Field(default_factory=list, description="Applicable compliance frameworks")
    timestamp: datetime = Field(..., description="Check execution timestamp")


class ScanReportSchema(BaseModel):
    """Schema for complete scan report."""
    
    scan_id: str = Field(..., description="Scan identifier")
    provider: CloudProvider = Field(..., description="Cloud provider")
    account_id: str = Field(..., description="Account identifier")
    account_name: Optional[str] = Field(None, description="Account friendly name")
    regions: List[str] = Field(..., description="Scanned regions")
    started_at: datetime = Field(..., description="Scan start time")
    completed_at: Optional[datetime] = Field(None, description="Scan completion time")
    status: str = Field(..., description="Scan status")
    
    # Statistics
    total_checks: int = Field(..., description="Total checks executed")
    passed_checks: int = Field(..., description="Number of passed checks")
    failed_checks: int = Field(..., description="Number of failed checks")
    error_checks: int = Field(..., description="Number of checks with errors")
    skipped_checks: int = Field(..., description="Number of skipped checks")
    
    # Findings by severity
    critical_findings: int = Field(..., description="Critical severity findings")
    high_findings: int = Field(..., description="High severity findings")
    medium_findings: int = Field(..., description="Medium severity findings")
    low_findings: int = Field(..., description="Low severity findings")
    info_findings: int = Field(..., description="Info severity findings")
    
    compliance_score: Optional[float] = Field(None, description="Overall compliance score (0-100)")
    results: List[CheckResultSchema] = Field(..., description="Individual check results")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary information")


class CheckMetadataSchema(BaseModel):
    """Schema for check metadata."""
    
    check_id: str = Field(..., description="Unique check identifier")
    title: str = Field(..., description="Check title")
    description: str = Field(..., description="Check description")
    provider: CloudProvider = Field(..., description="Cloud provider")
    service: str = Field(..., description="Cloud service")
    category: str = Field(..., description="Check category")
    severity: CheckSeverity = Field(..., description="Check severity")
    compliance_frameworks: List[str] = Field(default_factory=list, description="Applicable compliance frameworks")
    references: List[str] = Field(default_factory=list, description="Reference links")
    remediation: str = Field(..., description="Remediation guidance")
    enabled: bool = Field(True, description="Whether check is enabled")


class ChecksListResponse(BaseModel):
    """Response for listing available checks."""
    
    total_checks: int = Field(..., description="Total number of checks")
    checks: List[CheckMetadataSchema] = Field(..., description="List of available checks")
    providers: List[str] = Field(..., description="Available providers")
    categories: List[str] = Field(..., description="Available categories")
    
    class Config:
        json_schema_extra = {
            "example": {
                "total_checks": 45,
                "providers": ["aws", "gcp", "azure"],
                "categories": ["Identity and Access Management", "Storage", "Networking"]
            }
        }


class ComplianceFrameworkSummary(BaseModel):
    """Summary information for a compliance framework."""
    name: str = Field(..., description="Framework name")
    version: str = Field(..., description="Framework version")
    description: str = Field(..., description="Framework description")
    total_controls: int = Field(..., description="Total number of controls")
    passed_controls: int = Field(..., description="Number of passed controls")
    failed_controls: int = Field(..., description="Number of failed controls")
    compliance_percentage: float = Field(..., description="Compliance percentage")
    last_assessment: str = Field(..., description="Last assessment timestamp")


class ComplianceTrend(BaseModel):
    """Compliance trend information."""
    direction: str = Field(..., description="Trend direction: up, down, stable")
    percentage: float = Field(..., description="Percentage change")


class ComplianceSummaryResponse(BaseModel):
    """Aggregated compliance summary response."""
    total_resources: int = Field(..., description="Total number of resources evaluated")
    compliant_resources: int = Field(..., description="Number of compliant resources")
    non_compliant_resources: int = Field(..., description="Number of non-compliant resources")
    overall_score: float = Field(..., description="Overall compliance score")
    frameworks: List[ComplianceFrameworkSummary] = Field(..., description="Framework summaries")
    trend: ComplianceTrend = Field(..., description="Compliance trend")
    summary_period_days: int = Field(..., description="Summary period in days")
    provider_filter: Optional[str] = Field(None, description="Provider filter applied")
    last_updated: str = Field(..., description="Last update timestamp")


class ComplianceFinding(BaseModel):
    """Individual compliance finding."""
    finding_id: str = Field(..., description="Unique finding identifier")
    framework: str = Field(..., description="Compliance framework name")
    control_id: str = Field(..., description="Control identifier")
    control_title: str = Field(..., description="Control title")
    resource_id: str = Field(..., description="Resource identifier")
    resource_type: str = Field(..., description="Resource type")
    region: str = Field(..., description="Resource region")
    status: str = Field(..., description="Finding status: passed, failed, warning, not_applicable")
    severity: str = Field(..., description="Finding severity: critical, high, medium, low, info")
    description: str = Field(..., description="Finding description")
    remediation: str = Field(..., description="Remediation guidance")
    last_checked: str = Field(..., description="Last check timestamp")


class ComplianceFindingsResponse(BaseModel):
    """Compliance findings response with pagination."""
    findings: List[ComplianceFinding] = Field(..., description="List of compliance findings")
    total_count: int = Field(..., description="Total number of findings")
    limit: int = Field(..., description="Result limit")
    offset: int = Field(..., description="Result offset")
    has_more: bool = Field(..., description="Whether more results are available")


class ComplianceReportFrameworkSummary(BaseModel):
    """Framework summary for compliance report."""
    framework: str = Field(..., description="Framework name")
    total_checks: int = Field(..., description="Total number of checks")
    passed_checks: int = Field(..., description="Number of passed checks") 
    failed_checks: int = Field(..., description="Number of failed checks")
    compliance_percentage: float = Field(..., description="Compliance percentage")


class ComplianceReportResponse(BaseModel):
    """Compliance report response."""
    scan_id: str = Field(..., description="Scan identifier")
    account_id: str = Field(..., description="Account identifier")
    generated_at: str = Field(..., description="Report generation timestamp")
    frameworks: List[ComplianceReportFrameworkSummary] = Field(..., description="Framework summaries")
    overall_score: float = Field(..., description="Overall compliance score")
    recommendations: List[str] = Field(..., description="Recommendations")


class ErrorResponse(BaseModel):
    """Standard error response."""
    
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    
    class Config:
        json_schema_extra = {
            "example": {
                "error": "ValidationError",
                "message": "Invalid credentials provided",
                "details": {
                    "field": "credentials.access_key_id",
                    "reason": "required field missing"
                },
                "timestamp": "2024-01-15T10:30:00Z"
            }
        }


class HealthCheckResponse(BaseModel):
    """Health check response."""
    
    status: str = Field(..., description="Service health status")
    timestamp: datetime = Field(..., description="Health check timestamp")
    version: str = Field(..., description="Service version")
    uptime_seconds: Optional[float] = Field(None, description="Service uptime in seconds")
    checks: Dict[str, str] = Field(..., description="Individual component health")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-15T10:30:00Z",
                "version": "1.0.0",
                "uptime_seconds": 3600.5,
                "checks": {
                    "redis": "healthy",
                    "celery": "healthy",
                    "aws_connectivity": "healthy"
                }
            }
        }


# Enhanced response schemas for new endpoints

class TrendingMetricSchema(BaseModel):
    """Schema for trending security metrics."""
    date: str
    security_score: float
    critical_findings: int
    high_findings: int
    total_findings: int


class ExecutiveSummaryResponse(BaseModel):
    """Executive summary response with high-level metrics."""
    summary_period_days: int
    provider_filter: Optional[str]
    security_posture: Dict[str, Any]
    trending_metrics: List[TrendingMetricSchema]
    scan_coverage: Dict[str, Any]


class RemediationItemSchema(BaseModel):
    """Schema for a single remediation item."""
    remediation: str
    affected_resources: List[Dict[str, Any]]
    estimated_effort: str
    priority: str
    compliance_impact: List[str]
    priority_score: int
    order: int


class RemediationRoadmapResponse(BaseModel):
    """Remediation roadmap response with prioritized actions."""
    scan_id: str
    generated_at: datetime
    total_remediation_items: int
    roadmap: List[RemediationItemSchema]


class ResourceInventoryResponse(BaseModel):
    """Resource inventory response with detailed asset information."""
    scan_id: str
    filters: Dict[str, Optional[str]]
    summary: Dict[str, Any]
    resources: List[Dict[str, Any]]


class BatchScanJobSchema(BaseModel):
    """Schema for individual batch scan job."""
    scan_id: str
    provider: str
    account_id: str
    task_id: str
    status: str


class BatchScanResponse(BaseModel):
    """Batch scan response."""
    batch_id: str
    total_scans: int
    scans: List[BatchScanJobSchema]
    started_at: datetime


class BatchScanRequest(BaseModel):
    """Batch scan request with multiple scan configurations."""
    scans: List["ScanRequest"]
    parallel_execution_limit: Optional[int] = Field(default=3, description="Max parallel scans")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BatchScanStatusSchema(BaseModel):
    """Schema for individual scan status in batch."""
    scan_id: str
    status: str
    progress: int
    error: Optional[str] = None


class BatchStatusResponse(BaseModel):
    """Batch scan status response."""
    batch_id: str
    overall_status: str
    overall_progress: float
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int
    scan_statuses: List[BatchScanStatusSchema]
    started_at: datetime


class DashboardSummaryResponse(BaseModel):
    """Dashboard summary response."""
    total_scans: int = Field(..., description="Total number of scans")
    active_scans: int = Field(..., description="Number of active scans")
    failed_scans: int = Field(..., description="Number of failed scans")
    completed_scans: int = Field(..., description="Number of completed scans")
    total_findings: int = Field(..., description="Total security findings")
    critical_findings: int = Field(..., description="Critical severity findings")
    high_findings: int = Field(..., description="High severity findings")
    medium_findings: int = Field(..., description="Medium severity findings")
    low_findings: int = Field(..., description="Low severity findings")
    compliance_score: float = Field(..., description="Overall compliance score")
    last_scan_at: Optional[datetime] = Field(None, description="Last scan timestamp")
