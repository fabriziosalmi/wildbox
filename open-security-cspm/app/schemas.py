"""
Pydantic schemas for CSPM API
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator

from .checks.framework import CloudProvider, CheckSeverity, CheckStatus


class ScanProvider(str, Enum):
    """Providers a scan request can name.

    Naming one is not enough: the scan endpoints refuse, with a 400, every
    provider app.providers does not list as supported (#612).
    """
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class AWSCredentials(BaseModel):
    """AWS credentials configuration."""
    auth_method: str = Field(default="access_key", description="Authentication method")
    access_key_id: str = Field(..., description="AWS Access Key ID")
    secret_access_key: str = Field(..., description="AWS Secret Access Key", repr=False)
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
    service_account_key: Optional[Dict[str, Any]] = Field(None, description="Service account key JSON", repr=False)
    service_account_file: Optional[str] = Field(None, description="Path to service account key file")

    @validator('service_account_file')
    def validate_service_account_path(cls, v):
        if v is not None:
            import os
            normalized = os.path.normpath(v)
            if '..' in normalized.split(os.sep):
                raise ValueError('Path traversal not allowed in service_account_file')
        return v


class AzureCredentials(BaseModel):
    """Azure credentials configuration."""
    auth_method: str = Field(default="client_secret", description="Authentication method")
    tenant_id: str = Field(..., description="Azure Tenant ID")
    client_id: str = Field(..., description="Azure Client ID")
    client_secret: Optional[str] = Field(None, description="Azure Client Secret", repr=False)
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
    not_implemented_checks: int = Field(0, description="Number of checks not yet implemented (never counted as passed)")

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
                "total_checks": 22,
                "providers": ["aws"],
                "categories": ["Identity and Access Management", "Storage", "Networking"]
            }
        }


class ProviderSchema(BaseModel):
    """A provider cspm can scan."""

    provider: str = Field(..., description="Provider id, the value a scan request names")
    name: str = Field(..., description="Display name")
    checks: int = Field(..., description="Enabled checks a scan of this provider runs")


class ProvidersResponse(BaseModel):
    """The providers a scan can be submitted for (app.providers)."""

    providers: List[ProviderSchema] = Field(..., description="Supported providers")

    class Config:
        json_schema_extra = {
            "example": {"providers": [{"provider": "aws", "name": "Amazon Web Services", "checks": 22}]}
        }


class ComplianceFrameworkSummary(BaseModel):
    """Check verdicts for one compliance framework, from the team's scans."""
    name: str = Field(..., description="Framework name, as the checks tag it")
    total_checks: int = Field(..., description="Check results with a verdict (passed or failed)")
    passed_checks: int = Field(..., description="Check results that passed")
    failed_checks: int = Field(..., description="Check results that failed")
    compliance_percentage: float = Field(..., description="passed_checks / total_checks * 100")
    last_assessment: Optional[str] = Field(None, description="Completion time of the newest scan that contributed")


class ComplianceSummaryResponse(BaseModel):
    """Compliance aggregated over the newest completed scan of each account.

    Every figure comes from stored scan reports. With no completed scan in
    the period the counts are 0, ``frameworks`` is empty and
    ``overall_score`` and ``last_updated`` are null: nothing was assessed,
    which is not the same as 0% compliant.
    """
    total_resources: int = Field(..., description="Distinct resources with at least one verdict")
    compliant_resources: int = Field(..., description="Resources with no failed check")
    non_compliant_resources: int = Field(..., description="Resources with at least one failed check")
    overall_score: Optional[float] = Field(None, description="Passed share of all verdicts, or null when there are none")
    frameworks: List[ComplianceFrameworkSummary] = Field(..., description="Framework summaries")
    scans_considered: int = Field(..., description="Completed scan reports the figures come from")
    summary_period_days: int = Field(..., description="Summary period in days")
    provider_filter: Optional[str] = Field(None, description="Provider filter applied")
    last_updated: Optional[str] = Field(None, description="Completion time of the newest scan considered")


class ComplianceFinding(BaseModel):
    """One check verdict on one resource, from a completed scan."""
    finding_id: str = Field(..., description="<scan_id>:<index of the result in the report>")
    scan_id: str = Field(..., description="Scan the verdict comes from")
    check_id: str = Field(..., description="Check identifier")
    title: str = Field(..., description="Check title, or the check id when the check is unknown")
    frameworks: List[str] = Field(default_factory=list, description="Frameworks the check maps to")
    resource_id: str = Field(..., description="Resource identifier")
    resource_type: str = Field(..., description="Resource type")
    region: Optional[str] = Field(None, description="Resource region")
    status: str = Field(..., description="passed or failed")
    severity: Optional[str] = Field(None, description="Check severity, when the check is known")
    description: str = Field(..., description="Result message")
    remediation: Optional[str] = Field(None, description="Remediation guidance")
    last_checked: Optional[str] = Field(None, description="Check execution time")


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
    """The team's scan count and the figures of its newest completed scans.

    The findings, severity and score figures cover the newest completed scan
    of each account in the period, as GET /api/v1/compliance/summary does.
    With no completed scan they are 0 and ``compliance_score`` is null:
    nothing was assessed, which is not the same as 0% compliant.
    """
    total_scans: int = Field(..., description="Scans the team started that are still retained (30 days)")
    last_scan_at: Optional[datetime] = Field(None, description="Start time of the team's newest scan")
    summary_period_days: int = Field(..., description="Period the report figures cover, in days")
    accounts_assessed: int = Field(..., description="Accounts with a completed scan in the period")
    compliance_score: Optional[float] = Field(
        None, description="Passed share of all check verdicts, or null when there are none"
    )
    total_findings: int = Field(..., description="Failed checks")
    critical_findings: int = Field(..., description="Failed checks of critical severity")
    high_findings: int = Field(..., description="Failed checks of high severity")
    medium_findings: int = Field(..., description="Failed checks of medium severity")
    low_findings: int = Field(..., description="Failed checks of low severity")
    info_findings: int = Field(..., description="Failed checks of informational severity")
    unknown_severity_findings: int = Field(
        ..., description="Failed checks whose check is no longer in the catalog"
    )
