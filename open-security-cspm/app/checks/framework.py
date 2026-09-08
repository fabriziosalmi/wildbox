"""
Base framework for security checks
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Union
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class CheckSeverity(str, Enum):
    """Severity levels for security checks."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckStatus(str, Enum):
    """Status of a security check execution."""
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    # A check that has no real implementation yet. Never report these as PASSED:
    # an unimplemented check that "passes" is a false compliance signal.
    NOT_IMPLEMENTED = "not_implemented"


class CloudProvider(str, Enum):
    """Supported cloud providers."""
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class CheckResult(BaseModel):
    """Result of a single security check."""
    
    check_id: str
    resource_id: str
    resource_type: str
    resource_name: Optional[str] = None
    region: Optional[str] = None
    status: CheckStatus
    message: str
    details: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    compliance_frameworks: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @staticmethod
    def get_current_timestamp() -> str:
        """ISO-8601 timestamp string for embedding in check evidence/details."""
        return datetime.utcnow().isoformat()


class CheckMetadata(BaseModel):
    """Metadata for a security check."""
    
    check_id: str
    title: str
    description: str
    provider: CloudProvider
    service: str
    category: str
    severity: CheckSeverity
    compliance_frameworks: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    remediation: str
    enabled: bool = True
    # False for scaffolding whose execute() inspects nothing.
    #
    # 166 of the 204 check files used to be generated placeholders that still
    # declared full metadata -- check_id, severity, compliance frameworks, a
    # four-step remediation -- so the registry, the catalogue and any compliance
    # score saw 204 checks where only 31 inspected anything (WILDBO-QUAL-01).
    # Those files have been deleted: every check in the tree now calls a cloud
    # API. This flag stays as the guard that keeps it that way -- scaffolding
    # merged with implemented=False is excluded from discovery and from any
    # compliance score, so it can never inflate the advertised capability again.
    implemented: bool = True


class BaseCheck(ABC):
    """
    Base class for all security checks.
    
    Each check must inherit from this class and implement the execute method.
    """
    
    def __init__(self):
        self.metadata = self.get_metadata()
        self.results: List[CheckResult] = []
    
    @abstractmethod
    def get_metadata(self) -> CheckMetadata:
        """Return metadata for this check."""
        pass
    
    @abstractmethod
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the security check.
        
        Args:
            session: Cloud provider session/client
            region: Optional region to check (provider-specific)
            
        Returns:
            List of check results
        """
        pass
    
    def create_result(
        self,
        resource_id: str,
        resource_type: str,
        status: CheckStatus,
        message: str,
        resource_name: Optional[str] = None,
        region: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None
    ) -> CheckResult:
        """
        Create a standardized check result.
        
        Args:
            resource_id: Unique identifier for the resource
            resource_type: Type of cloud resource (e.g., 'S3Bucket', 'IAMUser')
            status: Check status
            message: Human-readable message
            resource_name: Optional friendly name for the resource
            region: Cloud region
            details: Additional context data
            remediation: Specific remediation steps
            
        Returns:
            CheckResult instance
        """
        return CheckResult(
            check_id=self.metadata.check_id,
            resource_id=resource_id,
            resource_type=resource_type,
            resource_name=resource_name,
            region=region,
            status=status,
            message=message,
            details=details or {},
            remediation=remediation or self.metadata.remediation,
            compliance_frameworks=self.metadata.compliance_frameworks
        )


class ScanReport(BaseModel):
    """Complete scan report for a cloud account."""
    
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    provider: CloudProvider
    account_id: str
    account_name: Optional[str] = None
    regions: List[str]
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    error_checks: int = 0
    skipped_checks: int = 0
    not_implemented_checks: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    compliance_score: Optional[float] = None
    results: List[CheckResult] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    
    def add_result(self, result: CheckResult):
        """Add a check result and update statistics."""
        self.results.append(result)
        self.total_checks += 1
        
        # Update status counters
        if result.status == CheckStatus.PASSED:
            self.passed_checks += 1
        elif result.status == CheckStatus.FAILED:
            self.failed_checks += 1
            
            # Update severity counters for failed checks
            severity = self._get_check_severity(result.check_id)
            if severity == CheckSeverity.CRITICAL:
                self.critical_findings += 1
            elif severity == CheckSeverity.HIGH:
                self.high_findings += 1
            elif severity == CheckSeverity.MEDIUM:
                self.medium_findings += 1
            elif severity == CheckSeverity.LOW:
                self.low_findings += 1
            elif severity == CheckSeverity.INFO:
                self.info_findings += 1
                
        elif result.status == CheckStatus.ERROR:
            self.error_checks += 1
        elif result.status == CheckStatus.SKIPPED:
            self.skipped_checks += 1
        elif result.status == CheckStatus.NOT_IMPLEMENTED:
            self.not_implemented_checks += 1
    
    def _get_check_severity(self, check_id: str) -> CheckSeverity:
        """Get severity for a check ID. This would be enhanced with check registry."""
        # This is a placeholder - in a real implementation, we'd look up the check metadata
        return CheckSeverity.MEDIUM
    
    def finalize(self):
        """Finalize the report and calculate final metrics."""
        self.completed_at = datetime.utcnow()
        self.status = "completed"
        
        # Calculate compliance score over checks that actually produced a verdict.
        # Not-implemented / skipped / errored checks are excluded from the
        # denominator so they neither inflate nor deflate the score — only real
        # pass/fail results count.
        evaluated_checks = self.passed_checks + self.failed_checks
        if evaluated_checks > 0:
            self.compliance_score = (self.passed_checks / evaluated_checks) * 100
        else:
            self.compliance_score = 0.0
        
        # Generate summary
        self.summary = {
            "duration_seconds": (self.completed_at - self.started_at).total_seconds(),
            "checks_by_status": {
                "passed": self.passed_checks,
                "failed": self.failed_checks,
                "error": self.error_checks,
                "skipped": self.skipped_checks,
                "not_implemented": self.not_implemented_checks,
            },
            "findings_by_severity": {
                "critical": self.critical_findings,
                "high": self.high_findings,
                "medium": self.medium_findings,
                "low": self.low_findings,
                "info": self.info_findings
            },
            "compliance_frameworks": self._get_compliance_summary(),
            "recommendations": self._get_top_recommendations()
        }
    
    def _get_compliance_summary(self) -> Dict[str, Any]:
        """Generate compliance framework summary."""
        frameworks = {}
        for result in self.results:
            for framework in result.compliance_frameworks:
                if framework not in frameworks:
                    frameworks[framework] = {"total": 0, "passed": 0, "failed": 0}
                
                frameworks[framework]["total"] += 1
                if result.status == CheckStatus.PASSED:
                    frameworks[framework]["passed"] += 1
                elif result.status == CheckStatus.FAILED:
                    frameworks[framework]["failed"] += 1
        
        # Calculate compliance percentage for each framework
        for framework in frameworks:
            total = frameworks[framework]["total"]
            passed = frameworks[framework]["passed"]
            frameworks[framework]["compliance_percentage"] = (passed / total * 100) if total > 0 else 0
        
        return frameworks
    
    def _get_top_recommendations(self) -> List[str]:
        """Get top remediation recommendations."""
        # Count failed checks by remediation advice
        remediations = {}
        for result in self.results:
            if result.status == CheckStatus.FAILED and result.remediation:
                remediations[result.remediation] = remediations.get(result.remediation, 0) + 1
        
        # Return top 5 most common remediations
        return sorted(remediations.keys(), key=lambda x: remediations[x], reverse=True)[:5]


class CheckRegistry:
    """Registry for managing available security checks."""
    
    def __init__(self):
        self._checks: Dict[str, BaseCheck] = {}
        self._checks_by_provider: Dict[CloudProvider, List[BaseCheck]] = {
            CloudProvider.AWS: [],
            CloudProvider.GCP: [],
            CloudProvider.AZURE: []
        }
        # Registered but not runnable: anything declaring implemented=False.
        # Empty today (the 166 generated placeholders were deleted), and kept so
        # that future scaffolding cannot be counted as capability
        # (WILDBO-QUAL-01).
        self._unimplemented: Dict[str, BaseCheck] = {}
    
    def register(self, check: BaseCheck):
        """
        Register a security check.

        Unimplemented scaffolding is recorded separately: it stays visible to
        anyone who asks for the full catalogue, but it is not returned as a
        runnable check and does not contribute to a compliance score
        (WILDBO-QUAL-01).
        """
        if not getattr(check.metadata, "implemented", True):
            self._unimplemented[check.metadata.check_id] = check
            return
        self._checks[check.metadata.check_id] = check
        self._checks_by_provider[check.metadata.provider].append(check)
    
    def get_check(self, check_id: str) -> Optional[BaseCheck]:
        """Get a specific check by ID."""
        return self._checks.get(check_id)
    
    def get_checks_by_provider(self, provider: CloudProvider) -> List[BaseCheck]:
        """Get all checks for a specific provider."""
        return self._checks_by_provider.get(provider, [])
    
    def get_all_checks(self) -> List[BaseCheck]:
        """Get all registered checks."""
        return list(self._checks.values())
    
    def get_metadata(self) -> List[CheckMetadata]:
        """Get metadata for all runnable checks."""
        return [check.metadata for check in self._checks.values()]

    def get_unimplemented(self) -> List[CheckMetadata]:
        """Metadata for checks that exist as scaffolding only."""
        return [check.metadata for check in self._unimplemented.values()]

    def coverage(self) -> Dict[str, int]:
        """
        How much of the advertised catalogue actually inspects anything.

        Exposed so the catalogue endpoint can report a true number instead of
        counting scaffolding as capability (WILDBO-QUAL-01).
        """
        return {
            "implemented": len(self._checks),
            "unimplemented": len(self._unimplemented),
            "total": len(self._checks) + len(self._unimplemented),
        }


# Global check registry
check_registry = CheckRegistry()
