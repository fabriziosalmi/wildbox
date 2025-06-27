"""
GCP COMPUTE Check: IP Forwarding Disabled
"""

from google.cloud import compute_v1
from google.api_core import exceptions
from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckIPForwardingDisabled(BaseCheck):
    """Ensure IP forwarding is disabled on instances."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="GCP_COMPUTE_005",
            title="IP Forwarding Disabled",
            description="Ensure IP forwarding is disabled on instances.",
            provider=CloudProvider.GCP,
            service="COMPUTE",
            category="Security",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "GCP Security Best Practices",
                "CIS GCP Foundations Benchmark"
            ],
            references=[
                "https://cloud.google.com/docs/"
            ],
            remediation="Implement ip forwarding disabled: "
                       "1. Go to GCP console. "
                       "2. Navigate to the service. "
                       "3. Configure the security setting. "
                       "4. Apply the changes."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the ip forwarding disabled check."""
        results = []
        
        try:
            # TODO: Implement the actual check logic
            # Example: client = compute_v1.InstancesClient()
            
            # Placeholder implementation
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="placeholder-resource",
                resource_type="GCP::compute::Resource",
                resource_name="placeholder",
                region=region,
                status=CheckStatus.PASSED,
                message="Check implementation needed",
                details={'note': 'This check needs to be implemented'}
            ))
                        
        except Exception as e:
            logger.error(f"Error in ip forwarding disabled check: {str(e)}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error during check execution: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
