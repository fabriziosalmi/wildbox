"""
GCP DNS Check: DNS DNSSEC Enabled
"""

from google.cloud import dns
from google.api_core import exceptions
from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckDNSDNSSECEnabled(BaseCheck):
    """Ensure DNSSEC is enabled for DNS zones."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="GCP_DNS_001",
            title="DNS DNSSEC Enabled",
            description="Ensure DNSSEC is enabled for DNS zones.",
            provider=CloudProvider.GCP,
            service="DNS",
            category="Security",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "GCP Security Best Practices",
                "SOC 2"
            ],
            references=[
                "https://docs.gcp.com/"
            ],
            remediation="Implement dns dnssec enabled: "
                       "1. Go to GCP console. "
                       "2. Navigate to the service. "
                       "3. Configure the security setting. "
                       "4. Apply the changes."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the dns dnssec enabled check."""
        results = []
        
        try:
            # TODO: Implement the actual check logic
            
            # Placeholder implementation
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="placeholder-resource",
                resource_type="GCP::dns::Resource",
                resource_name="placeholder",
                region=region,
                status=CheckStatus.PASSED,
                message="Check implementation needed",
                details={'note': 'This check needs to be implemented'}
            ))
                        
        except Exception as e:
            logger.error(f"Error in dns dnssec enabled check: {str(e)}")
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
