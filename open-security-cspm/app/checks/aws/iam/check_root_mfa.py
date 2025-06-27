"""
AWS IAM Check: Root Account MFA Enabled
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckRootMFAEnabled(BaseCheck):
    """Check if root account has MFA enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_IAM_002",
            title="Root Account MFA Enabled",
            description="Verify that the root account has Multi-Factor Authentication (MFA) enabled. "
                       "The root account has complete access to all AWS services and resources, "
                       "making MFA critical for security.",
            provider=CloudProvider.AWS,
            service="IAM",
            category="Identity & Access Management",
            severity=CheckSeverity.CRITICAL,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 1.4",
                "AWS Security Best Practices",
                "SOC 2",
                "PCI DSS",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html",
                "https://aws.amazon.com/blogs/security/getting-started-follow-security-best-practices-as-you-configure-your-aws-resources/"
            ],
            remediation="Enable MFA for root account: "
                       "1. Sign in to AWS console as root user. "
                       "2. Choose your account name -> Security credentials. "
                       "3. In MFA section, choose 'Activate MFA'. "
                       "4. Select virtual MFA device (recommended). "
                       "5. Follow the setup process with authenticator app. "
                       "6. Complete MFA setup and test authentication."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the root account MFA check.
        """
        results = []
        
        try:
            # Create IAM client
            iam_client = session.client('iam')
            
            # Get account summary
            response = iam_client.get_account_summary()
            summary_map = response.get('SummaryMap', {})
            
            # Check for MFA devices
            account_mfa_devices = summary_map.get('AccountMFAEnabled', 0)
            total_mfa_devices = summary_map.get('MFADevices', 0)
            
            details = {
                'account_mfa_devices': account_mfa_devices,
                'total_mfa_devices': total_mfa_devices,
                'check_timestamp': CheckResult.get_current_timestamp()
            }
            
            if account_mfa_devices > 0:
                results.append(self.create_result(
                    resource_id="root-account-mfa",
                    resource_type="Root Account MFA",
                    resource_name="Root Account MFA",
                    region="global",
                    status=CheckStatus.PASSED,
                    message="Account-level MFA is enabled",
                    details=details
                ))
            else:
                results.append(self.create_result(
                    resource_id="root-account-mfa",
                    resource_type="Root Account MFA",
                    resource_name="Root Account MFA",
                    region="global",
                    status=CheckStatus.FAILED,
                    message="No MFA devices found in account",
                    details=details,
                    remediation="Enable MFA for the root account"
                ))
            
        except Exception as e:
            logger.error(f"Error checking root account MFA: {e}")
            results.append(self.create_result(
                resource_id="root-account-mfa",
                resource_type="Root Account MFA",
                region="global",
                status=CheckStatus.ERROR,
                message=f"Error checking root account MFA: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
