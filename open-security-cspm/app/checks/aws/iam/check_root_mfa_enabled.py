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
    """Check if MFA is enabled for the AWS root account."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_IAM_001",
            title="Root Account MFA Enabled",
            description="Verify that Multi-Factor Authentication (MFA) is enabled for the AWS root account. "
                       "The root account has unrestricted access to all resources in the AWS account.",
            provider=CloudProvider.AWS,
            service="IAM",
            category="Identity and Access Management",
            severity=CheckSeverity.CRITICAL,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 1.5",
                "AWS Security Best Practices",
                "SOC 2",
                "PCI DSS"
            ],
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
                "https://aws.amazon.com/blogs/security/getting-started-follow-security-best-practices-as-you-configure-your-aws-resources/"
            ],
            remediation="Enable MFA for the root account: "
                       "1. Sign in to AWS Management Console as root user. "
                       "2. Go to IAM console. "
                       "3. Click on 'My Security Credentials'. "
                       "4. Under 'Multi-factor authentication (MFA)', click 'Assign MFA device'. "
                       "5. Follow the setup wizard to configure MFA."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the root MFA check.
        
        Args:
            session: boto3 session
            region: AWS region (not used for this global check)
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create IAM client (IAM is global)
            iam_client = session.client('iam', region_name='us-east-1')
            
            # Get account summary
            response = iam_client.get_account_summary()
            account_summary = response.get('SummaryMap', {})
            
            # Check if root account has MFA enabled
            root_mfa_enabled = account_summary.get('AccountMFAEnabled', 0)
            
            # Get account ID for resource identification
            sts_client = session.client('sts', region_name='us-east-1')
            account_id = sts_client.get_caller_identity()['Account']
            
            if root_mfa_enabled == 1:
                results.append(
                    self.create_result(
                        resource_id=f"arn:aws:iam::{account_id}:root",
                        resource_type="IAMRootAccount",
                        resource_name="root",
                        status=CheckStatus.PASSED,
                        message="Root account has MFA enabled",
                        details={
                            "account_id": account_id,
                            "mfa_enabled": True
                        }
                    )
                )
            else:
                results.append(
                    self.create_result(
                        resource_id=f"arn:aws:iam::{account_id}:root",
                        resource_type="IAMRootAccount",
                        resource_name="root",
                        status=CheckStatus.FAILED,
                        message="Root account does not have MFA enabled",
                        details={
                            "account_id": account_id,
                            "mfa_enabled": False
                        },
                        remediation="Enable MFA for the root account immediately. "
                                   "Root account access without MFA poses a critical security risk."
                    )
                )
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(
                self.create_result(
                    resource_id="unknown",
                    resource_type="IAMRootAccount",
                    status=CheckStatus.ERROR,
                    message=f"Failed to check root MFA status: {error_code}",
                    details={
                        "error": str(e),
                        "error_code": error_code
                    }
                )
            )
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            results.append(
                self.create_result(
                    resource_id="unknown",
                    resource_type="IAMRootAccount",
                    status=CheckStatus.ERROR,
                    message=f"Unexpected error checking root MFA: {str(e)}",
                    details={"error": str(e)}
                )
            )
        
        return results
