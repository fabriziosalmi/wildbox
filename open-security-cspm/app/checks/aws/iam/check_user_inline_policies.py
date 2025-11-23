"""
AWS IAM Check: User Inline Policies
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


class CheckUserInlinePolicies(BaseCheck):
    """Check for IAM users with inline policies (should use managed policies instead)."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_IAM_006",
            title="IAM Users Should Not Have Inline Policies",
            description="IAM users should not have inline policies attached. Use managed policies "
                       "instead for better security, auditability, and maintainability.",
            provider=CloudProvider.AWS,
            service="IAM",
            category="Access Management",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 1.16",
                "AWS Security Best Practices",
                "SOC 2"
            ],
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"
            ],
            remediation="Remove inline policies from IAM users: "
                       "1. Review permissions in inline policies. "
                       "2. Create equivalent managed policies or groups. "
                       "3. Attach user to appropriate groups or managed policies. "
                       "4. Remove inline policies from users."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the user inline policies check.
        
        Args:
            session: AWS session/client
            region: AWS region (IAM is global)
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            iam_client = session.client('iam')
            
            # Get all IAM users
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    
                    try:
                        # Get inline policies for the user
                        inline_policies = iam_client.list_user_policies(UserName=username)
                        policy_names = inline_policies.get('PolicyNames', [])
                        
                        if policy_names:
                            results.append(CheckResult(
                                check_id=self.get_metadata().check_id,
                                resource_id=f"iam-user-{username}",
                                resource_type="AWS::IAM::User",
                                resource_name=username,
                                region="global",
                                status=CheckStatus.FAILED,
                                message=f"IAM user '{username}' has {len(policy_names)} inline policies attached",
                                details={
                                    'username': username,
                                    'inline_policy_count': len(policy_names),
                                    'inline_policy_names': policy_names
                                }
                            ))
                        else:
                            results.append(CheckResult(
                                check_id=self.get_metadata().check_id,
                                resource_id=f"iam-user-{username}",
                                resource_type="AWS::IAM::User",
                                resource_name=username,
                                region="global",
                                status=CheckStatus.PASSED,
                                message=f"IAM user '{username}' has no inline policies",
                                details={'username': username}
                            ))
                            
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') == 'NoSuchEntity':
                            continue
                        else:
                            results.append(CheckResult(
                                check_id=self.get_metadata().check_id,
                                resource_id=f"iam-user-{username}",
                                resource_type="AWS::IAM::User",
                                resource_name=username,
                                region="global",
                                status=CheckStatus.ERROR,
                                message=f"Failed to check inline policies for user '{username}': {e}",
                                details={'error': str(e)}
                            ))
                            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="iam-service",
                resource_type="AWS::IAM::Service",
                region="global",
                status=CheckStatus.ERROR,
                message=f"Failed to check user inline policies: {error_code}",
                details={'error': str(e)}
            ))
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Unexpected error in user inline policies check: {str(e)}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region="global",
                status=CheckStatus.ERROR,
                message=f"Unexpected error during check execution: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
