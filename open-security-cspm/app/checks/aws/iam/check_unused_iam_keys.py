"""
AWS IAM Check: Unused Access Keys
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Any, Optional
from datetime import datetime, timezone, timedelta
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckUnusedIAMKeys(BaseCheck):
    """Check for IAM access keys that haven't been used recently."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_IAM_002",
            title="Unused IAM Access Keys",
            description="Identify IAM access keys that have not been used for more than 90 days. "
                       "Unused access keys represent unnecessary attack surface and should be removed.",
            provider=CloudProvider.AWS,
            service="IAM",
            category="Identity and Access Management",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 1.3",
                "AWS Security Best Practices",
                "SOC 2"
            ],
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
            ],
            remediation="Remove unused access keys: "
                       "1. Go to IAM console. "
                       "2. Select the user with unused keys. "
                       "3. Go to 'Security credentials' tab. "
                       "4. Delete the unused access key. "
                       "Alternatively, rotate keys if still needed but ensure old keys are removed."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the unused IAM keys check.
        
        Args:
            session: boto3 session
            region: AWS region (not used for this global check)
            
        Returns:
            List of check results
        """
        results = []
        unused_threshold_days = 90
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=unused_threshold_days)
        
        try:
            # Create IAM client (IAM is global)
            iam_client = session.client('iam', region_name='us-east-1')
            
            # Get all IAM users
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    
                    try:
                        # Get access keys for this user
                        keys_response = iam_client.list_access_keys(UserName=user_name)
                        
                        for key_metadata in keys_response['AccessKeyMetadata']:
                            access_key_id = key_metadata['AccessKeyId']
                            key_status = key_metadata['Status']
                            
                            # Skip inactive keys
                            if key_status != 'Active':
                                continue
                            
                            try:
                                # Get access key last used info
                                last_used_response = iam_client.get_access_key_last_used(
                                    AccessKeyId=access_key_id
                                )
                                
                                last_used_info = last_used_response.get('AccessKeyLastUsed', {})
                                last_used_date = last_used_info.get('LastUsedDate')
                                
                                # If never used, use creation date
                                if not last_used_date:
                                    last_used_date = key_metadata['CreateDate']
                                
                                # Check if key is unused
                                if last_used_date < cutoff_date:
                                    days_unused = (datetime.now(timezone.utc) - last_used_date).days
                                    
                                    results.append(
                                        self.create_result(
                                            resource_id=access_key_id,
                                            resource_type="IAMAccessKey",
                                            resource_name=f"{user_name}/{access_key_id}",
                                            status=CheckStatus.FAILED,
                                            message=f"Access key has not been used for {days_unused} days",
                                            details={
                                                "user_name": user_name,
                                                "access_key_id": access_key_id,
                                                "last_used_date": last_used_date.isoformat(),
                                                "days_unused": days_unused,
                                                "threshold_days": unused_threshold_days,
                                                "last_used_service": last_used_info.get('ServiceName'),
                                                "last_used_region": last_used_info.get('Region')
                                            }
                                        )
                                    )
                                else:
                                    results.append(
                                        self.create_result(
                                            resource_id=access_key_id,
                                            resource_type="IAMAccessKey",
                                            resource_name=f"{user_name}/{access_key_id}",
                                            status=CheckStatus.PASSED,
                                            message="Access key is actively used",
                                            details={
                                                "user_name": user_name,
                                                "access_key_id": access_key_id,
                                                "last_used_date": last_used_date.isoformat(),
                                                "last_used_service": last_used_info.get('ServiceName'),
                                                "last_used_region": last_used_info.get('Region')
                                            }
                                        )
                                    )
                                    
                            except ClientError as e:
                                if e.response.get('Error', {}).get('Code') == 'AccessDenied':
                                    # Can't check last used - create a warning
                                    results.append(
                                        self.create_result(
                                            resource_id=access_key_id,
                                            resource_type="IAMAccessKey",
                                            resource_name=f"{user_name}/{access_key_id}",
                                            status=CheckStatus.ERROR,
                                            message="Cannot determine access key usage due to insufficient permissions",
                                            details={
                                                "user_name": user_name,
                                                "access_key_id": access_key_id,
                                                "error": "AccessDenied"
                                            }
                                        )
                                    )
                                else:
                                    raise
                                    
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                        results.append(
                            self.create_result(
                                resource_id=user_name,
                                resource_type="IAMUser",
                                resource_name=user_name,
                                status=CheckStatus.ERROR,
                                message=f"Failed to check access keys for user: {error_code}",
                                details={
                                    "user_name": user_name,
                                    "error": str(e),
                                    "error_code": error_code
                                }
                            )
                        )
                        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(
                self.create_result(
                    resource_id="unknown",
                    resource_type="IAMUser",
                    status=CheckStatus.ERROR,
                    message=f"Failed to list IAM users: {error_code}",
                    details={
                        "error": str(e),
                        "error_code": error_code
                    }
                )
            )
        except Exception as e:
            results.append(
                self.create_result(
                    resource_id="unknown",
                    resource_type="IAMUser",
                    status=CheckStatus.ERROR,
                    message=f"Unexpected error checking unused access keys: {str(e)}",
                    details={"error": str(e)}
                )
            )
        
        return results
