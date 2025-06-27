"""
AWS S3 Check: Bucket MFA Delete
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


class CheckBucketMFADelete(BaseCheck):
    """Check if S3 buckets have MFA Delete enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_S3_004",
            title="S3 Bucket MFA Delete Enabled",
            description="Ensure S3 buckets have MFA Delete enabled to provide additional "
                       "protection against accidental or malicious deletion of versioned objects.",
            provider=CloudProvider.AWS,
            service="S3",
            category="Access Control",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 2.1.2",
                "AWS Security Best Practices",
                "SOC 2"
            ],
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html"
            ],
            remediation="Enable MFA Delete for S3 buckets: "
                       "1. Ensure versioning is enabled first. "
                       "2. Use AWS CLI with root credentials to enable MFA Delete. "
                       "3. aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'SERIAL TOKEN'"
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the S3 bucket MFA Delete check."""
        results = []
        
        try:
            s3_client = session.client('s3', region_name=region)
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    mfa_delete = versioning_response.get('MFADelete', 'Disabled')
                    versioning_status = versioning_response.get('Status', 'Disabled')
                    
                    if versioning_status == 'Enabled' and mfa_delete == 'Enabled':
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"s3-bucket-{bucket_name}",
                            resource_type="AWS::S3::Bucket",
                            resource_name=bucket_name,
                            region=region,
                            status=CheckStatus.PASSED,
                            message=f"S3 bucket '{bucket_name}' has MFA Delete enabled",
                            details={
                                'bucket_name': bucket_name,
                                'mfa_delete': mfa_delete,
                                'versioning_status': versioning_status
                            }
                        ))
                    else:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"s3-bucket-{bucket_name}",
                            resource_type="AWS::S3::Bucket",
                            resource_name=bucket_name,
                            region=region,
                            status=CheckStatus.FAILED,
                            message=f"S3 bucket '{bucket_name}' does not have MFA Delete enabled",
                            details={
                                'bucket_name': bucket_name,
                                'mfa_delete': mfa_delete,
                                'versioning_status': versioning_status,
                                'note': 'MFA Delete requires versioning to be enabled'
                            }
                        ))
                        
                except ClientError as e:
                    if e.response.get('Error', {}).get('Code') == 'NoSuchBucket':
                        continue
                    else:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"s3-bucket-{bucket_name}",
                            resource_type="AWS::S3::Bucket",
                            resource_name=bucket_name,
                            region=region,
                            status=CheckStatus.ERROR,
                            message=f"Failed to check MFA Delete for bucket '{bucket_name}'",
                            details={'error': str(e)}
                        ))
                        
        except Exception as e:
            logger.error(f"Unexpected error in S3 bucket MFA Delete check: {str(e)}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Unexpected error during check execution: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
