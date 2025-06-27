"""
AWS S3 Check: Bucket Versioning
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


class CheckBucketVersioning(BaseCheck):
    """Check if S3 buckets have versioning enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_S3_003",
            title="S3 Bucket Versioning Enabled",
            description="Ensure S3 buckets have versioning enabled to protect against "
                       "accidental deletion or modification of objects.",
            provider=CloudProvider.AWS,
            service="S3",
            category="Data Protection",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 2.1.3",
                "AWS Security Best Practices",
                "SOC 2",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/versioning-workflows.html"
            ],
            remediation="Enable S3 bucket versioning: "
                       "1. Go to S3 console. "
                       "2. Select the bucket. "
                       "3. Go to Properties tab. "
                       "4. Click on 'Bucket Versioning'. "
                       "5. Enable versioning. "
                       "6. Consider enabling MFA delete for additional protection."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the S3 bucket versioning check.
        
        Args:
            session: AWS session/client
            region: AWS region
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            s3_client = session.client('s3', region_name=region)
            
            # List all buckets
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket versioning status
                    versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    versioning_status = versioning_response.get('Status', 'Disabled')
                    mfa_delete = versioning_response.get('MFADelete', 'Disabled')
                    
                    if versioning_status == 'Enabled':
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"s3-bucket-{bucket_name}",
                            resource_type="AWS::S3::Bucket",
                            resource_name=bucket_name,
                            region=region,
                            status=CheckStatus.PASSED,
                            message=f"S3 bucket '{bucket_name}' has versioning enabled",
                            details={
                                'bucket_name': bucket_name,
                                'versioning_status': versioning_status,
                                'mfa_delete': mfa_delete
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
                            message=f"S3 bucket '{bucket_name}' does not have versioning enabled",
                            details={
                                'bucket_name': bucket_name,
                                'versioning_status': versioning_status,
                                'mfa_delete': mfa_delete
                            }
                        ))
                        
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    if error_code == 'NoSuchBucket':
                        continue
                    else:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"s3-bucket-{bucket_name}",
                            resource_type="AWS::S3::Bucket",
                            resource_name=bucket_name,
                            region=region,
                            status=CheckStatus.ERROR,
                            message=f"Failed to check versioning for bucket '{bucket_name}': {error_code}",
                            details={'error': str(e)}
                        ))
                        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="s3-service",
                resource_type="AWS::S3::Service",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Failed to check S3 bucket versioning: {error_code}",
                details={'error': str(e)}
            ))
        except Exception as e:
            logger.error(f"Unexpected error in S3 bucket versioning check: {str(e)}")
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
