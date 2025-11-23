"""
AWS S3 Check: Public Buckets
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Any, Optional
import json
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckPublicBuckets(BaseCheck):
    """Check for S3 buckets that are publicly accessible."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_S3_001",
            title="S3 Buckets Not Publicly Accessible",
            description="Verify that S3 buckets are not publicly accessible unless explicitly required. "
                       "Public S3 buckets can lead to data breaches and unauthorized access.",
            provider=CloudProvider.AWS,
            service="S3",
            category="Storage",
            severity=CheckSeverity.CRITICAL,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 2.1.5",
                "AWS Security Best Practices",
                "GDPR",
                "HIPAA",
                "SOC 2"
            ],
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "https://aws.amazon.com/s3/features/block-public-access/"
            ],
            remediation="Configure S3 bucket to block public access: "
                       "1. Go to S3 console. "
                       "2. Select the bucket. "
                       "3. Go to 'Permissions' tab. "
                       "4. Click 'Edit' under 'Block public access'. "
                       "5. Enable all four public access block settings. "
                       "6. Review and remove any public bucket policies or ACLs."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the public buckets check.
        
        Args:
            session: boto3 session
            region: AWS region (S3 bucket names are global but we check region-specific)
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create S3 client
            s3_client = session.client('s3', region_name=region or 'us-east-1')
            
            # List all buckets
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket region if we're filtering by region
                    if region:
                        try:
                            bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
                            bucket_region = bucket_location.get('LocationConstraint') or 'us-east-1'
                            
                            # Skip buckets not in the specified region
                            if bucket_region != region:
                                continue
                        except ClientError:
                            # Skip if we can't determine region
                            continue
                    
                    # Check public access block settings
                    public_access_block = self._get_public_access_block(s3_client, bucket_name)
                    
                    # Check bucket policy for public access
                    bucket_policy_public = self._check_bucket_policy_public(s3_client, bucket_name)
                    
                    # Check bucket ACL for public access
                    bucket_acl_public = self._check_bucket_acl_public(s3_client, bucket_name)
                    
                    # Determine if bucket is public
                    is_public = (
                        not public_access_block['all_blocked'] or
                        bucket_policy_public or
                        bucket_acl_public
                    )
                    
                    bucket_arn = f"arn:aws:s3:::{bucket_name}"
                    
                    if is_public:
                        public_reasons = []
                        if not public_access_block['all_blocked']:
                            public_reasons.append(f"Public access block not fully enabled: {public_access_block['details']}")
                        if bucket_policy_public:
                            public_reasons.append("Bucket policy allows public access")
                        if bucket_acl_public:
                            public_reasons.append("Bucket ACL allows public access")
                        
                        results.append(
                            self.create_result(
                                resource_id=bucket_arn,
                                resource_type="S3Bucket",
                                resource_name=bucket_name,
                                region=region,
                                status=CheckStatus.FAILED,
                                message=f"Bucket is publicly accessible: {'; '.join(public_reasons)}",
                                details={
                                    "bucket_name": bucket_name,
                                    "public_access_block": public_access_block,
                                    "bucket_policy_public": bucket_policy_public,
                                    "bucket_acl_public": bucket_acl_public,
                                    "public_reasons": public_reasons
                                }
                            )
                        )
                    else:
                        results.append(
                            self.create_result(
                                resource_id=bucket_arn,
                                resource_type="S3Bucket",
                                resource_name=bucket_name,
                                region=region,
                                status=CheckStatus.PASSED,
                                message="Bucket is not publicly accessible",
                                details={
                                    "bucket_name": bucket_name,
                                    "public_access_block": public_access_block,
                                    "bucket_policy_public": bucket_policy_public,
                                    "bucket_acl_public": bucket_acl_public
                                }
                            )
                        )
                        
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    
                    # Skip buckets we don't have permission to check
                    if error_code in ['AccessDenied', 'NoSuchBucket']:
                        results.append(
                            self.create_result(
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_type="S3Bucket",
                                resource_name=bucket_name,
                                region=region,
                                status=CheckStatus.ERROR,
                                message=f"Cannot check bucket public access: {error_code}",
                                details={
                                    "bucket_name": bucket_name,
                                    "error": str(e),
                                    "error_code": error_code
                                }
                            )
                        )
                    else:
                        raise
                        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(
                self.create_result(
                    resource_id="unknown",
                    resource_type="S3Bucket",
                    region=region,
                    status=CheckStatus.ERROR,
                    message=f"Failed to list S3 buckets: {error_code}",
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
                    resource_type="S3Bucket",
                    region=region,
                    status=CheckStatus.ERROR,
                    message=f"Unexpected error checking public buckets: {str(e)}",
                    details={"error": str(e)}
                )
            )
        
        return results
    
    def _get_public_access_block(self, s3_client, bucket_name: str) -> dict:
        """Get public access block configuration for a bucket."""
        try:
            response = s3_client.get_public_access_block(Bucket=bucket_name)
            pab = response['PublicAccessBlockConfiguration']
            
            all_blocked = (
                pab.get('BlockPublicAcls', False) and
                pab.get('IgnorePublicAcls', False) and
                pab.get('BlockPublicPolicy', False) and
                pab.get('RestrictPublicBuckets', False)
            )
            
            return {
                'all_blocked': all_blocked,
                'block_public_acls': pab.get('BlockPublicAcls', False),
                'ignore_public_acls': pab.get('IgnorePublicAcls', False),
                'block_public_policy': pab.get('BlockPublicPolicy', False),
                'restrict_public_buckets': pab.get('RestrictPublicBuckets', False),
                'details': pab
            }
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'NoSuchPublicAccessBlockConfiguration':
                # No public access block configured - means public access is allowed
                return {
                    'all_blocked': False,
                    'block_public_acls': False,
                    'ignore_public_acls': False,
                    'block_public_policy': False,
                    'restrict_public_buckets': False,
                    'details': 'No public access block configuration'
                }
            raise
    
    def _check_bucket_policy_public(self, s3_client, bucket_name: str) -> bool:
        """Check if bucket policy allows public access."""
        try:
            response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response['Policy'])
            
            # Check for public principals in policy statements
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal')
                if principal == '*' or principal == {'AWS': '*'}:
                    return True
                    
                # Check for public principals in array format
                if isinstance(principal, dict):
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, list) and '*' in aws_principals:
                        return True
                    elif aws_principals == '*':
                        return True
            
            return False
            
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'NoSuchBucketPolicy':
                return False
            raise
    
    def _check_bucket_acl_public(self, s3_client, bucket_name: str) -> bool:
        """Check if bucket ACL allows public access."""
        try:
            response = s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = response.get('Grants', [])
            
            for grant in grants:
                grantee = grant.get('Grantee', {})
                grantee_type = grantee.get('Type')
                
                # Check for public read/write grants
                if grantee_type == 'Group':
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        return True
            
            return False
            
        except ClientError:
            return False
