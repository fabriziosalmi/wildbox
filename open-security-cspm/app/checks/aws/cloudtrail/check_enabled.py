"""
AWS CloudTrail Check: CloudTrail Enabled
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


class CheckCloudTrailEnabled(BaseCheck):
    """Check if CloudTrail is enabled in all regions."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_CLOUDTRAIL_001",
            title="CloudTrail Enabled in All Regions",
            description="Verify that CloudTrail is enabled and logging events in all AWS regions. "
                       "CloudTrail provides audit logs of API calls and is essential for security monitoring.",
            provider=CloudProvider.AWS,
            service="CloudTrail",
            category="Logging & Monitoring",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 3.1",
                "AWS Security Best Practices",
                "NIST CSF",
                "SOC 2",
                "HIPAA"
            ],
            references=[
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html",
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-supported-regions.html"
            ],
            remediation="Enable CloudTrail in all regions: "
                       "1. Go to CloudTrail console. "
                       "2. Create a new trail. "
                       "3. Enable 'Apply trail to all regions'. "
                       "4. Configure S3 bucket for log storage. "
                       "5. Enable log file integrity validation. "
                       "6. Review and create the trail."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the CloudTrail enabled check.
        
        Args:
            session: boto3 session
            region: AWS region to check
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create CloudTrail client
            cloudtrail_client = session.client('cloudtrail', region_name=region)
            
            # Describe trails
            response = cloudtrail_client.describe_trails()
            trails = response.get('trailList', [])
            
            if not trails:
                results.append(self.create_result(
                    resource_id=f"arn:aws:cloudtrail:{region}::trail/none",
                    resource_type="CloudTrail",
                    resource_name="No trails configured",
                    region=region,
                    status=CheckStatus.FAILED,
                    message="No CloudTrail trails are configured",
                    details={
                        'trails_count': 0,
                        'recommendation': 'Create at least one CloudTrail trail'
                    },
                    remediation="Create a CloudTrail trail that applies to all regions"
                ))
                return results
            
            # Check each trail
            active_multi_region_trails = 0
            
            for trail in trails:
                trail_name = trail.get('Name', 'Unknown')
                trail_arn = trail.get('TrailARN', f"arn:aws:cloudtrail:{region}::trail/{trail_name}")
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                is_logging = trail.get('IsLogging', False)
                
                # Get trail status
                try:
                    status_response = cloudtrail_client.get_trail_status(Name=trail_name)
                    is_logging = status_response.get('IsLogging', False)
                except ClientError as e:
                    logger.warning(f"Could not get status for trail {trail_name}: {e}")
                
                trail_details = {
                    'trail_name': trail_name,
                    'is_multi_region': is_multi_region,
                    'is_logging': is_logging,
                    's3_bucket': trail.get('S3BucketName'),
                    'include_global_service_events': trail.get('IncludeGlobalServiceEvents', False),
                    'log_file_validation_enabled': trail.get('LogFileValidationEnabled', False)
                }
                
                if is_logging and is_multi_region:
                    active_multi_region_trails += 1
                    results.append(self.create_result(
                        resource_id=trail_arn,
                        resource_type="CloudTrail",
                        resource_name=trail_name,
                        region=region,
                        status=CheckStatus.PASSED,
                        message=f"CloudTrail trail '{trail_name}' is properly configured",
                        details=trail_details
                    ))
                else:
                    issues = []
                    if not is_logging:
                        issues.append("not logging")
                    if not is_multi_region:
                        issues.append("not multi-region")
                    
                    results.append(self.create_result(
                        resource_id=trail_arn,
                        resource_type="CloudTrail",
                        resource_name=trail_name,
                        region=region,
                        status=CheckStatus.FAILED,
                        message=f"CloudTrail trail '{trail_name}' has issues: {', '.join(issues)}",
                        details=trail_details,
                        remediation="Configure trail to enable logging and multi-region support"
                    ))
            
            # Summary check for multi-region coverage
            if active_multi_region_trails == 0:
                results.append(self.create_result(
                    resource_id=f"arn:aws:cloudtrail:{region}::account/multi-region-coverage",
                    resource_type="CloudTrail",
                    resource_name="Multi-region coverage",
                    region=region,
                    status=CheckStatus.FAILED,
                    message="No active multi-region CloudTrail trails found",
                    details={
                        'total_trails': len(trails),
                        'active_multi_region_trails': active_multi_region_trails
                    },
                    remediation="Enable multi-region trail or create new multi-region trail"
                ))
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="CloudTrail",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking CloudTrail: {error_code}",
                details={'error': str(e), 'error_code': error_code}
            ))
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="CloudTrail",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Unexpected error checking CloudTrail: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
