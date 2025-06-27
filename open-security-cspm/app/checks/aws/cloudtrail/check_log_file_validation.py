"""
AWS CloudTrail Check: Log File Validation
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


class CheckLogFileValidation(BaseCheck):
    """Check if CloudTrail log file validation is enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_CLOUDTRAIL_002",
            title="CloudTrail Log File Validation Enabled",
            description="Verify that CloudTrail log file validation is enabled to ensure log integrity. "
                       "Log file validation helps detect if logs have been tampered with after delivery.",
            provider=CloudProvider.AWS,
            service="CloudTrail",
            category="Logging & Monitoring",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 3.2",
                "AWS Security Best Practices",
                "NIST CSF",
                "SOC 2"
            ],
            references=[
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
            ],
            remediation="Enable CloudTrail log file validation: "
                       "1. Go to CloudTrail console. "
                       "2. Select your trail. "
                       "3. Edit trail settings. "
                       "4. Enable 'Log file validation'. "
                       "5. Save changes."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the CloudTrail log file validation check."""
        results = []
        
        try:
            cloudtrail_client = session.client('cloudtrail', region_name=region)
            
            response = cloudtrail_client.describe_trails()
            trails = response.get('trailList', [])
            
            if not trails:
                results.append(self.create_result(
                    resource_id=f"arn:aws:cloudtrail:{region}::trail/none",
                    resource_type="CloudTrail",
                    region=region,
                    status=CheckStatus.ERROR,
                    message="No CloudTrail trails found"
                ))
                return results
            
            for trail in trails:
                trail_name = trail.get('Name', 'Unknown')
                trail_arn = trail.get('TrailARN', f"arn:aws:cloudtrail:{region}::trail/{trail_name}")
                log_file_validation = trail.get('LogFileValidationEnabled', False)
                
                trail_details = {
                    'trail_name': trail_name,
                    'log_file_validation_enabled': log_file_validation,
                    's3_bucket': trail.get('S3BucketName')
                }
                
                if log_file_validation:
                    results.append(self.create_result(
                        resource_id=trail_arn,
                        resource_type="CloudTrail",
                        resource_name=trail_name,
                        region=region,
                        status=CheckStatus.PASSED,
                        message=f"CloudTrail trail '{trail_name}' has log file validation enabled",
                        details=trail_details
                    ))
                else:
                    results.append(self.create_result(
                        resource_id=trail_arn,
                        resource_type="CloudTrail",
                        resource_name=trail_name,
                        region=region,
                        status=CheckStatus.FAILED,
                        message=f"CloudTrail trail '{trail_name}' does not have log file validation enabled",
                        details=trail_details,
                        remediation="Enable log file validation for this CloudTrail trail"
                    ))
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="CloudTrail",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking CloudTrail log file validation: {error_code}",
                details={'error': str(e)}
            ))
        except Exception as e:
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="CloudTrail",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Unexpected error checking CloudTrail log file validation: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
