"""
AWS CloudTrail Check: Multi-Region Enabled
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckCloudTrailMultiRegion(BaseCheck):
    """Check if CloudTrail is enabled for all regions."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_CLOUDTRAIL_001",
            title="CloudTrail Multi-Region Enabled",
            description="Verify that AWS CloudTrail is enabled for all regions to ensure "
                       "comprehensive audit logging across the entire AWS account.",
            provider=CloudProvider.AWS,
            service="CloudTrail",
            category="Logging and Monitoring",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 2.1",
                "AWS Security Best Practices",
                "SOC 2",
                "PCI DSS",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html",
                "https://aws.amazon.com/cloudtrail/"
            ],
            remediation="Enable CloudTrail for all regions: "
                       "1. Go to CloudTrail console. "
                       "2. Click 'Create trail'. "
                       "3. Enter trail name and select 'Apply trail to all regions'. "
                       "4. Configure S3 bucket for log storage. "
                       "5. Enable log file validation. "
                       "6. Consider enabling CloudWatch Logs integration."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the CloudTrail multi-region check.
        
        Args:
            session: boto3 session
            region: AWS region to check (CloudTrail is checked globally)
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create CloudTrail client
            cloudtrail_client = session.client('cloudtrail', region_name=region or 'us-east-1')
            
            # Get all trails
            response = cloudtrail_client.describe_trails()
            trails = response.get('trailList', [])
            
            if not trails:
                # No trails configured
                results.append(self.create_result(
                    resource_id="account",
                    resource_type="CloudTrail",
                    region=region,
                    status=CheckStatus.FAILED,
                    message="No CloudTrail trails are configured",
                    details={
                        'trails_count': 0,
                        'multi_region_trails': 0
                    },
                    remediation="Create at least one CloudTrail trail with multi-region enabled"
                ))
                return results
            
            # Check for multi-region trails
            multi_region_trails = []
            regional_trails = []
            
            for trail in trails:
                trail_name = trail.get('Name', 'Unknown')
                trail_arn = trail.get('TrailARN', '')
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                is_logging = False
                
                try:
                    # Check if trail is actively logging
                    status_response = cloudtrail_client.get_trail_status(Name=trail_arn)
                    is_logging = status_response.get('IsLogging', False)
                except Exception as e:
                    logger.warning(f"Could not get status for trail {trail_name}: {e}")
                
                trail_details = {
                    'trail_name': trail_name,
                    'trail_arn': trail_arn,
                    'is_multi_region': is_multi_region,
                    'is_logging': is_logging,
                    's3_bucket_name': trail.get('S3BucketName'),
                    'include_global_service_events': trail.get('IncludeGlobalServiceEvents', False),
                    'is_organization_trail': trail.get('IsOrganizationTrail', False),
                    'has_custom_event_selectors': trail.get('HasCustomEventSelectors', False),
                    'has_insight_selectors': trail.get('HasInsightSelectors', False)
                }
                
                if is_multi_region and is_logging:
                    multi_region_trails.append(trail_details)
                else:
                    regional_trails.append(trail_details)
            
            # Evaluate results
            if multi_region_trails:
                # At least one multi-region trail is active
                results.append(self.create_result(
                    resource_id="account",
                    resource_type="CloudTrail",
                    region=region,
                    status=CheckStatus.PASSED,
                    message=f"CloudTrail multi-region logging is enabled ({len(multi_region_trails)} active trail(s))",
                    details={
                        'total_trails': len(trails),
                        'multi_region_trails': len(multi_region_trails),
                        'regional_trails': len(regional_trails),
                        'active_multi_region_trails': multi_region_trails,
                        'regional_trails_details': regional_trails
                    }
                ))
            else:
                # No active multi-region trails
                results.append(self.create_result(
                    resource_id="account",
                    resource_type="CloudTrail",
                    region=region,
                    status=CheckStatus.FAILED,
                    message="CloudTrail multi-region logging is not enabled",
                    details={
                        'total_trails': len(trails),
                        'multi_region_trails': 0,
                        'regional_trails': len(regional_trails),
                        'regional_trails_details': regional_trails
                    },
                    remediation="Configure at least one CloudTrail trail with multi-region enabled and ensure it's actively logging"
                ))
                
        except Exception as e:
            logger.error(f"Error checking CloudTrail configuration: {e}")
            results.append(self.create_result(
                resource_id="account",
                resource_type="CloudTrail",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking CloudTrail configuration: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
