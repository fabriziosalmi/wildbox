"""
AWS RDS Check: Multi-AZ Deployment
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


class CheckRDSMultiAZ(BaseCheck):
    """Check if RDS instances have Multi-AZ deployment enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_RDS_003",
            title="RDS Multi-AZ Deployment Enabled",
            description="Ensure RDS instances have Multi-AZ deployment enabled for high availability "
                       "and automatic failover capabilities.",
            provider=CloudProvider.AWS,
            service="RDS",
            category="High Availability",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "AWS Well-Architected Framework",
                "AWS Security Best Practices"
            ],
            references=[
                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"
            ],
            remediation="Enable Multi-AZ deployment: "
                       "1. Go to RDS console. "
                       "2. Select the DB instance. "
                       "3. Click 'Modify'. "
                       "4. Enable 'Multi-AZ deployment'. "
                       "5. Apply changes during maintenance window."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the RDS Multi-AZ check."""
        results = []
        
        try:
            rds_client = session.client('rds', region_name=region)
            paginator = rds_client.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db_instance in page['DBInstances']:
                    instance_id = db_instance['DBInstanceIdentifier']
                    multi_az = db_instance.get('MultiAZ', False)
                    engine = db_instance.get('Engine', 'unknown')
                    
                    if multi_az:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"rds-instance-{instance_id}",
                            resource_type="AWS::RDS::DBInstance",
                            resource_name=instance_id,
                            region=region,
                            status=CheckStatus.PASSED,
                            message=f"RDS instance '{instance_id}' has Multi-AZ enabled",
                            details={
                                'instance_id': instance_id,
                                'multi_az': multi_az,
                                'engine': engine
                            }
                        ))
                    else:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"rds-instance-{instance_id}",
                            resource_type="AWS::RDS::DBInstance",
                            resource_name=instance_id,
                            region=region,
                            status=CheckStatus.FAILED,
                            message=f"RDS instance '{instance_id}' does not have Multi-AZ enabled",
                            details={
                                'instance_id': instance_id,
                                'multi_az': multi_az,
                                'engine': engine
                            }
                        ))
                        
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error in RDS Multi-AZ check: {str(e)}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error during check execution: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
