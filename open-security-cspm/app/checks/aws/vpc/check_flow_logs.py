"""
AWS VPC Check: VPC Flow Logs Enabled
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


class CheckVPCFlowLogsEnabled(BaseCheck):
    """Check if VPC Flow Logs are enabled for all VPCs."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_VPC_001",
            title="VPC Flow Logs Enabled",
            description="Verify that VPC Flow Logs are enabled to capture network traffic information. "
                       "Flow logs help detect suspicious network activity and assist in security investigations.",
            provider=CloudProvider.AWS,
            service="VPC",
            category="Network Security",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 2.9",
                "AWS Security Best Practices",
                "SOC 2",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
                "https://aws.amazon.com/blogs/aws/vpc-flow-logs-log-and-view-network-traffic-flows/"
            ],
            remediation="Enable VPC Flow Logs: "
                       "1. Go to VPC console. "
                       "2. Select the VPC. "
                       "3. Click 'Flow logs' tab. "
                       "4. Click 'Create flow log'. "
                       "5. Configure flow log settings and destination (CloudWatch/S3). "
                       "6. Ensure proper IAM permissions are configured."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the VPC Flow Logs check.
        
        Args:
            session: boto3 session
            region: AWS region to check
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create EC2 client
            ec2_client = session.client('ec2', region_name=region)
            
            # Get all VPCs in the region
            response = ec2_client.describe_vpcs()
            vpcs = response.get('Vpcs', [])
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                vpc_name = self._get_vpc_name(vpc)
                
                try:
                    # Check if flow logs are enabled for this VPC
                    flow_logs_response = ec2_client.describe_flow_logs(
                        Filters=[
                            {'Name': 'resource-id', 'Values': [vpc_id]},
                            {'Name': 'flow-log-status', 'Values': ['ACTIVE']}
                        ]
                    )
                    
                    active_flow_logs = flow_logs_response.get('FlowLogs', [])
                    
                    if active_flow_logs:
                        # Flow logs are enabled
                        flow_log_details = []
                        for log in active_flow_logs:
                            flow_log_details.append({
                                'flow_log_id': log.get('FlowLogId'),
                                'log_destination_type': log.get('LogDestinationType'),
                                'log_destination': log.get('LogDestination'),
                                'traffic_type': log.get('TrafficType'),
                                'creation_time': log.get('CreationTime').isoformat() if log.get('CreationTime') else None
                            })
                        
                        results.append(self.create_result(
                            resource_id=vpc_id,
                            resource_type="VPC",
                            resource_name=vpc_name,
                            region=region,
                            status=CheckStatus.PASSED,
                            message=f"VPC Flow Logs are enabled for VPC {vpc_id}",
                            details={
                                'vpc_id': vpc_id,
                                'vpc_name': vpc_name,
                                'flow_logs_count': len(active_flow_logs),
                                'flow_logs': flow_log_details,
                                'is_default_vpc': vpc.get('IsDefault', False)
                            }
                        ))
                    else:
                        # Flow logs are not enabled
                        results.append(self.create_result(
                            resource_id=vpc_id,
                            resource_type="VPC",
                            resource_name=vpc_name,
                            region=region,
                            status=CheckStatus.FAILED,
                            message=f"VPC Flow Logs are not enabled for VPC {vpc_id}",
                            details={
                                'vpc_id': vpc_id,
                                'vpc_name': vpc_name,
                                'is_default_vpc': vpc.get('IsDefault', False),
                                'cidr_block': vpc.get('CidrBlock'),
                                'state': vpc.get('State')
                            },
                            remediation="Enable VPC Flow Logs to monitor network traffic and detect suspicious activity"
                        ))
                        
                except ClientError as e:
                    logger.error(f"Error checking flow logs for VPC {vpc_id}: {e}")
                    results.append(self.create_result(
                        resource_id=vpc_id,
                        resource_type="VPC",
                        resource_name=vpc_name,
                        region=region,
                        status=CheckStatus.ERROR,
                        message=f"Error checking flow logs for VPC {vpc_id}: {str(e)}",
                        details={'error': str(e)}
                    ))
                    
        except ClientError as e:
            logger.error(f"Error listing VPCs in region {region}: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="VPC",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error listing VPCs: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
    
    def _get_vpc_name(self, vpc: dict) -> str:
        """Extract VPC name from tags."""
        for tag in vpc.get('Tags', []):
            if tag.get('Key') == 'Name':
                return tag.get('Value', 'Unnamed VPC')
        return 'Unnamed VPC'
