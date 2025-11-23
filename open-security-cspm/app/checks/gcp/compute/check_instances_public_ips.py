"""
GCP Compute Check: Instances with Public IPs
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckInstancesPublicIPs(BaseCheck):
    """Check for Compute Engine instances with public IP addresses."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="GCP_COMPUTE_001",
            title="Compute Instances Without Unnecessary Public IPs",
            description="Verify that Compute Engine instances do not have public IP addresses "
                       "unless required. Public IPs increase the attack surface and should be "
                       "avoided when possible, using Cloud NAT or bastion hosts instead.",
            provider=CloudProvider.GCP,
            service="Compute Engine",
            category="Network Security",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "CIS GCP Foundations Benchmark v1.2.0 - 4.9",
                "GCP Security Best Practices",
                "SOC 2"
            ],
            references=[
                "https://cloud.google.com/compute/docs/ip-addresses/external-ip-addresses",
                "https://cloud.google.com/nat/docs/overview"
            ],
            remediation="Remove unnecessary public IPs: "
                       "1. Go to Compute Engine console. "
                       "2. Select the instance. "
                       "3. Click 'Edit'. "
                       "4. Under 'Network interfaces', click 'Edit'. "
                       "5. Change 'External IP' to 'None'. "
                       "6. Configure Cloud NAT if internet access is needed."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the compute instances public IPs check.
        
        Args:
            session: GCP service client or credentials
            region: GCP zone/region to check
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # This is a placeholder implementation
            # In a real implementation, you would use the GCP Compute Engine API
            # from googleapiclient import discovery
            # compute = discovery.build('compute', 'v1', credentials=session)
            
            # For demo purposes, we'll simulate some findings
            simulated_instances = [
                {
                    'name': 'web-server-1',
                    'zone': 'us-central1-a',
                    'machine_type': 'e2-medium',
                    'status': 'RUNNING',
                    'has_public_ip': True,
                    'public_ip': '34.123.45.67',
                    'internal_ip': '10.128.0.2',
                    'tags': ['web-server', 'production'],
                    'labels': {'environment': 'prod', 'team': 'frontend'}
                },
                {
                    'name': 'database-server',
                    'zone': 'us-central1-b',
                    'machine_type': 'n1-standard-2',
                    'status': 'RUNNING',
                    'has_public_ip': False,
                    'public_ip': None,
                    'internal_ip': '10.128.0.3',
                    'tags': ['database', 'private'],
                    'labels': {'environment': 'prod', 'team': 'backend'}
                },
                {
                    'name': 'bastion-host',
                    'zone': 'us-central1-a',
                    'machine_type': 'e2-micro',
                    'status': 'RUNNING',
                    'has_public_ip': True,
                    'public_ip': '35.123.45.68',
                    'internal_ip': '10.128.0.4',
                    'tags': ['bastion', 'ssh-access'],
                    'labels': {'environment': 'prod', 'team': 'infrastructure'}
                }
            ]
            
            for instance in simulated_instances:
                instance_name = instance['name']
                zone = instance['zone']
                
                instance_details = {
                    'instance_name': instance_name,
                    'zone': zone,
                    'machine_type': instance['machine_type'],
                    'status': instance['status'],
                    'has_public_ip': instance['has_public_ip'],
                    'public_ip': instance['public_ip'],
                    'internal_ip': instance['internal_ip'],
                    'tags': instance['tags'],
                    'labels': instance['labels'],
                    'check_timestamp': CheckResult.get_current_timestamp()
                }
                
                if not instance['has_public_ip']:
                    # Instance does not have public IP (good)
                    results.append(self.create_result(
                        resource_id=f"projects/demo-project/zones/{zone}/instances/{instance_name}",
                        resource_type="Compute Instance",
                        resource_name=instance_name,
                        region=zone,
                        status=CheckStatus.PASSED,
                        message=f"Instance {instance_name} does not have a public IP address",
                        details=instance_details
                    ))
                else:
                    # Instance has public IP - check if justified
                    is_bastion = 'bastion' in instance['tags'] or 'ssh' in instance['tags']
                    is_web_server = any(tag in instance['tags'] for tag in ['web', 'frontend', 'load-balancer'])
                    
                    if is_bastion:
                        # Bastion hosts typically need public IPs
                        results.append(self.create_result(
                            resource_id=f"projects/demo-project/zones/{zone}/instances/{instance_name}",
                            resource_type="Compute Instance",
                            resource_name=instance_name,
                            region=zone,
                            status=CheckStatus.PASSED,
                            message=f"Instance {instance_name} has public IP but appears to be a bastion host",
                            details=instance_details
                        ))
                    elif is_web_server:
                        # Web servers might need public IPs, but should be behind load balancer
                        results.append(self.create_result(
                            resource_id=f"projects/demo-project/zones/{zone}/instances/{instance_name}",
                            resource_type="Compute Instance",
                            resource_name=instance_name,
                            region=zone,
                            status=CheckStatus.FAILED,
                            message=f"Web server {instance_name} has public IP - consider using load balancer instead",
                            details=instance_details,
                            remediation="Place web servers behind a load balancer and remove public IPs"
                        ))
                    else:
                        # General instance with public IP - likely unnecessary
                        results.append(self.create_result(
                            resource_id=f"projects/demo-project/zones/{zone}/instances/{instance_name}",
                            resource_type="Compute Instance",
                            resource_name=instance_name,
                            region=zone,
                            status=CheckStatus.FAILED,
                            message=f"Instance {instance_name} has unnecessary public IP address",
                            details=instance_details,
                            remediation="Remove public IP and configure Cloud NAT if internet access is needed"
                        ))
                        
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error checking GCP compute instances: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="Compute Instance",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking compute instances: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
