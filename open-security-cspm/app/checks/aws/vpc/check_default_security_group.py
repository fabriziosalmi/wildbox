"""
AWS VPC Check: Default Security Group Rules
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


class CheckDefaultSecurityGroup(BaseCheck):
    """Check if default security groups restrict all traffic."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_VPC_002",
            title="Default Security Groups Restrict All Traffic",
            description="Verify that default security groups restrict all inbound and outbound traffic. "
                       "Default security groups should not be used and should deny all traffic as a security best practice.",
            provider=CloudProvider.AWS,
            service="VPC",
            category="Network Security",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 5.3",
                "AWS Security Best Practices",
                "NIST CSF",
                "SOC 2"
            ],
            references=[
                "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup"
            ],
            remediation="Restrict default security group: "
                       "1. Go to EC2 console. "
                       "2. Navigate to Security Groups. "
                       "3. Select the default security group. "
                       "4. Remove all inbound rules. "
                       "5. Remove all outbound rules. "
                       "6. Ensure no resources use the default security group."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the default security group check."""
        results = []
        
        try:
            ec2_client = session.client('ec2', region_name=region)
            
            # Get all security groups
            response = ec2_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-name',
                        'Values': ['default']
                    }
                ]
            )
            
            security_groups = response.get('SecurityGroups', [])
            
            if not security_groups:
                results.append(self.create_result(
                    resource_id=f"arn:aws:ec2:{region}::security-group/default",
                    resource_type="SecurityGroup",
                    region=region,
                    status=CheckStatus.WARNING,
                    message="No default security groups found"
                ))
                return results
            
            for sg in security_groups:
                sg_id = sg.get('GroupId', 'Unknown')
                sg_name = sg.get('GroupName', 'Unknown')
                vpc_id = sg.get('VpcId', 'Unknown')
                
                sg_arn = f"arn:aws:ec2:{region}::security-group/{sg_id}"
                
                inbound_rules = sg.get('IpPermissions', [])
                outbound_rules = sg.get('IpPermissionsEgress', [])
                
                # Check if there are any rules (there shouldn't be for a secure default SG)
                issues = []
                
                if inbound_rules:
                    issues.append(f"{len(inbound_rules)} inbound rule(s)")
                
                if outbound_rules:
                    # Default SGs typically have a default outbound rule allowing all traffic
                    # We want to flag this as an issue
                    non_default_outbound = [
                        rule for rule in outbound_rules 
                        if not (
                            rule.get('IpProtocol') == '-1' and
                            rule.get('IpRanges') == [{'CidrIp': '0.0.0.0/0'}]
                        )
                    ]
                    if len(outbound_rules) > 0:
                        issues.append(f"{len(outbound_rules)} outbound rule(s)")
                
                sg_details = {
                    'security_group_id': sg_id,
                    'security_group_name': sg_name,
                    'vpc_id': vpc_id,
                    'inbound_rules_count': len(inbound_rules),
                    'outbound_rules_count': len(outbound_rules),
                    'inbound_rules': [
                        {
                            'protocol': rule.get('IpProtocol'),
                            'from_port': rule.get('FromPort'),
                            'to_port': rule.get('ToPort'),
                            'sources': self._format_rule_sources(rule)
                        }
                        for rule in inbound_rules
                    ],
                    'outbound_rules': [
                        {
                            'protocol': rule.get('IpProtocol'),
                            'from_port': rule.get('FromPort'),
                            'to_port': rule.get('ToPort'),
                            'destinations': self._format_rule_sources(rule)
                        }
                        for rule in outbound_rules
                    ]
                }
                
                if issues:
                    results.append(self.create_result(
                        resource_id=sg_arn,
                        resource_type="SecurityGroup",
                        resource_name=f"{sg_name} ({sg_id})",
                        region=region,
                        status=CheckStatus.FAILED,
                        message=f"Default security group '{sg_id}' has rules: {', '.join(issues)}",
                        details=sg_details,
                        remediation="Remove all rules from the default security group"
                    ))
                else:
                    results.append(self.create_result(
                        resource_id=sg_arn,
                        resource_type="SecurityGroup",
                        resource_name=f"{sg_name} ({sg_id})",
                        region=region,
                        status=CheckStatus.PASSED,
                        message=f"Default security group '{sg_id}' properly restricts all traffic",
                        details=sg_details
                    ))
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="SecurityGroup",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking default security groups: {error_code}",
                details={'error': str(e)}
            ))
        except Exception as e:
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="SecurityGroup",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Unexpected error checking default security groups: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
    
    def _format_rule_sources(self, rule: dict) -> List[str]:
        """Format the sources/destinations from a security group rule."""
        sources = []
        
        # IP ranges
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            description = ip_range.get('Description', '')
            if description:
                sources.append(f"{cidr} ({description})")
            else:
                sources.append(cidr)
        
        # IPv6 ranges
        for ipv6_range in rule.get('Ipv6Ranges', []):
            cidr = ipv6_range.get('CidrIpv6', '')
            description = ipv6_range.get('Description', '')
            if description:
                sources.append(f"{cidr} ({description})")
            else:
                sources.append(cidr)
        
        # Security group references
        for sg_ref in rule.get('UserIdGroupPairs', []):
            sg_id = sg_ref.get('GroupId', '')
            description = sg_ref.get('Description', '')
            if description:
                sources.append(f"sg:{sg_id} ({description})")
            else:
                sources.append(f"sg:{sg_id}")
        
        # Prefix lists
        for prefix_list in rule.get('PrefixListIds', []):
            pl_id = prefix_list.get('PrefixListId', '')
            description = prefix_list.get('Description', '')
            if description:
                sources.append(f"pl:{pl_id} ({description})")
            else:
                sources.append(f"pl:{pl_id}")
        
        return sources
