"""
AWS VPC Check: Security Groups with Open Ports
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


class CheckSecurityGroupsOpenPorts(BaseCheck):
    """Check for security groups with unrestricted access (0.0.0.0/0)."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_VPC_001",
            title="Security Groups Restrict Access",
            description="Verify that security groups do not have unrestricted access (0.0.0.0/0) "
                       "for common ports like SSH (22), RDP (3389), or all ports. This helps "
                       "prevent unauthorized access to instances.",
            provider=CloudProvider.AWS,
            service="VPC",
            category="Network Security",
            severity=CheckSeverity.CRITICAL,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 4.1, 4.2",
                "AWS Security Best Practices",
                "SOC 2",
                "PCI DSS",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
                "https://aws.amazon.com/premiumsupport/knowledge-center/ec2-security-group-access-vpc/"
            ],
            remediation="Restrict security group access: "
                       "1. Go to VPC console. "
                       "2. Navigate to 'Security Groups'. "
                       "3. Select the security group with open access. "
                       "4. Edit inbound rules. "
                       "5. Replace 0.0.0.0/0 with specific IP ranges or security groups. "
                       "6. Consider using bastion hosts for SSH access."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the security groups open ports check.
        
        Args:
            session: AWS session/client
            region: AWS region to check
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create EC2 client for the region
            ec2_client = session.client('ec2', region_name=region)
            
            # Get all security groups
            response = ec2_client.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            
            # Common risky ports to check
            risky_ports = {
                22: 'SSH',
                3389: 'RDP',
                80: 'HTTP',
                443: 'HTTPS',
                21: 'FTP',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                135: 'RPC',
                445: 'SMB',
                1433: 'SQL Server',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                6379: 'Redis',
                27017: 'MongoDB'
            }
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', sg_id)
                vpc_id = sg.get('VpcId', 'EC2-Classic')
                
                # Check inbound rules
                inbound_issues = []
                open_ports = []
                
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    protocol = rule.get('IpProtocol', '')
                    
                    # Check for rules allowing access from anywhere
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        
                        if cidr == '0.0.0.0/0':
                            if protocol == '-1':
                                # All ports open
                                inbound_issues.append("All ports and protocols open to internet (0.0.0.0/0)")
                                open_ports.append("ALL")
                            elif from_port == to_port and from_port in risky_ports:
                                # Specific risky port open
                                port_name = risky_ports[from_port]
                                inbound_issues.append(f"Port {from_port} ({port_name}) open to internet (0.0.0.0/0)")
                                open_ports.append(f"{from_port} ({port_name})")
                            elif from_port != to_port:
                                # Port range open
                                inbound_issues.append(f"Port range {from_port}-{to_port} ({protocol}) open to internet (0.0.0.0/0)")
                                open_ports.append(f"{from_port}-{to_port}")
                            elif from_port == to_port:
                                # Single port open
                                inbound_issues.append(f"Port {from_port} ({protocol}) open to internet (0.0.0.0/0)")
                                open_ports.append(f"{from_port}")
                    
                    # Check for IPv6 unrestricted access
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        cidr_ipv6 = ipv6_range.get('CidrIpv6', '')
                        
                        if cidr_ipv6 == '::/0':
                            if protocol == '-1':
                                inbound_issues.append("All ports and protocols open to internet (IPv6 ::/0)")
                            elif from_port == to_port and from_port in risky_ports:
                                port_name = risky_ports[from_port]
                                inbound_issues.append(f"Port {from_port} ({port_name}) open to internet (IPv6 ::/0)")
                
                details = {
                    'security_group_id': sg_id,
                    'security_group_name': sg_name,
                    'vpc_id': vpc_id,
                    'region': region,
                    'inbound_rules_count': len(sg.get('IpPermissions', [])),
                    'outbound_rules_count': len(sg.get('IpPermissionsEgress', [])),
                    'open_ports': open_ports,
                    'issues_found': inbound_issues,
                    'check_timestamp': CheckResult.get_current_timestamp()
                }
                
                if not inbound_issues:
                    # Security group has no unrestricted access
                    results.append(self.create_result(
                        resource_id=sg_id,
                        resource_type="Security Group",
                        resource_name=sg_name,
                        region=region,
                        status=CheckStatus.PASSED,
                        message=f"Security group {sg_name} does not have unrestricted internet access",
                        details=details
                    ))
                else:
                    # Security group has unrestricted access
                    severity = CheckSeverity.CRITICAL if any("22" in issue or "3389" in issue or "ALL" in issue for issue in inbound_issues) else CheckSeverity.HIGH
                    
                    results.append(self.create_result(
                        resource_id=sg_id,
                        resource_type="Security Group",
                        resource_name=sg_name,
                        region=region,
                        status=CheckStatus.FAILED,
                        message=f"Security group {sg_name} has {len(inbound_issues)} unrestricted access rules",
                        details=details,
                        remediation=f"Restrict access for: {', '.join(open_ports[:3])}"
                    ))
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                # Insufficient permissions
                results.append(self.create_result(
                    resource_id=f"security-groups-{region}",
                    resource_type="Security Groups",
                    region=region,
                    status=CheckStatus.SKIPPED,
                    message=f"Insufficient permissions to check security groups in {region}",
                    details={'error': str(e)}
                ))
            else:
                # Other AWS API errors
                results.append(self.create_result(
                    resource_id=f"security-groups-{region}",
                    resource_type="Security Groups",
                    region=region,
                    status=CheckStatus.ERROR,
                    message=f"Error checking security groups in {region}: {error_code}",
                    details={'error': str(e)}
                ))
                
        except Exception as e:
            logger.error(f"Error checking security groups in {region}: {e}")
            results.append(self.create_result(
                resource_id=f"security-groups-{region}",
                resource_type="Security Groups",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking security groups in {region}: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
