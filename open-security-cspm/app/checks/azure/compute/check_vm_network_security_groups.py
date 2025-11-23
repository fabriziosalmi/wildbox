"""
Azure Compute Check: Virtual Machines with Network Security Groups
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckVMNetworkSecurityGroups(BaseCheck):
    """Check if Virtual Machines have Network Security Groups attached."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AZURE_COMPUTE_001",
            title="Virtual Machines Have Network Security Groups",
            description="Verify that Azure Virtual Machines have Network Security Groups (NSGs) "
                       "attached to control network traffic. NSGs act as virtual firewalls "
                       "and are essential for network security.",
            provider=CloudProvider.AZURE,
            service="Compute",
            category="Network Security",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS Microsoft Azure Foundations Benchmark v1.3.0 - 6.1",
                "Azure Security Best Practices",
                "SOC 2",
                "NIST CSF"
            ],
            references=[
                "https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
                "https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices"
            ],
            remediation="Attach Network Security Group to VM: "
                       "1. Go to Azure portal -> Virtual machines. "
                       "2. Select the VM. "
                       "3. Go to 'Networking' settings. "
                       "4. Click 'Add inbound port rule' or 'Configure the network security group'. "
                       "5. Create or associate an NSG with appropriate rules. "
                       "6. Ensure deny-by-default policy is in place."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the VM Network Security Groups check.
        
        Args:
            session: Azure service client or credentials
            region: Azure region to check
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # This is a placeholder implementation
            # In a real implementation, you would use the Azure SDK
            # from azure.mgmt.compute import ComputeManagementClient
            # from azure.mgmt.network import NetworkManagementClient
            # from azure.identity import DefaultAzureCredential
            
            # For demo purposes, we'll simulate some findings
            simulated_vms = [
                {
                    'name': 'web-vm-1',
                    'resource_group': 'rg-production',
                    'location': 'East US',
                    'vm_size': 'Standard_B2s',
                    'os_type': 'Linux',
                    'power_state': 'VM running',
                    'network_interfaces': [
                        {
                            'name': 'web-vm-1-nic',
                            'has_nsg': True,
                            'nsg_name': 'web-tier-nsg',
                            'public_ip': '20.123.45.67',
                            'private_ip': '10.0.1.4'
                        }
                    ]
                },
                {
                    'name': 'database-vm',
                    'resource_group': 'rg-production',
                    'location': 'East US',
                    'vm_size': 'Standard_D2s_v3',
                    'os_type': 'Windows',
                    'power_state': 'VM running',
                    'network_interfaces': [
                        {
                            'name': 'database-vm-nic',
                            'has_nsg': False,
                            'nsg_name': None,
                            'public_ip': None,
                            'private_ip': '10.0.2.4'
                        }
                    ]
                },
                {
                    'name': 'admin-vm',
                    'resource_group': 'rg-management',
                    'location': 'West US 2',
                    'vm_size': 'Standard_B1s',
                    'os_type': 'Windows',
                    'power_state': 'VM running',
                    'network_interfaces': [
                        {
                            'name': 'admin-vm-nic1',
                            'has_nsg': True,
                            'nsg_name': 'admin-nsg',
                            'public_ip': '20.123.45.68',
                            'private_ip': '10.1.0.4'
                        },
                        {
                            'name': 'admin-vm-nic2',
                            'has_nsg': False,
                            'nsg_name': None,
                            'public_ip': None,
                            'private_ip': '10.1.1.4'
                        }
                    ]
                }
            ]
            
            for vm in simulated_vms:
                vm_name = vm['name']
                resource_group = vm['resource_group']
                location = vm['location']
                
                # Check each network interface for NSG
                nics_without_nsg = []
                nics_with_nsg = []
                
                for nic in vm['network_interfaces']:
                    if nic['has_nsg']:
                        nics_with_nsg.append({
                            'nic_name': nic['name'],
                            'nsg_name': nic['nsg_name']
                        })
                    else:
                        nics_without_nsg.append(nic['name'])
                
                vm_details = {
                    'vm_name': vm_name,
                    'resource_group': resource_group,
                    'location': location,
                    'vm_size': vm['vm_size'],
                    'os_type': vm['os_type'],
                    'power_state': vm['power_state'],
                    'total_nics': len(vm['network_interfaces']),
                    'nics_with_nsg': len(nics_with_nsg),
                    'nics_without_nsg': len(nics_without_nsg),
                    'nsg_details': nics_with_nsg,
                    'unprotected_nics': nics_without_nsg,
                    'check_timestamp': CheckResult.get_current_timestamp()
                }
                
                if not nics_without_nsg:
                    # All network interfaces have NSGs
                    results.append(self.create_result(
                        resource_id=f"/subscriptions/demo-sub/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}",
                        resource_type="Virtual Machine",
                        resource_name=vm_name,
                        region=location,
                        status=CheckStatus.PASSED,
                        message=f"VM {vm_name} has Network Security Groups attached to all network interfaces",
                        details=vm_details
                    ))
                else:
                    # Some network interfaces lack NSGs
                    results.append(self.create_result(
                        resource_id=f"/subscriptions/demo-sub/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}",
                        resource_type="Virtual Machine",
                        resource_name=vm_name,
                        region=location,
                        status=CheckStatus.FAILED,
                        message=f"VM {vm_name} has {len(nics_without_nsg)} network interface(s) without NSG: {', '.join(nics_without_nsg)}",
                        details=vm_details,
                        remediation=f"Attach Network Security Groups to unprotected network interfaces: {', '.join(nics_without_nsg)}"
                    ))
                        
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error checking Azure VM Network Security Groups: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="Virtual Machine",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking VM Network Security Groups: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
