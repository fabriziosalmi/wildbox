"""
Azure Storage Check: Storage Account Public Access
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckStorageAccountPublicAccess(BaseCheck):
    """Check if Azure Storage Accounts allow public access."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AZURE_STORAGE_001",
            title="Storage Account Public Access Disabled",
            description="Verify that Azure Storage Accounts do not allow public access to blobs, containers, "
                       "or the storage account itself unless explicitly required.",
            provider=CloudProvider.AZURE,
            service="Storage",
            category="Storage",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS Microsoft Azure Foundations Benchmark v1.3.0 - 3.1",
                "Azure Security Best Practices",
                "SOC 2",
                "NIST CSF"
            ],
            references=[
                "https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
                "https://docs.microsoft.com/en-us/azure/storage/common/storage-account-overview"
            ],
            remediation="Disable public access for Storage Account: "
                       "1. Go to Azure Portal > Storage Accounts. "
                       "2. Select the storage account. "
                       "3. Go to 'Configuration' settings. "
                       "4. Set 'Allow Blob public access' to 'Disabled'. "
                       "5. Review container-level access policies. "
                       "6. Consider using private endpoints for secure access."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the Azure Storage Account public access check.
        
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
            # from azure.mgmt.storage import StorageManagementClient
            # from azure.identity import DefaultAzureCredential
            
            # For demo purposes, we'll simulate some findings
            
            # Simulate storage accounts with different configurations
            simulated_storage_accounts = [
                {
                    'name': 'mystorageaccount1',
                    'resource_group': 'my-rg-1',
                    'location': 'East US',
                    'allow_blob_public_access': True,
                    'public_network_access': 'Enabled',
                    'containers': [
                        {'name': 'public-container', 'public_access': 'Blob'},
                        {'name': 'private-container', 'public_access': 'None'}
                    ]
                },
                {
                    'name': 'mystorageaccount2',
                    'resource_group': 'my-rg-2',
                    'location': 'West US 2',
                    'allow_blob_public_access': False,
                    'public_network_access': 'Disabled',
                    'containers': [
                        {'name': 'secure-container', 'public_access': 'None'}
                    ]
                },
                {
                    'name': 'mystorageaccount3',
                    'resource_group': 'my-rg-3',
                    'location': 'Central US',
                    'allow_blob_public_access': None,  # Not explicitly configured
                    'public_network_access': 'Enabled',
                    'containers': []
                }
            ]
            
            for account in simulated_storage_accounts:
                account_name = account['name']
                
                # Check for public access configuration
                has_public_access_issues = []
                
                if account['allow_blob_public_access'] is True:
                    has_public_access_issues.append("Blob public access is enabled")
                elif account['allow_blob_public_access'] is None:
                    has_public_access_issues.append("Blob public access setting is not explicitly configured")
                
                if account['public_network_access'] == 'Enabled':
                    has_public_access_issues.append("Public network access is enabled")
                
                # Check containers for public access
                public_containers = [
                    container for container in account['containers']
                    if container['public_access'] != 'None'
                ]
                
                if public_containers:
                    has_public_access_issues.append(f"{len(public_containers)} container(s) have public access")
                
                account_details = {
                    'storage_account_name': account_name,
                    'resource_group': account['resource_group'],
                    'location': account['location'],
                    'allow_blob_public_access': account['allow_blob_public_access'],
                    'public_network_access': account['public_network_access'],
                    'containers_count': len(account['containers']),
                    'public_containers_count': len(public_containers),
                    'public_containers': [
                        {
                            'name': container['name'],
                            'public_access_level': container['public_access']
                        }
                        for container in public_containers
                    ],
                    'issues': has_public_access_issues
                }
                
                if has_public_access_issues:
                    # Storage account has public access issues
                    results.append(self.create_result(
                        resource_id=account_name,
                        resource_type="StorageAccount",
                        resource_name=account_name,
                        region=region,
                        status=CheckStatus.FAILED,
                        message=f"Storage Account {account_name} has public access configured: {', '.join(has_public_access_issues)}",
                        details=account_details,
                        remediation="Disable public access and configure private endpoints for secure access"
                    ))
                else:
                    # Storage account is properly secured
                    results.append(self.create_result(
                        resource_id=account_name,
                        resource_type="StorageAccount",
                        resource_name=account_name,
                        region=region,
                        status=CheckStatus.PASSED,
                        message=f"Storage Account {account_name} does not allow public access",
                        details=account_details
                    ))
                    
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error checking Azure Storage Accounts: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="StorageAccount",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking Storage Accounts: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
