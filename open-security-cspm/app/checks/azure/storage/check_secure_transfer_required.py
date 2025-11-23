"""
Azure Storage Check: Secure Transfer Required
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckSecureTransferRequired(BaseCheck):
    """Check if Azure Storage Accounts require secure transfer (HTTPS)."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AZURE_STORAGE_002",
            title="Storage Accounts Require Secure Transfer",
            description="Verify that Azure Storage Accounts have 'Secure transfer required' enabled. "
                       "This ensures all requests to storage accounts use HTTPS/TLS encryption in transit.",
            provider=CloudProvider.AZURE,
            service="Storage",
            category="Encryption",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS Microsoft Azure Foundations Benchmark v1.3.0 - 3.1",
                "Azure Security Best Practices",
                "NIST CSF",
                "SOC 2",
                "HIPAA"
            ],
            references=[
                "https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer"
            ],
            remediation="Enable secure transfer for storage account: "
                       "1. Go to Azure Portal > Storage accounts. "
                       "2. Select your storage account. "
                       "3. Go to Settings > Configuration. "
                       "4. Set 'Secure transfer required' to Enabled. "
                       "5. Save changes."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the storage account secure transfer check."""
        results = []
        
        try:
            # This is a placeholder implementation
            # In a real implementation, you would use the Azure Storage Management API
            # from azure.mgmt.storage import StorageManagementClient
            
            # For demo purposes, we'll simulate some findings
            simulated_storage_accounts = [
                {
                    'name': 'mysecurestorageaccount',
                    'resourceGroup': 'production-rg',
                    'location': 'eastus',
                    'kind': 'StorageV2',
                    'tier': 'Standard',
                    'replication': 'LRS',
                    'httpsTrafficOnlyEnabled': True,
                    'minimumTlsVersion': 'TLS1_2',
                    'allowBlobPublicAccess': False
                },
                {
                    'name': 'myoldstorage',
                    'resourceGroup': 'legacy-rg',
                    'location': 'westus',
                    'kind': 'Storage',
                    'tier': 'Standard',
                    'replication': 'GRS',
                    'httpsTrafficOnlyEnabled': False,
                    'minimumTlsVersion': 'TLS1_0',
                    'allowBlobPublicAccess': True
                },
                {
                    'name': 'partiallysecurestorage',
                    'resourceGroup': 'development-rg',
                    'location': 'centralus',
                    'kind': 'StorageV2',
                    'tier': 'Standard',
                    'replication': 'ZRS',
                    'httpsTrafficOnlyEnabled': True,
                    'minimumTlsVersion': 'TLS1_1',
                    'allowBlobPublicAccess': False
                }
            ]
            
            for storage_account in simulated_storage_accounts:
                account_name = storage_account['name']
                resource_group = storage_account['resourceGroup']
                account_location = storage_account['location']
                
                account_resource_id = f"/subscriptions/subscription-id/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account_name}"
                
                # Check secure transfer settings
                https_only = storage_account.get('httpsTrafficOnlyEnabled', False)
                min_tls_version = storage_account.get('minimumTlsVersion', 'TLS1_0')
                
                # Analyze security configuration
                issues = []
                recommendations = []
                
                if not https_only:
                    issues.append("Secure transfer not required")
                    recommendations.append("Enable secure transfer requirement")
                
                if min_tls_version not in ['TLS1_2']:
                    issues.append(f"Minimum TLS version is {min_tls_version} (should be TLS1_2)")
                    recommendations.append("Set minimum TLS version to 1.2")
                
                account_details = {
                    'account_name': account_name,
                    'resource_group': resource_group,
                    'location': account_location,
                    'kind': storage_account.get('kind'),
                    'tier': storage_account.get('tier'),
                    'replication': storage_account.get('replication'),
                    'https_traffic_only_enabled': https_only,
                    'minimum_tls_version': min_tls_version,
                    'allow_blob_public_access': storage_account.get('allowBlobPublicAccess'),
                    'security_issues': issues,
                    'recommendations': recommendations
                }
                
                if not issues:
                    results.append(self.create_result(
                        resource_id=account_resource_id,
                        resource_type="StorageAccount",
                        resource_name=account_name,
                        region=account_location,
                        status=CheckStatus.PASSED,
                        message=f"Storage account '{account_name}' requires secure transfer",
                        details=account_details
                    ))
                else:
                    # Determine severity based on issues
                    status = CheckStatus.FAILED
                    if https_only and min_tls_version in ['TLS1_1']:
                        status = CheckStatus.WARNING  # HTTPS required but old TLS
                    
                    results.append(self.create_result(
                        resource_id=account_resource_id,
                        resource_type="StorageAccount",
                        resource_name=account_name,
                        region=account_location,
                        status=status,
                        message=f"Storage account '{account_name}' has security issues: {', '.join(issues)}",
                        details=account_details,
                        remediation="; ".join(recommendations)
                    ))
                    
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error checking Azure Storage secure transfer: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="StorageAccount",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking Storage Account secure transfer: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
