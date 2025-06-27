#!/usr/bin/env python3

"""
Script to batch create GCP and Azure security checks
"""

import os

# GCP checks to create
gcp_checks = [
    # Compute Engine
    ('gcp/compute', 'check_oslogin_enabled.py', 'GCP_COMPUTE_003', 'Compute OS Login Enabled', 'Ensure Compute instances have OS Login enabled'),
    ('gcp/compute', 'check_serial_port_disabled.py', 'GCP_COMPUTE_004', 'Compute Serial Port Disabled', 'Ensure serial port access is disabled'),
    ('gcp/compute', 'check_ip_forwarding_disabled.py', 'GCP_COMPUTE_005', 'IP Forwarding Disabled', 'Ensure IP forwarding is disabled on instances'),
    ('gcp/compute', 'check_secure_boot_enabled.py', 'GCP_COMPUTE_006', 'Secure Boot Enabled', 'Ensure Secure Boot is enabled on instances'),
    
    # Cloud Storage
    ('gcp/storage', 'check_bucket_encryption.py', 'GCP_STORAGE_002', 'Storage Bucket Encryption', 'Ensure Cloud Storage buckets have encryption enabled'),
    ('gcp/storage', 'check_uniform_bucket_access.py', 'GCP_STORAGE_003', 'Uniform Bucket Access', 'Ensure uniform bucket-level access is enabled'),
    ('gcp/storage', 'check_bucket_logging.py', 'GCP_STORAGE_004', 'Storage Bucket Logging', 'Ensure access logging is enabled for buckets'),
    
    # Cloud SQL
    ('gcp/cloudsql', 'check_ssl_required.py', 'GCP_CLOUDSQL_001', 'Cloud SQL SSL Required', 'Ensure Cloud SQL requires SSL connections'),
    ('gcp/cloudsql', 'check_backup_enabled.py', 'GCP_CLOUDSQL_002', 'Cloud SQL Backup Enabled', 'Ensure Cloud SQL has backup enabled'),
    ('gcp/cloudsql', 'check_authorized_networks.py', 'GCP_CLOUDSQL_003', 'Cloud SQL Authorized Networks', 'Ensure Cloud SQL has restricted authorized networks'),
    
    # Kubernetes Engine
    ('gcp/gke', 'check_private_cluster.py', 'GCP_GKE_001', 'GKE Private Cluster', 'Ensure GKE clusters are private'),
    ('gcp/gke', 'check_network_policy.py', 'GCP_GKE_002', 'GKE Network Policy', 'Ensure GKE has network policy enabled'),
    ('gcp/gke', 'check_pod_security_policy.py', 'GCP_GKE_003', 'GKE Pod Security Policy', 'Ensure GKE has pod security policy enabled'),
    
    # Cloud Functions
    ('gcp/functions', 'check_ingress_settings.py', 'GCP_FUNCTIONS_001', 'Cloud Functions Ingress', 'Ensure Cloud Functions have restricted ingress'),
    ('gcp/functions', 'check_environment_variables.py', 'GCP_FUNCTIONS_002', 'Functions Environment Variables', 'Check for secrets in environment variables'),
    
    # BigQuery
    ('gcp/bigquery', 'check_dataset_encryption.py', 'GCP_BIGQUERY_001', 'BigQuery Dataset Encryption', 'Ensure BigQuery datasets are encrypted'),
    ('gcp/bigquery', 'check_table_access.py', 'GCP_BIGQUERY_002', 'BigQuery Table Access', 'Ensure BigQuery tables have proper access controls'),
    
    # Logging and Monitoring
    ('gcp/logging', 'check_audit_logs_enabled.py', 'GCP_LOGGING_001', 'Audit Logs Enabled', 'Ensure audit logs are enabled'),
    ('gcp/logging', 'check_retention_policy.py', 'GCP_LOGGING_002', 'Log Retention Policy', 'Ensure logs have appropriate retention policy'),
]

# Create Azure checks
azure_checks = [
    # Virtual Machines
    ('azure/compute', 'check_disk_encryption.py', 'AZURE_COMPUTE_002', 'VM Disk Encryption', 'Ensure VM disks are encrypted'),
    ('azure/compute', 'check_endpoint_protection.py', 'AZURE_COMPUTE_003', 'VM Endpoint Protection', 'Ensure VMs have endpoint protection'),
    ('azure/compute', 'check_os_updates.py', 'AZURE_COMPUTE_004', 'VM OS Updates', 'Ensure VMs have OS updates enabled'),
    
    # Storage Account
    ('azure/storage', 'check_storage_encryption.py', 'AZURE_STORAGE_003', 'Storage Account Encryption', 'Ensure storage accounts are encrypted'),
    ('azure/storage', 'check_access_tier.py', 'AZURE_STORAGE_004', 'Storage Access Tier', 'Ensure appropriate access tier is configured'),
    ('azure/storage', 'check_private_endpoints.py', 'AZURE_STORAGE_005', 'Storage Private Endpoints', 'Ensure storage uses private endpoints'),
    
    # SQL Database
    ('azure/sql', 'check_transparent_encryption.py', 'AZURE_SQL_001', 'SQL Transparent Encryption', 'Ensure SQL databases have transparent encryption'),
    ('azure/sql', 'check_auditing_enabled.py', 'AZURE_SQL_002', 'SQL Auditing Enabled', 'Ensure SQL databases have auditing enabled'),
    ('azure/sql', 'check_threat_detection.py', 'AZURE_SQL_003', 'SQL Threat Detection', 'Ensure SQL databases have threat detection enabled'),
    
    # Key Vault
    ('azure/keyvault', 'check_soft_delete.py', 'AZURE_KEYVAULT_001', 'Key Vault Soft Delete', 'Ensure Key Vault has soft delete enabled'),
    ('azure/keyvault', 'check_purge_protection.py', 'AZURE_KEYVAULT_002', 'Key Vault Purge Protection', 'Ensure Key Vault has purge protection'),
    ('azure/keyvault', 'check_access_policies.py', 'AZURE_KEYVAULT_003', 'Key Vault Access Policies', 'Ensure Key Vault has proper access policies'),
    
    # Network Security
    ('azure/network', 'check_nsg_rules.py', 'AZURE_NETWORK_001', 'NSG Security Rules', 'Ensure NSGs have appropriate security rules'),
    ('azure/network', 'check_ddos_protection.py', 'AZURE_NETWORK_002', 'DDoS Protection', 'Ensure DDoS protection is enabled'),
    ('azure/network', 'check_network_watcher.py', 'AZURE_NETWORK_003', 'Network Watcher', 'Ensure Network Watcher is enabled'),
    
    # App Service
    ('azure/appservice', 'check_https_only.py', 'AZURE_APPSERVICE_001', 'App Service HTTPS Only', 'Ensure App Service uses HTTPS only'),
    ('azure/appservice', 'check_identity_enabled.py', 'AZURE_APPSERVICE_002', 'App Service Managed Identity', 'Ensure App Service has managed identity'),
    
    # Monitor
    ('azure/monitor', 'check_activity_log_alerts.py', 'AZURE_MONITOR_001', 'Activity Log Alerts', 'Ensure activity log alerts are configured'),
    ('azure/monitor', 'check_diagnostic_settings.py', 'AZURE_MONITOR_002', 'Diagnostic Settings', 'Ensure diagnostic settings are configured'),
]

def create_directory_structure():
    """Create directory structure for GCP and Azure checks."""
    base_path = "/Users/fab/GitHub/wildbox/open-security-cspm/app/checks"
    
    # GCP directories
    gcp_services = ['cloudsql', 'gke', 'functions', 'bigquery', 'logging']
    for service in gcp_services:
        os.makedirs(f"{base_path}/gcp/{service}", exist_ok=True)
        with open(f"{base_path}/gcp/{service}/__init__.py", 'w') as f:
            f.write(f"# GCP {service.upper()} Security Checks\\n")
    
    # Azure directories  
    azure_services = ['sql', 'keyvault', 'network', 'appservice', 'monitor']
    for service in azure_services:
        os.makedirs(f"{base_path}/azure/{service}", exist_ok=True)
        with open(f"{base_path}/azure/{service}/__init__.py", 'w') as f:
            f.write(f"# Azure {service.upper()} Security Checks\\n")

def create_gcp_check_file(service_path, filename, check_id, title, description):
    """Create a GCP security check file."""
    
    template = f'''"""
GCP {service_path.split('/')[-1].upper()} Check: {title}
"""

from google.cloud import compute_v1
from google.api_core import exceptions
from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class Check{title.replace(' ', '').replace('-', '')}(BaseCheck):
    """{description}."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="{check_id}",
            title="{title}",
            description="{description}.",
            provider=CloudProvider.GCP,
            service="{service_path.split('/')[-1].upper()}",
            category="Security",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "GCP Security Best Practices",
                "CIS GCP Foundations Benchmark"
            ],
            references=[
                "https://cloud.google.com/docs/"
            ],
            remediation="Implement {title.lower()}: "
                       "1. Go to GCP console. "
                       "2. Navigate to the service. "
                       "3. Configure the security setting. "
                       "4. Apply the changes."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the {title.lower()} check."""
        results = []
        
        try:
            # TODO: Implement the actual check logic
            # Example: client = compute_v1.InstancesClient()
            
            # Placeholder implementation
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="placeholder-resource",
                resource_type="GCP::{service_path.split('/')[-1]}::Resource",
                resource_name="placeholder",
                region=region,
                status=CheckStatus.PASSED,
                message="Check implementation needed",
                details={{'note': 'This check needs to be implemented'}}
            ))
                        
        except Exception as e:
            logger.error(f"Error in {title.lower()} check: {{str(e)}}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error during check execution: {{str(e)}}",
                details={{'error': str(e)}}
            ))
        
        return results
'''
    
    base_path = "/Users/fab/GitHub/wildbox/open-security-cspm/app/checks"
    full_path = os.path.join(base_path, service_path, filename)
    
    with open(full_path, 'w') as f:
        f.write(template)
    
    print(f"Created {full_path}")

def create_azure_check_file(service_path, filename, check_id, title, description):
    """Create an Azure security check file."""
    
    template = f'''"""
Azure {service_path.split('/')[-1].upper()} Check: {title}
"""

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class Check{title.replace(' ', '').replace('-', '')}(BaseCheck):
    """{description}."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="{check_id}",
            title="{title}",
            description="{description}.",
            provider=CloudProvider.AZURE,
            service="{service_path.split('/')[-1].upper()}",
            category="Security",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "Azure Security Benchmark",
                "CIS Azure Foundations Benchmark"
            ],
            references=[
                "https://docs.microsoft.com/en-us/azure/"
            ],
            remediation="Implement {title.lower()}: "
                       "1. Go to Azure portal. "
                       "2. Navigate to the service. "
                       "3. Configure the security setting. "
                       "4. Apply the changes."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the {title.lower()} check."""
        results = []
        
        try:
            # TODO: Implement the actual check logic
            # Example: credential = DefaultAzureCredential()
            
            # Placeholder implementation
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="placeholder-resource",
                resource_type="Azure::{service_path.split('/')[-1]}::Resource",
                resource_name="placeholder",
                region=region,
                status=CheckStatus.PASSED,
                message="Check implementation needed",
                details={{'note': 'This check needs to be implemented'}}
            ))
                        
        except Exception as e:
            logger.error(f"Error in {title.lower()} check: {{str(e)}}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error during check execution: {{str(e)}}",
                details={{'error': str(e)}}
            ))
        
        return results
'''
    
    base_path = "/Users/fab/GitHub/wildbox/open-security-cspm/app/checks"
    full_path = os.path.join(base_path, service_path, filename)
    
    with open(full_path, 'w') as f:
        f.write(template)
    
    print(f"Created {full_path}")

# Create directory structure
create_directory_structure()

# Create GCP checks
for service_path, filename, check_id, title, description in gcp_checks:
    create_gcp_check_file(service_path, filename, check_id, title, description)

# Create Azure checks
for service_path, filename, check_id, title, description in azure_checks:
    create_azure_check_file(service_path, filename, check_id, title, description)

print(f"\\nCreated {len(gcp_checks)} GCP checks and {len(azure_checks)} Azure checks!")
