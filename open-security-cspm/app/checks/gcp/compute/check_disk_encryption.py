"""
GCP Compute Engine Check: Disk Encryption
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckDiskEncryption(BaseCheck):
    """Check if Compute Engine disks are encrypted with customer-managed keys."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="GCP_COMPUTE_002",
            title="Compute Engine Disks Encrypted with Customer-Managed Keys",
            description="Verify that Compute Engine disks are encrypted with customer-managed encryption keys (CMEK). "
                       "Using CMEK provides better control over encryption keys and meets compliance requirements.",
            provider=CloudProvider.GCP,
            service="Compute Engine",
            category="Encryption",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "CIS GCP Foundations Benchmark v1.2.0 - 4.7",
                "GCP Security Best Practices",
                "NIST CSF",
                "SOC 2",
                "HIPAA"
            ],
            references=[
                "https://cloud.google.com/compute/docs/disks/customer-managed-encryption",
                "https://cloud.google.com/security/encryption-at-rest"
            ],
            remediation="Enable customer-managed encryption for disks: "
                       "1. Go to Compute Engine > Disks. "
                       "2. Select the disk. "
                       "3. Edit disk settings. "
                       "4. Choose customer-managed encryption key (CMEK). "
                       "5. Select or create a Cloud KMS key. "
                       "6. Save changes."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the Compute Engine disk encryption check."""
        results = []
        
        try:
            # This is a placeholder implementation
            # In a real implementation, you would use the Google Cloud Compute API
            # from googleapiclient import discovery
            # service = discovery.build('compute', 'v1', credentials=session)
            
            # For demo purposes, we'll simulate some findings
            simulated_zones = ['us-central1-a', 'us-central1-b', 'europe-west1-a']
            
            for zone in simulated_zones:
                simulated_disks = [
                    {
                        'name': 'instance-1-disk',
                        'zone': zone,
                        'type': 'pd-standard',
                        'sizeGb': '20',
                        'status': 'READY',
                        'diskEncryptionKey': None,  # Google-managed encryption
                        'users': ['https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances/instance-1']
                    },
                    {
                        'name': 'secure-disk',
                        'zone': zone,
                        'type': 'pd-ssd',
                        'sizeGb': '100',
                        'status': 'READY',
                        'diskEncryptionKey': {
                            'kmsKeyName': 'projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key'
                        },
                        'users': ['https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances/secure-instance']
                    },
                    {
                        'name': 'unattached-disk',
                        'zone': zone,
                        'type': 'pd-standard',
                        'sizeGb': '50',
                        'status': 'READY',
                        'diskEncryptionKey': None,
                        'users': []
                    }
                ]
                
                for disk in simulated_disks:
                    disk_name = disk['name']
                    disk_zone = disk['zone']
                    disk_resource_id = f"projects/my-project/zones/{disk_zone}/disks/{disk_name}"
                    
                    # Check encryption configuration
                    encryption_key = disk.get('diskEncryptionKey')
                    is_cmek_encrypted = encryption_key is not None and 'kmsKeyName' in encryption_key
                    
                    disk_details = {
                        'disk_name': disk_name,
                        'zone': disk_zone,
                        'type': disk.get('type'),
                        'size_gb': disk.get('sizeGb'),
                        'status': disk.get('status'),
                        'is_cmek_encrypted': is_cmek_encrypted,
                        'encryption_key': encryption_key,
                        'attached_instances': len(disk.get('users', [])),
                        'users': disk.get('users', [])
                    }
                    
                    if is_cmek_encrypted:
                        results.append(self.create_result(
                            resource_id=disk_resource_id,
                            resource_type="ComputeDisk",
                            resource_name=disk_name,
                            region=disk_zone,
                            status=CheckStatus.PASSED,
                            message=f"Compute Engine disk '{disk_name}' is encrypted with customer-managed key",
                            details=disk_details
                        ))
                    else:
                        # Check if this is a boot disk or important disk
                        severity = CheckStatus.FAILED
                        
                        # If disk is not attached to any instance, it's lower priority
                        if not disk.get('users'):
                            severity = CheckStatus.WARNING
                        
                        results.append(self.create_result(
                            resource_id=disk_resource_id,
                            resource_type="ComputeDisk",
                            resource_name=disk_name,
                            region=disk_zone,
                            status=severity,
                            message=f"Compute Engine disk '{disk_name}' is not encrypted with customer-managed key",
                            details=disk_details,
                            remediation="Configure customer-managed encryption for this disk"
                        ))
                        
        except Exception as e:
            logger.error(f"Error checking GCP Compute Engine disk encryption: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="ComputeDisk",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking Compute Engine disk encryption: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
