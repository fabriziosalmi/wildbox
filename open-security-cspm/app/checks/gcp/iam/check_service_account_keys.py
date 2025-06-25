"""
GCP IAM Check: Service Account Key Rotation
"""

from typing import List, Any, Optional
import logging
from datetime import datetime, timedelta

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckServiceAccountKeyRotation(BaseCheck):
    """Check if GCP service account keys are rotated regularly."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="GCP_IAM_001",
            title="Service Account Key Rotation",
            description="Verify that GCP service account keys are rotated regularly (within 90 days). "
                       "Regular key rotation reduces the risk of compromise from long-lived credentials.",
            provider=CloudProvider.GCP,
            service="IAM",
            category="Identity and Access Management",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS GCP Foundations Benchmark v1.2.0 - 1.4",
                "GCP Security Best Practices",
                "SOC 2",
                "NIST CSF"
            ],
            references=[
                "https://cloud.google.com/iam/docs/understanding-service-accounts",
                "https://cloud.google.com/iam/docs/creating-managing-service-account-keys"
            ],
            remediation="Rotate service account keys: "
                       "1. Go to GCP Console > IAM & Admin > Service Accounts. "
                       "2. Select the service account. "
                       "3. Click 'Keys' tab. "
                       "4. Click 'Add Key' > 'Create new key'. "
                       "5. Delete old keys after updating applications. "
                       "6. Consider using workload identity or other alternatives to service account keys."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the service account key rotation check.
        
        Args:
            session: GCP service client or credentials
            region: GCP region/zone (optional for IAM)
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # This is a placeholder implementation
            # In a real implementation, you would use the Google Cloud IAM API
            # from google.cloud import iam
            
            # For demo purposes, we'll simulate some findings
            
            # Simulate service accounts with old keys
            simulated_service_accounts = [
                {
                    'name': 'projects/my-project/serviceAccounts/old-sa@my-project.iam.gserviceaccount.com',
                    'display_name': 'Old Service Account',
                    'keys': [
                        {
                            'name': 'projects/my-project/serviceAccounts/old-sa@my-project.iam.gserviceaccount.com/keys/key1',
                            'key_id': 'key1',
                            'key_type': 'USER_MANAGED',
                            'created_time': datetime.utcnow() - timedelta(days=150)
                        }
                    ]
                },
                {
                    'name': 'projects/my-project/serviceAccounts/new-sa@my-project.iam.gserviceaccount.com',
                    'display_name': 'New Service Account',
                    'keys': [
                        {
                            'name': 'projects/my-project/serviceAccounts/new-sa@my-project.iam.gserviceaccount.com/keys/key2',
                            'key_id': 'key2',
                            'key_type': 'USER_MANAGED',
                            'created_time': datetime.utcnow() - timedelta(days=30)
                        }
                    ]
                }
            ]
            
            for sa in simulated_service_accounts:
                sa_email = sa['name'].split('/')[-1]
                sa_display_name = sa['display_name']
                
                old_keys = []
                recent_keys = []
                
                for key in sa['keys']:
                    key_age = (datetime.utcnow() - key['created_time']).days
                    
                    if key_age > 90:
                        old_keys.append({
                            'key_id': key['key_id'],
                            'age_days': key_age,
                            'created_time': key['created_time'].isoformat()
                        })
                    else:
                        recent_keys.append({
                            'key_id': key['key_id'],
                            'age_days': key_age,
                            'created_time': key['created_time'].isoformat()
                        })
                
                sa_details = {
                    'service_account_email': sa_email,
                    'display_name': sa_display_name,
                    'total_keys': len(sa['keys']),
                    'old_keys_count': len(old_keys),
                    'recent_keys_count': len(recent_keys),
                    'old_keys': old_keys,
                    'recent_keys': recent_keys
                }
                
                if old_keys:
                    # Found old keys
                    results.append(self.create_result(
                        resource_id=sa_email,
                        resource_type="ServiceAccount",
                        resource_name=sa_display_name,
                        region=region,
                        status=CheckStatus.FAILED,
                        message=f"Service account {sa_email} has {len(old_keys)} key(s) older than 90 days",
                        details=sa_details,
                        remediation="Rotate service account keys that are older than 90 days"
                    ))
                else:
                    # All keys are recent
                    results.append(self.create_result(
                        resource_id=sa_email,
                        resource_type="ServiceAccount",
                        resource_name=sa_display_name,
                        region=region,
                        status=CheckStatus.PASSED,
                        message=f"Service account {sa_email} has all keys rotated within 90 days",
                        details=sa_details
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking GCP service account keys: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="ServiceAccount",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking service account keys: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
