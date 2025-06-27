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
            check_id="GCP_IAM_002",
            title="Service Account Keys Rotated Regularly",
            description="Verify that GCP service account keys are rotated regularly (within 90 days). "
                       "Regular key rotation reduces the risk of compromised credentials.",
            provider=CloudProvider.GCP,
            service="IAM",
            category="Access Control",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS GCP Foundations Benchmark v1.2.0 - 1.4",
                "GCP Security Best Practices",
                "NIST CSF",
                "SOC 2"
            ],
            references=[
                "https://cloud.google.com/iam/docs/service-accounts#service_account_keys",
                "https://cloud.google.com/iam/docs/best-practices-for-using-service-accounts"
            ],
            remediation="Rotate service account keys: "
                       "1. Go to IAM & Admin > Service Accounts. "
                       "2. Select the service account. "
                       "3. Go to Keys tab. "
                       "4. Create a new key. "
                       "5. Update applications to use the new key. "
                       "6. Delete the old key. "
                       "7. Implement automated key rotation."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the service account key rotation check."""
        results = []
        
        try:
            # This is a placeholder implementation
            # In a real implementation, you would use the Google Cloud IAM API
            # from googleapiclient import discovery
            # service = discovery.build('iam', 'v1', credentials=session)
            
            # For demo purposes, we'll simulate some findings
            simulated_service_accounts = [
                {
                    'name': 'projects/my-project/serviceAccounts/app-service@my-project.iam.gserviceaccount.com',
                    'email': 'app-service@my-project.iam.gserviceaccount.com',
                    'display_name': 'Application Service Account',
                    'keys': [
                        {
                            'name': 'projects/my-project/serviceAccounts/app-service@my-project.iam.gserviceaccount.com/keys/key1',
                            'validAfterTime': '2023-01-15T10:00:00Z',
                            'validBeforeTime': '2033-01-15T10:00:00Z',
                            'keyType': 'USER_MANAGED'
                        }
                    ]
                },
                {
                    'name': 'projects/my-project/serviceAccounts/old-service@my-project.iam.gserviceaccount.com',
                    'email': 'old-service@my-project.iam.gserviceaccount.com',
                    'display_name': 'Old Service Account',
                    'keys': [
                        {
                            'name': 'projects/my-project/serviceAccounts/old-service@my-project.iam.gserviceaccount.com/keys/key1',
                            'validAfterTime': '2023-01-01T10:00:00Z',
                            'validBeforeTime': '2033-01-01T10:00:00Z',
                            'keyType': 'USER_MANAGED'
                        }
                    ]
                },
                {
                    'name': 'projects/my-project/serviceAccounts/good-service@my-project.iam.gserviceaccount.com',
                    'email': 'good-service@my-project.iam.gserviceaccount.com',
                    'display_name': 'Recently Rotated Service Account',
                    'keys': [
                        {
                            'name': 'projects/my-project/serviceAccounts/good-service@my-project.iam.gserviceaccount.com/keys/key1',
                            'validAfterTime': '2024-11-01T10:00:00Z',
                            'validBeforeTime': '2034-11-01T10:00:00Z',
                            'keyType': 'USER_MANAGED'
                        }
                    ]
                }
            ]
            
            current_time = datetime.now()
            rotation_threshold = timedelta(days=90)
            
            for service_account in simulated_service_accounts:
                sa_name = service_account['name']
                sa_email = service_account['email']
                sa_display_name = service_account.get('display_name', sa_email)
                
                keys = service_account.get('keys', [])
                user_managed_keys = [key for key in keys if key.get('keyType') == 'USER_MANAGED']
                
                if not user_managed_keys:
                    # No user-managed keys, this is actually good
                    results.append(self.create_result(
                        resource_id=sa_name,
                        resource_type="ServiceAccount",
                        resource_name=sa_display_name,
                        region=region,
                        status=CheckStatus.PASSED,
                        message=f"Service account '{sa_display_name}' has no user-managed keys",
                        details={
                            'service_account_name': sa_name,
                            'service_account_email': sa_email,
                            'user_managed_keys_count': 0,
                            'recommendation': 'Continue using service account with no user-managed keys'
                        }
                    ))
                    continue
                
                # Check each user-managed key
                issues = []
                key_details = []
                
                for key in user_managed_keys:
                    key_name = key['name']
                    valid_after_str = key.get('validAfterTime', '')
                    
                    try:
                        # Parse the timestamp
                        valid_after = datetime.fromisoformat(valid_after_str.replace('Z', '+00:00'))
                        key_age = current_time - valid_after.replace(tzinfo=None)
                        
                        key_info = {
                            'key_name': key_name,
                            'valid_after': valid_after_str,
                            'age_days': key_age.days,
                            'needs_rotation': key_age > rotation_threshold
                        }
                        key_details.append(key_info)
                        
                        if key_age > rotation_threshold:
                            issues.append(f"Key {key_name.split('/')[-1]} is {key_age.days} days old")
                        
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Could not parse key timestamp {valid_after_str}: {e}")
                        key_details.append({
                            'key_name': key_name,
                            'valid_after': valid_after_str,
                            'age_days': 'unknown',
                            'needs_rotation': True
                        })
                        issues.append(f"Key {key_name.split('/')[-1]} has unparseable timestamp")
                
                sa_details = {
                    'service_account_name': sa_name,
                    'service_account_email': sa_email,
                    'user_managed_keys_count': len(user_managed_keys),
                    'key_details': key_details,
                    'rotation_threshold_days': rotation_threshold.days
                }
                
                if issues:
                    results.append(self.create_result(
                        resource_id=sa_name,
                        resource_type="ServiceAccount",
                        resource_name=sa_display_name,
                        region=region,
                        status=CheckStatus.FAILED,
                        message=f"Service account '{sa_display_name}' has old keys: {'; '.join(issues)}",
                        details=sa_details,
                        remediation="Rotate service account keys that are older than 90 days"
                    ))
                else:
                    results.append(self.create_result(
                        resource_id=sa_name,
                        resource_type="ServiceAccount",
                        resource_name=sa_display_name,
                        region=region,
                        status=CheckStatus.PASSED,
                        message=f"Service account '{sa_display_name}' has recently rotated keys",
                        details=sa_details
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking GCP service account key rotation: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="ServiceAccount",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking service account key rotation: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
