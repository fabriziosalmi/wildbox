"""
AWS KMS Check: Key Rotation Enabled
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckKMSKeyRotation(BaseCheck):
    """Check if KMS key rotation is enabled for customer-managed keys."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_KMS_001",
            title="KMS Key Rotation Enabled",
            description="Verify that AWS KMS key rotation is enabled for customer-managed keys. "
                       "Regular key rotation helps reduce the risk of data compromise.",
            provider=CloudProvider.AWS,
            service="KMS",
            category="Encryption",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 2.8",
                "AWS Security Best Practices",
                "SOC 2",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/kms/latest/developerguide/rotating-keys.html",
                "https://aws.amazon.com/kms/"
            ],
            remediation="Enable KMS key rotation: "
                       "1. Go to KMS console. "
                       "2. Select the customer-managed key. "
                       "3. Click 'Key rotation' tab. "
                       "4. Enable 'Automatically rotate this KMS key every year'. "
                       "5. Review and update applications that might be affected."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the KMS key rotation check.
        
        Args:
            session: boto3 session
            region: AWS region to check
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create KMS client
            kms_client = session.client('kms', region_name=region)
            
            # List all customer-managed keys
            paginator = kms_client.get_paginator('list_keys')
            
            for page in paginator.paginate():
                keys = page.get('Keys', [])
                
                for key in keys:
                    key_id = key['KeyId']
                    
                    try:
                        # Get key details
                        key_details = kms_client.describe_key(KeyId=key_id)
                        key_metadata = key_details['KeyMetadata']
                        
                        # Skip AWS managed keys (they have automatic rotation)
                        if key_metadata.get('KeyManager') == 'AWS':
                            continue
                        
                        # Skip keys that are not enabled
                        if key_metadata.get('KeyState') != 'Enabled':
                            continue
                        
                        key_arn = key_metadata.get('Arn')
                        key_description = key_metadata.get('Description', 'No description')
                        creation_date = key_metadata.get('CreationDate')
                        key_usage = key_metadata.get('KeyUsage', 'ENCRYPT_DECRYPT')
                        key_spec = key_metadata.get('KeySpec', 'SYMMETRIC_DEFAULT')
                        
                        # Check key rotation status
                        try:
                            rotation_response = kms_client.get_key_rotation_status(KeyId=key_id)
                            rotation_enabled = rotation_response.get('KeyRotationEnabled', False)
                        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                            # Some key types don't support rotation
                            if 'is not valid for this operation' in str(e):
                                # Skip asymmetric keys and HMAC keys
                                continue
                            else:
                                logger.warning(f"Could not check rotation status for key {key_id}: {e}")
                                rotation_enabled = False
                        
                        key_details_info = {
                            'key_id': key_id,
                            'key_arn': key_arn,
                            'description': key_description,
                            'creation_date': creation_date.isoformat() if creation_date else None,
                            'key_usage': key_usage,
                            'key_spec': key_spec,
                            'key_state': key_metadata.get('KeyState'),
                            'rotation_enabled': rotation_enabled
                        }
                        
                        if rotation_enabled:
                            # Key rotation is enabled
                            results.append(self.create_result(
                                resource_id=key_id,
                                resource_type="KMSKey",
                                resource_name=key_description,
                                region=region,
                                status=CheckStatus.PASSED,
                                message=f"KMS key rotation is enabled for key {key_id}",
                                details=key_details_info
                            ))
                        else:
                            # Key rotation is not enabled
                            results.append(self.create_result(
                                resource_id=key_id,
                                resource_type="KMSKey",
                                resource_name=key_description,
                                region=region,
                                status=CheckStatus.FAILED,
                                message=f"KMS key rotation is not enabled for key {key_id}",
                                details=key_details_info,
                                remediation="Enable automatic key rotation for this customer-managed KMS key"
                            ))
                            
                    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                        logger.error(f"Error checking key {key_id}: {e}")
                        results.append(self.create_result(
                            resource_id=key_id,
                            resource_type="KMSKey",
                            region=region,
                            status=CheckStatus.ERROR,
                            message=f"Error checking key rotation for {key_id}: {str(e)}",
                            details={'error': str(e)}
                        ))
                        
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error listing KMS keys in region {region}: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="KMSKey",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error listing KMS keys: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
