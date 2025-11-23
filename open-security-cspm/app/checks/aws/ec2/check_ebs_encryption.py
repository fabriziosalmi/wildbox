"""
AWS EC2 Check: EBS Default Encryption
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


class CheckEBSEncryption(BaseCheck):
    """Check if EBS default encryption is enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_EC2_001",
            title="EBS Default Encryption Enabled",
            description="Verify that EBS default encryption is enabled to ensure all new EBS volumes "
                       "are encrypted by default. This helps protect data at rest and ensures compliance.",
            provider=CloudProvider.AWS,
            service="EC2",
            category="Encryption",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 2.2.1",
                "AWS Security Best Practices",
                "SOC 2",
                "PCI DSS",
                "HIPAA"
            ],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/encryption-by-default.html"
            ],
            remediation="Enable EBS default encryption: "
                       "1. Go to EC2 console. "
                       "2. Navigate to 'Settings' -> 'EBS encryption'. "
                       "3. Enable 'Always encrypt new EBS volumes'. "
                       "4. Select appropriate KMS key for encryption. "
                       "5. Apply settings to region."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the EBS default encryption check.
        
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
            
            # Check EBS default encryption settings
            response = ec2_client.describe_ebs_default_kms_key_id()
            encryption_response = ec2_client.describe_ebs_encryption_by_default()
            
            # Get encryption status
            encryption_enabled = encryption_response.get('EbsEncryptionByDefault', False)
            kms_key_id = response.get('KmsKeyId')
            
            details = {
                'region': region,
                'encryption_enabled': encryption_enabled,
                'kms_key_id': kms_key_id,
                'check_timestamp': CheckResult.get_current_timestamp()
            }
            
            if encryption_enabled:
                # EBS default encryption is enabled
                results.append(self.create_result(
                    resource_id=f"ebs-encryption-{region}",
                    resource_type="EBS Encryption",
                    resource_name=f"EBS Default Encryption ({region})",
                    region=region,
                    status=CheckStatus.PASSED,
                    message=f"EBS default encryption is enabled in region {region}",
                    details=details
                ))
            else:
                # EBS default encryption is disabled
                results.append(self.create_result(
                    resource_id=f"ebs-encryption-{region}",
                    resource_type="EBS Encryption",
                    resource_name=f"EBS Default Encryption ({region})",
                    region=region,
                    status=CheckStatus.FAILED,
                    message=f"EBS default encryption is disabled in region {region}",
                    details=details,
                    remediation="Enable EBS default encryption in EC2 console settings"
                ))
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                # Insufficient permissions
                results.append(self.create_result(
                    resource_id=f"ebs-encryption-{region}",
                    resource_type="EBS Encryption",
                    region=region,
                    status=CheckStatus.SKIPPED,
                    message=f"Insufficient permissions to check EBS encryption in {region}",
                    details={'error': str(e)}
                ))
            else:
                # Other AWS API errors
                results.append(self.create_result(
                    resource_id=f"ebs-encryption-{region}",
                    resource_type="EBS Encryption",
                    region=region,
                    status=CheckStatus.ERROR,
                    message=f"Error checking EBS encryption in {region}: {error_code}",
                    details={'error': str(e)}
                ))
                
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error checking EBS default encryption in {region}: {e}")
            results.append(self.create_result(
                resource_id=f"ebs-encryption-{region}",
                resource_type="EBS Encryption",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error checking EBS encryption in {region}: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
