"""
AWS SQS Check: Queue Encryption
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


class CheckSQSQueueEncryption(BaseCheck):
    """Check if SQS queues have encryption enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_SQS_001",
            title="SQS Queue Encryption Enabled",
            description="Ensure SQS queues have server-side encryption enabled to protect "
                       "message data at rest and in transit.",
            provider=CloudProvider.AWS,
            service="SQS",
            category="Encryption",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "AWS Security Best Practices",
                "SOC 2",
                "HIPAA"
            ],
            references=[
                "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html"
            ],
            remediation="Enable SQS queue encryption: "
                       "1. Go to SQS console. "
                       "2. Select the queue. "
                       "3. Edit the queue. "
                       "4. Enable server-side encryption. "
                       "5. Choose KMS key for encryption."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the SQS queue encryption check."""
        results = []
        
        try:
            sqs_client = session.client('sqs', region_name=region)
            paginator = sqs_client.get_paginator('list_queues')
            
            for page in paginator.paginate():
                queue_urls = page.get('QueueUrls', [])
                
                for queue_url in queue_urls:
                    queue_name = queue_url.split('/')[-1]
                    
                    try:
                        # Get queue attributes to check encryption
                        attributes = sqs_client.get_queue_attributes(
                            QueueUrl=queue_url,
                            AttributeNames=['KmsMasterKeyId', 'SqsManagedSseEnabled']
                        )
                        
                        kms_key_id = attributes['Attributes'].get('KmsMasterKeyId')
                        sse_enabled = attributes['Attributes'].get('SqsManagedSseEnabled')
                        
                        if kms_key_id or sse_enabled == 'true':
                            results.append(CheckResult(
                                check_id=self.get_metadata().check_id,
                                resource_id=f"sqs-queue-{queue_name}",
                                resource_type="AWS::SQS::Queue",
                                resource_name=queue_name,
                                region=region,
                                status=CheckStatus.PASSED,
                                message=f"SQS queue '{queue_name}' has encryption enabled",
                                details={
                                    'queue_url': queue_url,
                                    'kms_master_key_id': kms_key_id,
                                    'sqs_managed_sse_enabled': sse_enabled
                                }
                            ))
                        else:
                            results.append(CheckResult(
                                check_id=self.get_metadata().check_id,
                                resource_id=f"sqs-queue-{queue_name}",
                                resource_type="AWS::SQS::Queue",
                                resource_name=queue_name,
                                region=region,
                                status=CheckStatus.FAILED,
                                message=f"SQS queue '{queue_name}' does not have encryption enabled",
                                details={'queue_url': queue_url}
                            ))
                            
                    except ClientError as e:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"sqs-queue-{queue_name}",
                            resource_type="AWS::SQS::Queue",
                            resource_name=queue_name,
                            region=region,
                            status=CheckStatus.ERROR,
                            message=f"Failed to check encryption for queue '{queue_name}'",
                            details={'error': str(e)}
                        ))
                        
        except Exception as e:
            logger.error(f"Error in SQS queue encryption check: {str(e)}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error during check execution: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
