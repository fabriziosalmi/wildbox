"""
AWS SNS Check: Topic Encryption
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


class CheckSNSTopicEncryption(BaseCheck):
    """Check if SNS topics have encryption enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_SNS_001",
            title="SNS Topic Encryption Enabled",
            description="Ensure SNS topics have server-side encryption enabled to protect "
                       "message data at rest.",
            provider=CloudProvider.AWS,
            service="SNS",
            category="Encryption",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "AWS Security Best Practices",
                "SOC 2",
                "HIPAA"
            ],
            references=[
                "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html"
            ],
            remediation="Enable SNS topic encryption: "
                       "1. Go to SNS console. "
                       "2. Select the topic. "
                       "3. Edit the topic. "
                       "4. Enable server-side encryption. "
                       "5. Choose appropriate KMS key."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the SNS topic encryption check."""
        results = []
        
        try:
            sns_client = session.client('sns', region_name=region)
            paginator = sns_client.get_paginator('list_topics')
            
            for page in paginator.paginate():
                for topic in page['Topics']:
                    topic_arn = topic['TopicArn']
                    topic_name = topic_arn.split(':')[-1]
                    
                    try:
                        # Get topic attributes to check encryption
                        attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
                        kms_master_key_id = attributes['Attributes'].get('KmsMasterKeyId')
                        
                        if kms_master_key_id:
                            results.append(CheckResult(
                                check_id=self.get_metadata().check_id,
                                resource_id=f"sns-topic-{topic_name}",
                                resource_type="AWS::SNS::Topic",
                                resource_name=topic_name,
                                region=region,
                                status=CheckStatus.PASSED,
                                message=f"SNS topic '{topic_name}' has encryption enabled",
                                details={
                                    'topic_arn': topic_arn,
                                    'kms_master_key_id': kms_master_key_id
                                }
                            ))
                        else:
                            results.append(CheckResult(
                                check_id=self.get_metadata().check_id,
                                resource_id=f"sns-topic-{topic_name}",
                                resource_type="AWS::SNS::Topic",
                                resource_name=topic_name,
                                region=region,
                                status=CheckStatus.FAILED,
                                message=f"SNS topic '{topic_name}' does not have encryption enabled",
                                details={'topic_arn': topic_arn}
                            ))
                            
                    except ClientError as e:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"sns-topic-{topic_name}",
                            resource_type="AWS::SNS::Topic",
                            resource_name=topic_name,
                            region=region,
                            status=CheckStatus.ERROR,
                            message=f"Failed to check encryption for topic '{topic_name}'",
                            details={'error': str(e)}
                        ))
                        
        except Exception as e:
            logger.error(f"Error in SNS topic encryption check: {str(e)}")
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
