"""
AWS KMS Check: Key Usage and Permissions
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Any, Optional
import logging
import json

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckKeyPermissions(BaseCheck):
    """Check KMS key policies for overly permissive access."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_KMS_002",
            title="KMS Key Policies Follow Least Privilege",
            description="Verify that KMS key policies follow the principle of least privilege and "
                       "don't grant unnecessary permissions to principals.",
            provider=CloudProvider.AWS,
            service="KMS",
            category="Access Control",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "AWS Security Best Practices",
                "NIST CSF",
                "SOC 2",
                "CIS AWS Foundations"
            ],
            references=[
                "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
                "https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html"
            ],
            remediation="Review and restrict KMS key policies: "
                       "1. Go to KMS console. "
                       "2. Select your key. "
                       "3. Review key policy. "
                       "4. Remove overly broad permissions. "
                       "5. Apply principle of least privilege. "
                       "6. Save policy changes."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the KMS key permissions check."""
        results = []
        
        try:
            kms_client = session.client('kms', region_name=region)
            
            # List customer-managed keys
            paginator = kms_client.get_paginator('list_keys')
            
            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    key_id = key['KeyId']
                    
                    try:
                        # Get key metadata
                        key_metadata = kms_client.describe_key(KeyId=key_id)
                        key_details = key_metadata['KeyMetadata']
                        
                        # Skip AWS-managed keys
                        if key_details.get('KeyManager') == 'AWS':
                            continue
                        
                        key_arn = key_details.get('Arn', f"arn:aws:kms:{region}::key/{key_id}")
                        
                        # Get key policy
                        try:
                            policy_response = kms_client.get_key_policy(
                                KeyId=key_id,
                                PolicyName='default'
                            )
                            policy_doc = json.loads(policy_response['Policy'])
                            
                            # Analyze policy for security issues
                            issues = self._analyze_key_policy(policy_doc)
                            
                            key_info = {
                                'key_id': key_id,
                                'key_state': key_details.get('KeyState'),
                                'creation_date': str(key_details.get('CreationDate', '')),
                                'description': key_details.get('Description', ''),
                                'policy_issues': issues
                            }
                            
                            if issues:
                                results.append(self.create_result(
                                    resource_id=key_arn,
                                    resource_type="KMSKey",
                                    resource_name=key_id,
                                    region=region,
                                    status=CheckStatus.FAILED,
                                    message=f"KMS key '{key_id}' has policy security issues: {', '.join(issues)}",
                                    details=key_info,
                                    remediation="Review and restrict the key policy to follow least privilege"
                                ))
                            else:
                                results.append(self.create_result(
                                    resource_id=key_arn,
                                    resource_type="KMSKey",
                                    resource_name=key_id,
                                    region=region,
                                    status=CheckStatus.PASSED,
                                    message=f"KMS key '{key_id}' policy follows security best practices",
                                    details=key_info
                                ))
                                
                        except ClientError as policy_error:
                            error_code = policy_error.response.get('Error', {}).get('Code', 'Unknown')
                            results.append(self.create_result(
                                resource_id=key_arn,
                                resource_type="KMSKey",
                                resource_name=key_id,
                                region=region,
                                status=CheckStatus.ERROR,
                                message=f"Error getting policy for KMS key '{key_id}': {error_code}",
                                details={'error': str(policy_error)}
                            ))
                        
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                        if error_code != 'AccessDenied':
                            results.append(self.create_result(
                                resource_id=f"arn:aws:kms:{region}::key/{key_id}",
                                resource_type="KMSKey",
                                resource_name=key_id,
                                region=region,
                                status=CheckStatus.ERROR,
                                message=f"Error checking KMS key '{key_id}': {error_code}",
                                details={'error': str(e)}
                            ))
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="KMSKey",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error listing KMS keys: {error_code}",
                details={'error': str(e)}
            ))
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="KMSKey",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Unexpected error checking KMS key permissions: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
    
    def _analyze_key_policy(self, policy_doc: dict) -> List[str]:
        """Analyze a KMS key policy for security issues."""
        issues = []
        
        statements = policy_doc.get('Statement', [])
        
        for statement in statements:
            effect = statement.get('Effect', '')
            principal = statement.get('Principal', {})
            action = statement.get('Action', [])
            
            # Check for overly broad Allow statements
            if effect == 'Allow':
                # Check for wildcard principals
                if principal == '*' or principal == {'AWS': '*'}:
                    issues.append("Policy allows access to all principals (*)")
                
                # Check for broad actions
                if isinstance(action, str):
                    actions = [action]
                else:
                    actions = action if isinstance(action, list) else []
                
                for act in actions:
                    if act == '*':
                        issues.append("Policy allows all actions (*)")
                    elif act == 'kms:*':
                        issues.append("Policy allows all KMS actions (kms:*)")
                
                # Check for cross-account access without conditions
                if isinstance(principal, dict) and 'AWS' in principal:
                    aws_principals = principal['AWS']
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for aws_principal in aws_principals:
                        if ':root' in aws_principal and 'Condition' not in statement:
                            issues.append("Policy allows cross-account root access without conditions")
        
        return issues
