"""
AWS Lambda Check: Public Access
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


class CheckPublicAccess(BaseCheck):
    """Check if Lambda functions have public access through resource policies."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_LAMBDA_002",
            title="Lambda Functions Not Publicly Accessible",
            description="Verify that Lambda functions are not publicly accessible through resource policies. "
                       "Public access to Lambda functions can lead to unauthorized code execution and data exposure.",
            provider=CloudProvider.AWS,
            service="Lambda",
            category="Access Control",
            severity=CheckSeverity.CRITICAL,
            compliance_frameworks=[
                "AWS Security Best Practices",
                "CIS AWS Foundations",
                "NIST CSF",
                "SOC 2"
            ],
            references=[
                "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"
            ],
            remediation="Remove public access from Lambda function: "
                       "1. Go to Lambda console. "
                       "2. Select your function. "
                       "3. Go to Configuration > Permissions. "
                       "4. Review resource-based policy. "
                       "5. Remove statements that grant public access. "
                       "6. Save changes."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the Lambda public access check."""
        results = []
        
        try:
            lambda_client = session.client('lambda', region_name=region)
            
            # List all Lambda functions
            paginator = lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for function in page.get('Functions', []):
                    function_name = function.get('FunctionName', 'Unknown')
                    function_arn = function.get('FunctionArn', f"arn:aws:lambda:{region}::function:{function_name}")
                    
                    try:
                        # Get function policy
                        policy_response = lambda_client.get_policy(FunctionName=function_name)
                        policy_doc = json.loads(policy_response['Policy'])
                        
                        # Analyze policy for public access
                        public_access_issues = self._check_for_public_access(policy_doc)
                        
                        function_details = {
                            'function_name': function_name,
                            'has_resource_policy': True,
                            'runtime': function.get('Runtime'),
                            'last_modified': function.get('LastModified'),
                            'public_access_issues': public_access_issues
                        }
                        
                        if public_access_issues:
                            results.append(self.create_result(
                                resource_id=function_arn,
                                resource_type="LambdaFunction",
                                resource_name=function_name,
                                region=region,
                                status=CheckStatus.FAILED,
                                message=f"Lambda function '{function_name}' has public access: {', '.join(public_access_issues)}",
                                details=function_details,
                                remediation="Remove public access statements from the function's resource policy"
                            ))
                        else:
                            results.append(self.create_result(
                                resource_id=function_arn,
                                resource_type="LambdaFunction",
                                resource_name=function_name,
                                region=region,
                                status=CheckStatus.PASSED,
                                message=f"Lambda function '{function_name}' resource policy does not grant public access",
                                details=function_details
                            ))
                        
                    except ClientError as policy_error:
                        error_code = policy_error.response.get('Error', {}).get('Code', 'Unknown')
                        
                        if error_code == 'ResourceNotFoundException':
                            # No resource policy found - this is good
                            results.append(self.create_result(
                                resource_id=function_arn,
                                resource_type="LambdaFunction",
                                resource_name=function_name,
                                region=region,
                                status=CheckStatus.PASSED,
                                message=f"Lambda function '{function_name}' has no resource policy",
                                details={
                                    'function_name': function_name,
                                    'has_resource_policy': False,
                                    'runtime': function.get('Runtime'),
                                    'last_modified': function.get('LastModified')
                                }
                            ))
                        else:
                            results.append(self.create_result(
                                resource_id=function_arn,
                                resource_type="LambdaFunction",
                                resource_name=function_name,
                                region=region,
                                status=CheckStatus.ERROR,
                                message=f"Error getting policy for Lambda function '{function_name}': {error_code}",
                                details={'error': str(policy_error)}
                            ))
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="LambdaFunction",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error listing Lambda functions: {error_code}",
                details={'error': str(e)}
            ))
        except Exception as e:
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="LambdaFunction",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Unexpected error checking Lambda public access: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
    
    def _check_for_public_access(self, policy_doc: dict) -> List[str]:
        """Check a Lambda resource policy for public access statements."""
        issues = []
        
        statements = policy_doc.get('Statement', [])
        
        for statement in statements:
            effect = statement.get('Effect', '')
            principal = statement.get('Principal', {})
            
            if effect == 'Allow':
                # Check for wildcard principals
                if principal == '*':
                    issues.append("Policy allows access to all principals (*)")
                elif isinstance(principal, dict):
                    # Check for AWS wildcard
                    if principal.get('AWS') == '*':
                        issues.append("Policy allows access to all AWS principals")
                    
                    # Check for service principals that might be public
                    service = principal.get('Service')
                    if service:
                        # Some service principals can effectively grant public access
                        public_services = ['s3.amazonaws.com', 'sns.amazonaws.com']
                        if isinstance(service, str) and service in public_services:
                            if 'Condition' not in statement:
                                issues.append(f"Policy allows access from {service} without conditions")
                        elif isinstance(service, list):
                            for svc in service:
                                if svc in public_services and 'Condition' not in statement:
                                    issues.append(f"Policy allows access from {svc} without conditions")
        
        return issues
