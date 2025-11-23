"""
AWS Lambda Check: Function Environment Variables Encryption
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckLambdaEnvironmentEncryption(BaseCheck):
    """Check if Lambda functions have environment variables encrypted."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_LAMBDA_001",
            title="Lambda Environment Variables Encrypted",
            description="Verify that AWS Lambda functions have environment variables encrypted "
                       "using customer-managed KMS keys. This protects sensitive configuration data.",
            provider=CloudProvider.AWS,
            service="Lambda",
            category="Compute Security",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "AWS Security Best Practices",
                "SOC 2",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html",
                "https://aws.amazon.com/lambda/"
            ],
            remediation="Encrypt Lambda environment variables: "
                       "1. Go to Lambda console. "
                       "2. Select the function. "
                       "3. Go to 'Configuration' tab. "
                       "4. Click 'Environment variables'. "
                       "5. Click 'Edit' and enable encryption in transit. "
                       "6. Select a customer-managed KMS key for encryption at rest."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the Lambda environment encryption check.
        
        Args:
            session: boto3 session
            region: AWS region to check
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create Lambda client
            lambda_client = session.client('lambda', region_name=region)
            
            # List all Lambda functions
            paginator = lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                functions = page.get('Functions', [])
                
                for function in functions:
                    function_name = function.get('FunctionName')
                    function_arn = function.get('FunctionArn')
                    
                    try:
                        # Get function configuration
                        config_response = lambda_client.get_function_configuration(
                            FunctionName=function_name
                        )
                        
                        # Check environment variables
                        environment = config_response.get('Environment', {})
                        variables = environment.get('Variables', {})
                        
                        # If no environment variables, this check is not applicable
                        if not variables:
                            results.append(self.create_result(
                                resource_id=function_name,
                                resource_type="LambdaFunction",
                                resource_name=function_name,
                                region=region,
                                status=CheckStatus.PASSED,
                                message=f"Lambda function {function_name} has no environment variables",
                                details={
                                    'function_name': function_name,
                                    'function_arn': function_arn,
                                    'runtime': config_response.get('Runtime'),
                                    'has_environment_variables': False,
                                    'environment_variables_count': 0,
                                    'kms_key_arn': None
                                }
                            ))
                            continue
                        
                        # Check KMS encryption
                        kms_key_arn = config_response.get('KMSKeyArn')
                        
                        function_details = {
                            'function_name': function_name,
                            'function_arn': function_arn,
                            'runtime': config_response.get('Runtime'),
                            'has_environment_variables': True,
                            'environment_variables_count': len(variables),
                            'kms_key_arn': kms_key_arn,
                            'last_modified': config_response.get('LastModified'),
                            'code_size': config_response.get('CodeSize'),
                            'timeout': config_response.get('Timeout'),
                            'memory_size': config_response.get('MemorySize')
                        }
                        
                        if kms_key_arn:
                            # Environment variables are encrypted with customer-managed key
                            results.append(self.create_result(
                                resource_id=function_name,
                                resource_type="LambdaFunction",
                                resource_name=function_name,
                                region=region,
                                status=CheckStatus.PASSED,
                                message=f"Lambda function {function_name} has encrypted environment variables",
                                details=function_details
                            ))
                        else:
                            # Environment variables are not encrypted or using default service key
                            results.append(self.create_result(
                                resource_id=function_name,
                                resource_type="LambdaFunction",
                                resource_name=function_name,
                                region=region,
                                status=CheckStatus.FAILED,
                                message=f"Lambda function {function_name} environment variables are not encrypted with customer-managed KMS key",
                                details=function_details,
                                remediation="Configure customer-managed KMS key encryption for environment variables"
                            ))
                            
                    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                        logger.error(f"Error checking Lambda function {function_name}: {e}")
                        results.append(self.create_result(
                            resource_id=function_name,
                            resource_type="LambdaFunction",
                            resource_name=function_name,
                            region=region,
                            status=CheckStatus.ERROR,
                            message=f"Error checking Lambda function {function_name}: {str(e)}",
                            details={'error': str(e)}
                        ))
                        
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error listing Lambda functions in region {region}: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="LambdaFunction",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error listing Lambda functions: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
