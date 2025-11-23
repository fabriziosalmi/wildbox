"""
AWS IAM Check: Password Policy
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


class CheckPasswordPolicy(BaseCheck):
    """Check if IAM account password policy meets security requirements."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_IAM_001",
            title="IAM Password Policy Configured",
            description="Verify that IAM account password policy is configured with strong "
                       "password requirements including minimum length, character requirements, "
                       "and password rotation policies.",
            provider=CloudProvider.AWS,
            service="IAM",
            category="Identity & Access Management",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 1.5",
                "AWS Security Best Practices",
                "SOC 2",
                "PCI DSS",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
                "https://aws.amazon.com/blogs/security/how-to-create-a-password-policy-using-iam/"
            ],
            remediation="Configure strong IAM password policy: "
                       "1. Go to IAM console. "
                       "2. Navigate to 'Account settings'. "
                       "3. Set minimum password length to 14+ characters. "
                       "4. Require uppercase, lowercase, numbers, and symbols. "
                       "5. Enable password expiration (90 days recommended). "
                       "6. Prevent password reuse (24 passwords recommended)."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the IAM password policy check.
        
        Args:
            session: AWS session/client
            region: AWS region (IAM is global)
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create IAM client (IAM is global, region doesn't matter)
            iam_client = session.client('iam')
            
            # Get password policy
            try:
                response = iam_client.get_account_password_policy()
                policy = response['PasswordPolicy']
                
                # Check policy requirements
                issues = []
                recommendations = []
                
                # Minimum password length
                min_length = policy.get('MinimumPasswordLength', 0)
                if min_length < 14:
                    issues.append(f"Minimum password length is {min_length} (should be 14+)")
                    recommendations.append("Set minimum password length to 14 or more characters")
                
                # Character requirements
                if not policy.get('RequireUppercaseCharacters', False):
                    issues.append("Uppercase characters not required")
                    recommendations.append("Require uppercase characters")
                
                if not policy.get('RequireLowercaseCharacters', False):
                    issues.append("Lowercase characters not required")
                    recommendations.append("Require lowercase characters")
                
                if not policy.get('RequireNumbers', False):
                    issues.append("Numbers not required")
                    recommendations.append("Require numbers")
                
                if not policy.get('RequireSymbols', False):
                    issues.append("Symbols not required")
                    recommendations.append("Require symbols")
                
                # Password expiration
                max_age = policy.get('MaxPasswordAge')
                if not max_age:
                    issues.append("Password expiration not configured")
                    recommendations.append("Set password expiration (90 days recommended)")
                elif max_age > 90:
                    issues.append(f"Password expiration too long ({max_age} days)")
                    recommendations.append("Set password expiration to 90 days or less")
                
                # Password reuse prevention
                reuse_prevention = policy.get('PasswordReusePrevention')
                if not reuse_prevention:
                    issues.append("Password reuse prevention not configured")
                    recommendations.append("Prevent reuse of last 24 passwords")
                elif reuse_prevention < 24:
                    issues.append(f"Password reuse prevention too low ({reuse_prevention})")
                    recommendations.append("Prevent reuse of last 24 passwords")
                
                details = {
                    'policy_exists': True,
                    'minimum_password_length': min_length,
                    'require_uppercase': policy.get('RequireUppercaseCharacters', False),
                    'require_lowercase': policy.get('RequireLowercaseCharacters', False),
                    'require_numbers': policy.get('RequireNumbers', False),
                    'require_symbols': policy.get('RequireSymbols', False),
                    'max_password_age': max_age,
                    'password_reuse_prevention': reuse_prevention,
                    'allow_users_to_change_password': policy.get('AllowUsersToChangePassword', False),
                    'hard_expiry': policy.get('HardExpiry', False),
                    'issues_found': issues,
                    'recommendations': recommendations,
                    'check_timestamp': CheckResult.get_current_timestamp()
                }
                
                if not issues:
                    # Password policy meets requirements
                    results.append(self.create_result(
                        resource_id="iam-password-policy",
                        resource_type="IAM Password Policy",
                        resource_name="Account Password Policy",
                        region="global",
                        status=CheckStatus.PASSED,
                        message="IAM password policy meets security requirements",
                        details=details
                    ))
                else:
                    # Password policy has issues
                    results.append(self.create_result(
                        resource_id="iam-password-policy",
                        resource_type="IAM Password Policy",
                        resource_name="Account Password Policy",
                        region="global",
                        status=CheckStatus.FAILED,
                        message=f"IAM password policy has {len(issues)} security issues: {', '.join(issues[:3])}{'...' if len(issues) > 3 else ''}",
                        details=details,
                        remediation=f"Address password policy issues: {'; '.join(recommendations[:3])}"
                    ))
                
            except ClientError as policy_error:
                if policy_error.response['Error']['Code'] == 'NoSuchEntity':
                    # No password policy configured
                    details = {
                        'policy_exists': False,
                        'check_timestamp': CheckResult.get_current_timestamp()
                    }
                    
                    results.append(self.create_result(
                        resource_id="iam-password-policy",
                        resource_type="IAM Password Policy",
                        resource_name="Account Password Policy",
                        region="global",
                        status=CheckStatus.FAILED,
                        message="No IAM password policy configured",
                        details=details,
                        remediation="Configure a strong IAM password policy with minimum 14 characters and complexity requirements"
                    ))
                else:
                    raise policy_error
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                # Insufficient permissions
                results.append(self.create_result(
                    resource_id="iam-password-policy",
                    resource_type="IAM Password Policy",
                    region="global",
                    status=CheckStatus.SKIPPED,
                    message="Insufficient permissions to check IAM password policy",
                    details={'error': str(e)}
                ))
            else:
                # Other AWS API errors
                results.append(self.create_result(
                    resource_id="iam-password-policy",
                    resource_type="IAM Password Policy",
                    region="global",
                    status=CheckStatus.ERROR,
                    message=f"Error checking IAM password policy: {error_code}",
                    details={'error': str(e)}
                ))
                
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error checking IAM password policy: {e}")
            results.append(self.create_result(
                resource_id="iam-password-policy",
                resource_type="IAM Password Policy",
                region="global",
                status=CheckStatus.ERROR,
                message=f"Error checking IAM password policy: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
