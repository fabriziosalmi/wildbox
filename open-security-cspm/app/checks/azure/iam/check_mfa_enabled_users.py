"""
Azure IAM Check: Multi-Factor Authentication
"""

from typing import List, Any, Optional
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckMfaEnabledUsers(BaseCheck):
    """Check if Azure AD users have Multi-Factor Authentication enabled."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AZURE_IAM_002",
            title="Multi-Factor Authentication Enabled for Users",
            description="Verify that Azure Active Directory users have Multi-Factor Authentication (MFA) enabled. "
                       "MFA provides an additional layer of security for user accounts.",
            provider=CloudProvider.AZURE,
            service="Azure Active Directory",
            category="Access Control",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=[
                "CIS Microsoft Azure Foundations Benchmark v1.3.0 - 1.1",
                "Azure Security Best Practices",
                "NIST CSF",
                "SOC 2",
                "HIPAA"
            ],
            references=[
                "https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks"
            ],
            remediation="Enable MFA for Azure AD users: "
                       "1. Go to Azure Portal > Azure Active Directory. "
                       "2. Go to Security > MFA. "
                       "3. Select user accounts. "
                       "4. Enable MFA for selected users. "
                       "5. Configure MFA policies. "
                       "6. Test MFA functionality."
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the Azure AD MFA check."""
        results = []
        
        try:
            # This is a placeholder implementation
            # In a real implementation, you would use the Microsoft Graph API
            # from azure.graphrbac import GraphRbacManagementClient
            # from msgraph import GraphServiceClient
            
            # For demo purposes, we'll simulate some findings
            simulated_users = [
                {
                    'userPrincipalName': 'admin@company.onmicrosoft.com',
                    'displayName': 'Administrator',
                    'userType': 'Member',
                    'accountEnabled': True,
                    'mfaEnabled': True,
                    'mfaEnforced': True,
                    'lastSignIn': '2024-12-26T10:00:00Z',
                    'roles': ['Global Administrator']
                },
                {
                    'userPrincipalName': 'user1@company.onmicrosoft.com',
                    'displayName': 'Regular User',
                    'userType': 'Member',
                    'accountEnabled': True,
                    'mfaEnabled': False,
                    'mfaEnforced': False,
                    'lastSignIn': '2024-12-25T15:30:00Z',
                    'roles': ['User']
                },
                {
                    'userPrincipalName': 'service@company.onmicrosoft.com',
                    'displayName': 'Service Account',
                    'userType': 'Member',
                    'accountEnabled': True,
                    'mfaEnabled': False,
                    'mfaEnforced': False,
                    'lastSignIn': '2024-12-26T08:00:00Z',
                    'roles': ['Application Developer']
                },
                {
                    'userPrincipalName': 'guest@external.com',
                    'displayName': 'External Guest',
                    'userType': 'Guest',
                    'accountEnabled': True,
                    'mfaEnabled': True,
                    'mfaEnforced': False,
                    'lastSignIn': '2024-12-20T12:00:00Z',
                    'roles': ['Guest User']
                }
            ]
            
            for user in simulated_users:
                user_principal_name = user['userPrincipalName']
                display_name = user['displayName']
                user_type = user['userType']
                account_enabled = user['accountEnabled']
                mfa_enabled = user.get('mfaEnabled', False)
                mfa_enforced = user.get('mfaEnforced', False)
                roles = user.get('roles', [])
                
                user_resource_id = f"users/{user_principal_name}"
                
                # Skip disabled accounts
                if not account_enabled:
                    continue
                
                # Determine if user is privileged
                privileged_roles = ['Global Administrator', 'User Administrator', 'Privileged Role Administrator', 'Security Administrator']
                is_privileged = any(role in privileged_roles for role in roles)
                
                user_details = {
                    'user_principal_name': user_principal_name,
                    'display_name': display_name,
                    'user_type': user_type,
                    'account_enabled': account_enabled,
                    'mfa_enabled': mfa_enabled,
                    'mfa_enforced': mfa_enforced,
                    'is_privileged': is_privileged,
                    'roles': roles,
                    'last_sign_in': user.get('lastSignIn')
                }
                
                # Check MFA status
                if mfa_enabled and mfa_enforced:
                    results.append(self.create_result(
                        resource_id=user_resource_id,
                        resource_type="AzureADUser",
                        resource_name=display_name,
                        region="global",
                        status=CheckStatus.PASSED,
                        message=f"User '{display_name}' has MFA enabled and enforced",
                        details=user_details
                    ))
                elif mfa_enabled and not mfa_enforced:
                    results.append(self.create_result(
                        resource_id=user_resource_id,
                        resource_type="AzureADUser",
                        resource_name=display_name,
                        region="global",
                        status=CheckStatus.WARNING,
                        message=f"User '{display_name}' has MFA enabled but not enforced",
                        details=user_details,
                        remediation="Enforce MFA for this user account"
                    ))
                else:
                    # MFA not enabled
                    severity = CheckStatus.FAILED
                    if is_privileged:
                        severity = CheckStatus.FAILED  # Critical for privileged users
                    elif user_type == 'Guest':
                        severity = CheckStatus.WARNING  # Less critical for guests
                    
                    results.append(self.create_result(
                        resource_id=user_resource_id,
                        resource_type="AzureADUser",
                        resource_name=display_name,
                        region="global",
                        status=severity,
                        message=f"User '{display_name}' does not have MFA enabled" + 
                               (" (privileged user)" if is_privileged else ""),
                        details=user_details,
                        remediation="Enable and enforce MFA for this user account"
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking Azure AD MFA: {e}")
            results.append(self.create_result(
                resource_id="unknown",
                resource_type="AzureADUser",
                region="global",
                status=CheckStatus.ERROR,
                message=f"Error checking Azure AD MFA: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
