"""
AWS IAM Check: Unused User Credentials
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Any, Optional
from datetime import datetime, timedelta
import logging

from ...framework import (
    BaseCheck, CheckResult, CheckMetadata, CheckSeverity, 
    CheckStatus, CloudProvider
)

logger = logging.getLogger(__name__)


class CheckUnusedUserCredentials(BaseCheck):
    """Check for IAM users with unused credentials (no activity in 90+ days)."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_IAM_005",
            title="IAM Users with Unused Credentials",
            description="Identify IAM users who haven't used their credentials in the last 90 days. "
                       "Unused credentials increase security risk and should be removed or disabled.",
            provider=CloudProvider.AWS,
            service="IAM",
            category="Access Management",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "CIS AWS Foundations Benchmark v1.4.0 - 1.3",
                "AWS Security Best Practices",
                "SOC 2",
                "NIST CSF"
            ],
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
            ],
            remediation="Remove or disable unused IAM user credentials: "
                       "1. Review user activity using credential reports. "
                       "2. Contact users to confirm if credentials are needed. "
                       "3. Delete unused users or disable access keys. "
                       "4. Implement regular credential auditing."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """
        Execute the unused user credentials check.
        
        Args:
            session: AWS session/client
            region: AWS region (IAM is global but region may be used for metadata)
            
        Returns:
            List of check results
        """
        results = []
        
        try:
            # Create IAM client
            iam_client = session.client('iam')
            
            # Generate credential report
            try:
                iam_client.generate_credential_report()
                # Wait a moment for report generation
                import time
                time.sleep(2)
            except ClientError as e:
                if 'ReportInProgress' not in str(e):
                    logger.warning(f"Could not generate credential report: {e}")
            
            # Get credential report
            try:
                report_response = iam_client.get_credential_report()
                report_content = report_response['Content'].decode('utf-8')
                
                # Parse CSV content
                import csv
                import io
                reader = csv.DictReader(io.StringIO(report_content))
                
                threshold_date = datetime.now() - timedelta(days=90)
                
                for row in reader:
                    username = row['user']
                    
                    # Skip root user
                    if username == '<root_account>':
                        continue
                    
                    # Check password last used
                    password_last_used = row.get('password_last_used', 'N/A')
                    access_key_1_last_used = row.get('access_key_1_last_used_date', 'N/A')
                    access_key_2_last_used = row.get('access_key_2_last_used_date', 'N/A')
                    
                    unused_credentials = []
                    
                    # Check password usage
                    if password_last_used and password_last_used != 'N/A' and password_last_used != 'no_information':
                        try:
                            last_used = datetime.strptime(password_last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                            if last_used < threshold_date:
                                unused_credentials.append('password')
                        except ValueError:
                            pass
                    elif row.get('password_enabled') == 'true' and (password_last_used == 'N/A' or password_last_used == 'no_information'):
                        unused_credentials.append('password')
                    
                    # Check access key 1 usage
                    if access_key_1_last_used and access_key_1_last_used != 'N/A':
                        try:
                            last_used = datetime.strptime(access_key_1_last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                            if last_used < threshold_date:
                                unused_credentials.append('access_key_1')
                        except ValueError:
                            pass
                    elif row.get('access_key_1_active') == 'true' and access_key_1_last_used == 'N/A':
                        unused_credentials.append('access_key_1')
                    
                    # Check access key 2 usage
                    if access_key_2_last_used and access_key_2_last_used != 'N/A':
                        try:
                            last_used = datetime.strptime(access_key_2_last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                            if last_used < threshold_date:
                                unused_credentials.append('access_key_2')
                        except ValueError:
                            pass
                    elif row.get('access_key_2_active') == 'true' and access_key_2_last_used == 'N/A':
                        unused_credentials.append('access_key_2')
                    
                    if unused_credentials:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"iam-user-{username}",
                            resource_type="AWS::IAM::User",
                            resource_name=username,
                            region="global",
                            status=CheckStatus.FAILED,
                            message=f"IAM user '{username}' has unused credentials: {', '.join(unused_credentials)}",
                            details={
                                'username': username,
                                'unused_credentials': unused_credentials,
                                'password_last_used': password_last_used,
                                'access_key_1_last_used': access_key_1_last_used,
                                'access_key_2_last_used': access_key_2_last_used,
                                'threshold_days': 90
                            }
                        ))
                    else:
                        results.append(CheckResult(
                            check_id=self.get_metadata().check_id,
                            resource_id=f"iam-user-{username}",
                            resource_type="AWS::IAM::User",
                            resource_name=username,
                            region="global",
                            status=CheckStatus.PASSED,
                            message=f"IAM user '{username}' has no unused credentials",
                            details={
                                'username': username,
                                'password_last_used': password_last_used,
                                'access_key_1_last_used': access_key_1_last_used,
                                'access_key_2_last_used': access_key_2_last_used
                            }
                        ))
                        
            except ClientError as e:
                if 'ReportNotPresent' in str(e):
                    results.append(CheckResult(
                        check_id=self.get_metadata().check_id,
                        resource_id="credential-report",
                        resource_type="AWS::IAM::CredentialReport",
                        region="global",
                        status=CheckStatus.ERROR,
                        message="Credential report not available. Generate report first.",
                        details={'error': str(e)}
                    ))
                else:
                    raise
                    
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="iam-service",
                resource_type="AWS::IAM::Service",
                region="global",
                status=CheckStatus.ERROR,
                message=f"Failed to check unused user credentials: {error_code}",
                details={'error': str(e)}
            ))
        except Exception as e:
            logger.error(f"Unexpected error in unused user credentials check: {str(e)}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region="global",
                status=CheckStatus.ERROR,
                message=f"Unexpected error during check execution: {str(e)}",
                details={'error': str(e)}
            ))
        
        return results
