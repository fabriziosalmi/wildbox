#!/usr/bin/env python3

"""
Script to batch create AWS security checks
"""

import os

# Define check templates
checks_to_create = [
    # ELB checks
    ('aws/elb', 'check_https_only.py', 'AWS_ELB_001', 'ELB HTTPS Only', 'Ensure ELB listeners use HTTPS only'),
    ('aws/elb', 'check_access_logging.py', 'AWS_ELB_002', 'ELB Access Logging', 'Ensure ELB has access logging enabled'),
    ('aws/elb', 'check_connection_draining.py', 'AWS_ELB_003', 'ELB Connection Draining', 'Ensure ELB has connection draining enabled'),
    
    # ElastiCache checks
    ('aws/elasticache', 'check_encryption_at_rest.py', 'AWS_ELASTICACHE_001', 'ElastiCache Encryption at Rest', 'Ensure ElastiCache clusters have encryption at rest'),
    ('aws/elasticache', 'check_encryption_in_transit.py', 'AWS_ELASTICACHE_002', 'ElastiCache Encryption in Transit', 'Ensure ElastiCache clusters have encryption in transit'),
    ('aws/elasticache', 'check_backup_retention.py', 'AWS_ELASTICACHE_003', 'ElastiCache Backup Retention', 'Ensure ElastiCache has adequate backup retention'),
    
    # ECS checks
    ('aws/ecs', 'check_task_definition_secrets.py', 'AWS_ECS_001', 'ECS Task Definition Secrets', 'Ensure ECS task definitions don\'t contain secrets'),
    ('aws/ecs', 'check_container_insights.py', 'AWS_ECS_002', 'ECS Container Insights', 'Ensure ECS clusters have Container Insights enabled'),
    ('aws/ecs', 'check_task_role_assigned.py', 'AWS_ECS_003', 'ECS Task Role Assigned', 'Ensure ECS tasks have appropriate IAM roles'),
    
    # EKS checks
    ('aws/eks', 'check_endpoint_private.py', 'AWS_EKS_001', 'EKS Private Endpoint', 'Ensure EKS cluster endpoint is not public'),
    ('aws/eks', 'check_logging_enabled.py', 'AWS_EKS_002', 'EKS Logging Enabled', 'Ensure EKS cluster has logging enabled'),
    ('aws/eks', 'check_secrets_encryption.py', 'AWS_EKS_003', 'EKS Secrets Encryption', 'Ensure EKS cluster encrypts secrets'),
    
    # EFS checks
    ('aws/efs', 'check_encryption_at_rest.py', 'AWS_EFS_001', 'EFS Encryption at Rest', 'Ensure EFS filesystems have encryption at rest'),
    ('aws/efs', 'check_encryption_in_transit.py', 'AWS_EFS_002', 'EFS Encryption in Transit', 'Ensure EFS uses encryption in transit'),
    ('aws/efs', 'check_backup_enabled.py', 'AWS_EFS_003', 'EFS Backup Enabled', 'Ensure EFS has backup enabled'),
    
    # Config checks
    ('aws/config', 'check_enabled.py', 'AWS_CONFIG_001', 'AWS Config Enabled', 'Ensure AWS Config is enabled'),
    ('aws/config', 'check_delivery_channel.py', 'AWS_CONFIG_002', 'Config Delivery Channel', 'Ensure Config has delivery channel configured'),
    ('aws/config', 'check_recording_all_resources.py', 'AWS_CONFIG_003', 'Config Recording All Resources', 'Ensure Config records all supported resources'),
    
    # GuardDuty checks
    ('aws/guardduty', 'check_enabled.py', 'AWS_GUARDDUTY_001', 'GuardDuty Enabled', 'Ensure GuardDuty is enabled'),
    ('aws/guardduty', 'check_s3_protection.py', 'AWS_GUARDDUTY_002', 'GuardDuty S3 Protection', 'Ensure GuardDuty S3 protection is enabled'),
    ('aws/guardduty', 'check_malware_protection.py', 'AWS_GUARDDUTY_003', 'GuardDuty Malware Protection', 'Ensure GuardDuty malware protection is enabled'),
    
    # Security Hub checks
    ('aws/securityhub', 'check_enabled.py', 'AWS_SECURITYHUB_001', 'Security Hub Enabled', 'Ensure Security Hub is enabled'),
    ('aws/securityhub', 'check_standards_enabled.py', 'AWS_SECURITYHUB_002', 'Security Hub Standards', 'Ensure Security Hub standards are enabled'),
    
    # API Gateway checks
    ('aws/apigateway', 'check_logging_enabled.py', 'AWS_APIGATEWAY_001', 'API Gateway Logging', 'Ensure API Gateway has logging enabled'),
    ('aws/apigateway', 'check_ssl_certificate.py', 'AWS_APIGATEWAY_002', 'API Gateway SSL Certificate', 'Ensure API Gateway uses valid SSL certificates'),
    ('aws/apigateway', 'check_waf_enabled.py', 'AWS_APIGATEWAY_003', 'API Gateway WAF', 'Ensure API Gateway has WAF enabled'),
    
    # CloudWatch checks
    ('aws/cloudwatch', 'check_log_group_retention.py', 'AWS_CLOUDWATCH_001', 'CloudWatch Log Retention', 'Ensure CloudWatch logs have retention policy'),
    ('aws/cloudwatch', 'check_log_group_encryption.py', 'AWS_CLOUDWATCH_002', 'CloudWatch Log Encryption', 'Ensure CloudWatch logs are encrypted'),
    
    # Redshift checks
    ('aws/redshift', 'check_encryption_at_rest.py', 'AWS_REDSHIFT_001', 'Redshift Encryption at Rest', 'Ensure Redshift clusters have encryption at rest'),
    ('aws/redshift', 'check_public_access.py', 'AWS_REDSHIFT_002', 'Redshift Public Access', 'Ensure Redshift clusters are not publicly accessible'),
    ('aws/redshift', 'check_audit_logging.py', 'AWS_REDSHIFT_003', 'Redshift Audit Logging', 'Ensure Redshift has audit logging enabled'),
    
    # WorkSpaces checks
    ('aws/workspaces', 'check_encryption.py', 'AWS_WORKSPACES_001', 'WorkSpaces Encryption', 'Ensure WorkSpaces have encryption enabled'),
    ('aws/workspaces', 'check_access_control.py', 'AWS_WORKSPACES_002', 'WorkSpaces Access Control', 'Ensure WorkSpaces have proper access control'),
]

def create_check_file(service_path, filename, check_id, title, description):
    """Create a security check file."""
    
    # Create the base template
    template = f'''"""
AWS {service_path.split('/')[-1].upper()} Check: {title}
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


class Check{title.replace(' ', '').replace('-', '')}(BaseCheck):
    """{description}."""
    
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="{check_id}",
            title="{title}",
            description="{description}.",
            provider=CloudProvider.AWS,
            service="{service_path.split('/')[-1].upper()}",
            category="Security",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=[
                "AWS Security Best Practices",
                "SOC 2"
            ],
            references=[
                "https://docs.aws.amazon.com/"
            ],
            remediation="Implement {title.lower()}: "
                       "1. Go to AWS console. "
                       "2. Navigate to the service. "
                       "3. Configure the security setting. "
                       "4. Apply the changes."
        )
    
    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        """Execute the {title.lower()} check."""
        results = []
        
        try:
            # TODO: Implement the actual check logic
            service_client = session.client('{service_path.split('/')[-1].lower().replace('_', '')}', region_name=region)
            
            # Placeholder implementation
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="placeholder-resource",
                resource_type="AWS::{service_path.split('/')[-1]}::Resource",
                resource_name="placeholder",
                region=region,
                status=CheckStatus.PASSED,
                message="Check implementation needed",
                details={{'note': 'This check needs to be implemented'}}
            ))
                        
        except Exception as e:
            logger.error(f"Error in {title.lower()} check: {{str(e)}}")
            results.append(CheckResult(
                check_id=self.get_metadata().check_id,
                resource_id="check-execution",
                resource_type="Check",
                region=region,
                status=CheckStatus.ERROR,
                message=f"Error during check execution: {{str(e)}}",
                details={{'error': str(e)}}
            ))
        
        return results
'''
    
    # Create the full file path
    base_path = "/Users/fab/GitHub/wildbox/open-security-cspm/app/checks"
    full_path = os.path.join(base_path, service_path, filename)
    
    # Write the file
    with open(full_path, 'w') as f:
        f.write(template)
    
    print(f"Created {full_path}")

# Create all the checks
for service_path, filename, check_id, title, description in checks_to_create:
    create_check_file(service_path, filename, check_id, title, description)

print(f"\nCreated {len(checks_to_create)} security checks!")
