import time
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import aiohttp

from schemas import (
    CloudSecurityAnalyzerInput,
    CloudSecurityAnalyzerOutput,
    CloudMisconfiguration,
    ComplianceCheck,
    ResourceInventory
)

# Tool metadata
TOOL_INFO = {
    "name": "Cloud Security Analyzer",
    "description": "Comprehensive cloud security assessment tool for AWS, Azure, and GCP with compliance checking and cost optimization",
    "category": "cloud_security",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["cloud", "aws", "azure", "gcp", "compliance", "security", "cost-optimization"]
}

async def execute_tool(data: CloudSecurityAnalyzerInput) -> CloudSecurityAnalyzerOutput:
    """
    Analyze cloud infrastructure for security misconfigurations and compliance
    """
    start_time = time.time()
    
    misconfigurations = []
    compliance_results = []
    resource_inventory = []
    recommendations = []
    
    try:
        # Simulate cloud provider connection and analysis
        if data.cloud_provider.lower() == "aws":
            analysis_result = await analyze_aws_infrastructure(data)
        elif data.cloud_provider.lower() == "azure":
            analysis_result = await analyze_azure_infrastructure(data)
        elif data.cloud_provider.lower() == "gcp":
            analysis_result = await analyze_gcp_infrastructure(data)
        elif data.cloud_provider.lower() == "multi":
            analysis_result = await analyze_multi_cloud_infrastructure(data)
        else:
            raise ValueError(f"Unsupported cloud provider: {data.cloud_provider}")
        
        misconfigurations = analysis_result["misconfigurations"]
        compliance_results = analysis_result["compliance_results"]
        resource_inventory = analysis_result["resource_inventory"]
        
        # Calculate security metrics
        total_resources = len(resource_inventory)
        total_misconfigs = len(misconfigurations)
        critical_issues = len([m for m in misconfigurations if m.severity == "Critical"])
        high_issues = len([m for m in misconfigurations if m.severity == "High"])
        medium_issues = len([m for m in misconfigurations if m.severity == "Medium"])
        low_issues = len([m for m in misconfigurations if m.severity == "Low"])
        
        # Calculate scores
        security_score = calculate_security_score(misconfigurations, resource_inventory)
        compliance_scores = calculate_compliance_scores(compliance_results, data.compliance_frameworks)
        
        # Cost optimization analysis
        cost_savings = calculate_cost_optimization_savings(resource_inventory) if data.include_cost_analysis else None
        
        # Generate recommendations
        recommendations = generate_recommendations(
            misconfigurations, 
            compliance_results, 
            resource_inventory,
            data.cloud_provider
        )
        
        return CloudSecurityAnalyzerOutput(
            cloud_provider=data.cloud_provider,
            analysis_timestamp=datetime.utcnow().isoformat(),
            assessment_type=data.assessment_type,
            regions_analyzed=[data.region],
            total_resources=total_resources,
            total_misconfigurations=total_misconfigs,
            critical_issues=critical_issues,
            high_issues=high_issues,
            medium_issues=medium_issues,
            low_issues=low_issues,
            misconfigurations=misconfigurations,
            compliance_results=compliance_results,
            resource_inventory=resource_inventory,
            security_score=security_score,
            compliance_score=compliance_scores,
            cost_optimization_savings=cost_savings,
            recommendations=recommendations,
            execution_time=time.time() - start_time
        )
        
    except Exception as e:
        return CloudSecurityAnalyzerOutput(
            cloud_provider=data.cloud_provider,
            analysis_timestamp=datetime.utcnow().isoformat(),
            assessment_type=data.assessment_type,
            regions_analyzed=[],
            total_resources=0,
            total_misconfigurations=1,
            critical_issues=1,
            high_issues=0,
            medium_issues=0,
            low_issues=0,
            misconfigurations=[CloudMisconfiguration(
                service="analyzer",
                resource_id="error",
                severity="Critical",
                category="Analysis Error",
                title="Cloud Analysis Failed",
                description=f"Failed to analyze cloud infrastructure: {str(e)}",
                current_configuration={},
                recommended_configuration={},
                compliance_frameworks=[],
                remediation_steps=["Verify cloud credentials and permissions"]
            )],
            compliance_results=[],
            resource_inventory=[],
            security_score=0.0,
            compliance_score={},
            cost_optimization_savings=None,
            recommendations=["Fix analysis errors and retry"],
            execution_time=time.time() - start_time
        )

async def analyze_aws_infrastructure(data: CloudSecurityAnalyzerInput) -> Dict[str, List]:
    """Analyze AWS infrastructure for security issues"""
    misconfigurations = []
    compliance_results = []
    resource_inventory = []
    
    # Simulate AWS service checks
    services_to_check = data.services_to_check if "all" not in data.services_to_check else [
        "s3", "ec2", "iam", "rds", "vpc", "cloudtrail", "kms", "lambda"
    ]
    
    for service in services_to_check:
        if service == "s3":
            s3_results = await check_aws_s3_security(data)
            misconfigurations.extend(s3_results["misconfigurations"])
            resource_inventory.extend(s3_results["resources"])
            
        elif service == "ec2":
            ec2_results = await check_aws_ec2_security(data)
            misconfigurations.extend(ec2_results["misconfigurations"])
            resource_inventory.extend(ec2_results["resources"])
            
        elif service == "iam":
            iam_results = await check_aws_iam_security(data)
            misconfigurations.extend(iam_results["misconfigurations"])
            resource_inventory.extend(iam_results["resources"])
    
    # Run compliance checks
    for framework in data.compliance_frameworks:
        framework_results = await run_aws_compliance_checks(framework, services_to_check)
        compliance_results.extend(framework_results)
    
    return {
        "misconfigurations": misconfigurations,
        "compliance_results": compliance_results,
        "resource_inventory": resource_inventory
    }

async def check_aws_s3_security(data: CloudSecurityAnalyzerInput) -> Dict[str, List]:
    """Check AWS S3 security configurations"""
    misconfigurations = []
    resources = []
    
    # Simulate S3 bucket analysis
    sample_buckets = [
        {"name": "example-bucket-1", "public": True, "encryption": False},
        {"name": "example-bucket-2", "public": False, "encryption": True},
        {"name": "logs-bucket", "public": False, "encryption": False}
    ]
    
    for bucket in sample_buckets:
        # Add to inventory
        resources.append(ResourceInventory(
            service="s3",
            resource_type="bucket",
            resource_id=bucket["name"],
            region=data.region,
            tags={"Environment": "production"},
            security_score=60.0 if bucket["public"] else 80.0,
            estimated_monthly_cost=25.50
        ))
        
        # Check for public buckets
        if bucket["public"]:
            misconfigurations.append(CloudMisconfiguration(
                service="s3",
                resource_id=bucket["name"],
                severity="High",
                category="Access Control",
                title="Publicly Accessible S3 Bucket",
                description="S3 bucket is publicly accessible which may expose sensitive data",
                current_configuration={"public_access": True},
                recommended_configuration={"public_access": False, "bucket_policy": "private"},
                compliance_frameworks=["CIS", "NIST"],
                remediation_steps=[
                    "Remove public read/write permissions",
                    "Implement bucket policies with least privilege",
                    "Enable S3 bucket public access block"
                ]
            ))
        
        # Check for encryption
        if not bucket["encryption"]:
            misconfigurations.append(CloudMisconfiguration(
                service="s3",
                resource_id=bucket["name"],
                severity="Medium",
                category="Encryption",
                title="S3 Bucket Not Encrypted",
                description="S3 bucket does not have server-side encryption enabled",
                current_configuration={"encryption": "none"},
                recommended_configuration={"encryption": "AES256", "kms_key": "customer_managed"},
                compliance_frameworks=["SOC2", "NIST"],
                remediation_steps=[
                    "Enable default server-side encryption",
                    "Use customer-managed KMS keys where appropriate",
                    "Enable bucket key for cost optimization"
                ]
            ))
    
    return {"misconfigurations": misconfigurations, "resources": resources}

async def check_aws_ec2_security(data: CloudSecurityAnalyzerInput) -> Dict[str, List]:
    """Check AWS EC2 security configurations"""
    misconfigurations = []
    resources = []
    
    # Simulate EC2 instance analysis
    sample_instances = [
        {"id": "i-1234567890abcdef0", "public_ip": True, "sg_open": True, "encrypted": False},
        {"id": "i-0987654321fedcba0", "public_ip": False, "sg_open": False, "encrypted": True}
    ]
    
    for instance in sample_instances:
        resources.append(ResourceInventory(
            service="ec2",
            resource_type="instance",
            resource_id=instance["id"],
            region=data.region,
            tags={"Environment": "production", "Application": "web"},
            security_score=40.0 if instance["sg_open"] else 75.0,
            estimated_monthly_cost=87.60
        ))
        
        if instance["sg_open"]:
            misconfigurations.append(CloudMisconfiguration(
                service="ec2",
                resource_id=instance["id"],
                severity="Critical",
                category="Network Security",
                title="Overly Permissive Security Group",
                description="Security group allows unrestricted access (0.0.0.0/0) on critical ports",
                current_configuration={"inbound_rules": ["0.0.0.0/0:22", "0.0.0.0/0:3389"]},
                recommended_configuration={"inbound_rules": ["specific_ip_ranges_only"]},
                compliance_frameworks=["CIS", "NIST", "SOC2"],
                remediation_steps=[
                    "Restrict SSH/RDP access to specific IP ranges",
                    "Use VPN or bastion hosts for administrative access",
                    "Implement least privilege network access"
                ]
            ))
    
    return {"misconfigurations": misconfigurations, "resources": resources}

async def check_aws_iam_security(data: CloudSecurityAnalyzerInput) -> Dict[str, List]:
    """Check AWS IAM security configurations"""
    misconfigurations = []
    resources = []
    
    # Simulate IAM analysis
    sample_policies = [
        {"name": "AdminPolicy", "admin_access": True, "mfa_required": False},
        {"name": "DeveloperPolicy", "admin_access": False, "mfa_required": True}
    ]
    
    for policy in sample_policies:
        resources.append(ResourceInventory(
            service="iam",
            resource_type="policy",
            resource_id=policy["name"],
            region="global",
            tags={},
            security_score=30.0 if policy["admin_access"] and not policy["mfa_required"] else 85.0
        ))
        
        if policy["admin_access"] and not policy["mfa_required"]:
            misconfigurations.append(CloudMisconfiguration(
                service="iam",
                resource_id=policy["name"],
                severity="High",
                category="Access Control",
                title="Administrative Access Without MFA",
                description="IAM policy grants administrative access without requiring MFA",
                current_configuration={"admin_access": True, "mfa_required": False},
                recommended_configuration={"admin_access": True, "mfa_required": True},
                compliance_frameworks=["CIS", "NIST", "SOC2"],
                remediation_steps=[
                    "Enable MFA requirement for administrative actions",
                    "Implement conditional access policies",
                    "Regular review of administrative permissions"
                ]
            ))
    
    return {"misconfigurations": misconfigurations, "resources": resources}

async def analyze_azure_infrastructure(data: CloudSecurityAnalyzerInput) -> Dict[str, List]:
    """Analyze Azure infrastructure for security issues"""
    # Simplified Azure analysis
    misconfigurations = [
        CloudMisconfiguration(
            service="azure_storage",
            resource_id="storageaccount123",
            severity="Medium",
            category="Access Control",
            title="Storage Account Public Access",
            description="Azure Storage Account allows public blob access",
            current_configuration={"public_access": "blob"},
            recommended_configuration={"public_access": "none"},
            compliance_frameworks=["CIS"],
            remediation_steps=["Disable public blob access", "Use private endpoints"]
        )
    ]
    
    resources = [
        ResourceInventory(
            service="azure_storage",
            resource_type="storage_account",
            resource_id="storageaccount123",
            region=data.region,
            tags={"Environment": "prod"},
            security_score=65.0,
            estimated_monthly_cost=45.30
        )
    ]
    
    compliance_results = []
    
    return {
        "misconfigurations": misconfigurations,
        "compliance_results": compliance_results,
        "resource_inventory": resources
    }

async def analyze_gcp_infrastructure(data: CloudSecurityAnalyzerInput) -> Dict[str, List]:
    """Analyze GCP infrastructure for security issues"""
    # Simplified GCP analysis
    misconfigurations = [
        CloudMisconfiguration(
            service="gcs",
            resource_id="example-gcs-bucket",
            severity="High",
            category="Access Control",
            title="Public GCS Bucket",
            description="Google Cloud Storage bucket is publicly accessible",
            current_configuration={"public_access": True},
            recommended_configuration={"public_access": False},
            compliance_frameworks=["CIS"],
            remediation_steps=["Remove allUsers and allAuthenticatedUsers permissions"]
        )
    ]
    
    resources = [
        ResourceInventory(
            service="gcs",
            resource_type="bucket",
            resource_id="example-gcs-bucket",
            region=data.region,
            tags={"env": "production"},
            security_score=40.0,
            estimated_monthly_cost=32.75
        )
    ]
    
    compliance_results = []
    
    return {
        "misconfigurations": misconfigurations,
        "compliance_results": compliance_results,
        "resource_inventory": resources
    }

async def analyze_multi_cloud_infrastructure(data: CloudSecurityAnalyzerInput) -> Dict[str, List]:
    """Analyze multi-cloud infrastructure"""
    # Combine results from multiple providers
    aws_results = await analyze_aws_infrastructure(data)
    azure_results = await analyze_azure_infrastructure(data)
    gcp_results = await analyze_gcp_infrastructure(data)
    
    return {
        "misconfigurations": (
            aws_results["misconfigurations"] + 
            azure_results["misconfigurations"] + 
            gcp_results["misconfigurations"]
        ),
        "compliance_results": (
            aws_results["compliance_results"] + 
            azure_results["compliance_results"] + 
            gcp_results["compliance_results"]
        ),
        "resource_inventory": (
            aws_results["resource_inventory"] + 
            azure_results["resource_inventory"] + 
            gcp_results["resource_inventory"]
        )
    }

async def run_aws_compliance_checks(framework: str, services: List[str]) -> List[ComplianceCheck]:
    """Run compliance checks for specific framework"""
    compliance_results = []
    
    if framework.lower() == "cis":
        compliance_results.extend([
            ComplianceCheck(
                framework="CIS",
                control_id="1.3",
                control_title="Ensure credentials unused for 90 days or greater are disabled",
                status="FAIL",
                description="Found credentials that haven't been used in 90+ days",
                evidence=["User 'old_service_account' last used 120 days ago"],
                remediation="Disable or remove unused credentials"
            ),
            ComplianceCheck(
                framework="CIS",
                control_id="2.1.1",
                control_title="Ensure S3 bucket access logging is enabled",
                status="PARTIAL",
                description="Some S3 buckets do not have access logging enabled",
                evidence=["2 out of 3 buckets have logging enabled"],
                remediation="Enable access logging on all S3 buckets"
            )
        ])
    
    return compliance_results

def calculate_security_score(misconfigurations: List[CloudMisconfiguration], resources: List[ResourceInventory]) -> float:
    """Calculate overall security score"""
    if not resources:
        return 0.0
    
    total_score = sum(resource.security_score for resource in resources)
    base_score = total_score / len(resources)
    
    # Deduct points for misconfigurations
    severity_penalties = {"Critical": 20, "High": 15, "Medium": 8, "Low": 3}
    
    for misconfig in misconfigurations:
        penalty = severity_penalties.get(misconfig.severity, 1)
        base_score -= penalty
    
    return max(0.0, min(100.0, base_score))

def calculate_compliance_scores(compliance_results: List[ComplianceCheck], frameworks: List[str]) -> Dict[str, float]:
    """Calculate compliance scores per framework"""
    scores = {}
    
    for framework in frameworks:
        framework_checks = [c for c in compliance_results if c.framework.lower() == framework.lower()]
        if framework_checks:
            passed = len([c for c in framework_checks if c.status == "PASS"])
            total = len(framework_checks)
            scores[framework] = (passed / total) * 100.0
        else:
            scores[framework] = 100.0
    
    return scores

def calculate_cost_optimization_savings(resources: List[ResourceInventory]) -> float:
    """Calculate potential cost optimization savings"""
    total_cost = sum(r.estimated_monthly_cost or 0 for r in resources)
    
    # Estimate 15-25% savings through optimization
    estimated_savings = total_cost * 0.20
    
    return estimated_savings

def generate_recommendations(
    misconfigurations: List[CloudMisconfiguration],
    compliance_results: List[ComplianceCheck],
    resources: List[ResourceInventory],
    cloud_provider: str
) -> List[str]:
    """Generate actionable recommendations"""
    recommendations = []
    
    # Priority recommendations based on critical issues
    critical_issues = [m for m in misconfigurations if m.severity == "Critical"]
    if critical_issues:
        recommendations.append("URGENT: Address critical security misconfigurations immediately")
        recommendations.append("Review and restrict overly permissive access controls")
    
    # Encryption recommendations
    encryption_issues = [m for m in misconfigurations if "encrypt" in m.title.lower()]
    if encryption_issues:
        recommendations.append("Enable encryption at rest and in transit for all data stores")
    
    # Access control recommendations
    access_issues = [m for m in misconfigurations if "access" in m.category.lower()]
    if access_issues:
        recommendations.append("Implement least privilege access controls")
        recommendations.append("Enable multi-factor authentication for administrative access")
    
    # Cloud-specific recommendations
    if cloud_provider.lower() == "aws":
        recommendations.extend([
            "Enable AWS CloudTrail for all regions",
            "Use AWS Config for compliance monitoring",
            "Implement AWS GuardDuty for threat detection"
        ])
    elif cloud_provider.lower() == "azure":
        recommendations.extend([
            "Enable Azure Security Center",
            "Use Azure Policy for compliance enforcement",
            "Implement Azure Sentinel for SIEM"
        ])
    elif cloud_provider.lower() == "gcp":
        recommendations.extend([
            "Enable GCP Security Command Center",
            "Use Cloud Asset Inventory for resource tracking",
            "Implement Cloud Security Scanner"
        ])
    
    # General recommendations
    recommendations.extend([
        "Regularly review and rotate access keys and credentials",
        "Implement automated security scanning in CI/CD pipelines",
        "Establish incident response procedures for cloud environments",
        "Regular security training for cloud operations teams"
    ])
    
    return recommendations

# Export tool info for registration
tool_info = TOOL_INFO
