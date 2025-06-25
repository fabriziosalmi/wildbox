# 🛡️ Open Security CSPM - Cloud Security Posture Manager

A comprehensive, multi-cloud Security Posture Management service designed for the Wildbox Security Suite. This service provides automated security assessments, compliance monitoring, and detailed reporting across AWS, GCP, and Azure environments.

## 🚀 Features

### 🔍 **Multi-Cloud Coverage**
- **AWS**: S3, EC2, IAM, RDS, VPC, CloudTrail, KMS, Lambda
- **GCP**: Cloud Storage, IAM, Compute Engine, Identity & Access Management
- **Azure**: Storage Accounts, Virtual Machines, Identity Management

### 📊 **Comprehensive Security Checks**
- **120+ Security Controls** across all major cloud providers
- **Compliance Framework Support**: CIS Benchmarks, NIST CSF, SOC 2, PCI DSS, GDPR, HIPAA
- **Real-time Assessment** with detailed remediation guidance
- **Risk-based Prioritization** with severity scoring

### 🎯 **Executive Reporting**
- **Executive Dashboard** with high-level security metrics
- **Trending Analysis** to track security posture over time
- **Compliance Scoring** per framework with gap analysis
- **Remediation Roadmaps** with prioritized action items

### ⚡ **Advanced Operations**
- **Batch Scanning** across multiple accounts and providers
- **Asynchronous Processing** with Celery task queue
- **Multi-region Support** with concurrent execution
- **API-first Design** for seamless integration

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Wildbox Dashboard                        │
│               (React + TypeScript)                         │
└─────────────────────┬───────────────────────────────────────┘
                      │ REST API Calls
┌─────────────────────▼───────────────────────────────────────┐
│                 CSPM FastAPI                               │
│     Authentication │ Validation │ Orchestration            │
└─────────────────────┬───────────────────────────────────────┘
                      │ Task Queue
┌─────────────────────▼───────────────────────────────────────┐
│              Celery Workers                                 │
│         Async Scan Execution                               │
└─────────────────────┬───────────────────────────────────────┘
                      │ Security Checks
┌─────────────────────▼───────────────────────────────────────┐
│             Check Framework                                 │
│   AWS Checks │ GCP Checks │ Azure Checks                  │
└─────────────────────┬───────────────────────────────────────┘
                      │ Results Storage
┌─────────────────────▼───────────────────────────────────────┐
│               Redis Cache                                   │
│     Scan Results │ Metadata │ Status                       │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Quick Start

### Docker Deployment

```bash
# Clone the repository
git clone https://github.com/your-org/wildbox
cd wildbox/open-security-cspm

# Start the CSPM service
docker-compose up -d

# Verify deployment
curl http://localhost:8000/health
```

### Manual Deployment

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export REDIS_URL="redis://localhost:6379"
export CELERY_BROKER_URL="redis://localhost:6379/0"
export LOG_LEVEL="INFO"

# Start Redis
redis-server

# Start Celery worker
celery -A app.worker worker --loglevel=info

# Start FastAPI application
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 📚 API Documentation

### Authentication

All API endpoints require authentication. Include the bearer token in the Authorization header:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8000/api/v1/scans
```

### Core Endpoints

#### 1. Start a Security Scan

**POST** `/api/v1/scans`

```json
{
  "provider": "aws",
  "credentials": {
    "auth_method": "access_key",
    "access_key_id": "AKIA...",
    "secret_access_key": "...",
    "region": "us-east-1"
  },
  "account_id": "123456789012",
  "account_name": "Production Account",
  "regions": ["us-east-1", "us-west-2"],
  "check_ids": null,
  "metadata": {
    "environment": "production",
    "team": "security"
  }
}
```

**Response:**
```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "started",
  "provider": "aws",
  "account_id": "123456789012",
  "started_at": "2025-06-25T10:30:00Z",
  "estimated_duration_minutes": 15
}
```

#### 2. Get Scan Status

**GET** `/api/v1/scans/{scan_id}/status`

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "running",
  "progress": 45,
  "current_region": "us-west-2",
  "checks_completed": 23,
  "checks_total": 51,
  "estimated_completion": "2025-06-25T10:45:00Z"
}
```

#### 3. Get Detailed Report

**GET** `/api/v1/scans/{scan_id}/report`

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "provider": "aws",
  "account_id": "123456789012",
  "started_at": "2025-06-25T10:30:00Z",
  "completed_at": "2025-06-25T10:44:32Z",
  "status": "completed",
  "summary": {
    "total_checks": 51,
    "passed_checks": 38,
    "failed_checks": 11,
    "error_checks": 2,
    "compliance_score": 74.5,
    "critical_findings": 3,
    "high_findings": 8
  },
  "results": [
    {
      "check_id": "AWS_S3_001",
      "resource_id": "my-public-bucket",
      "resource_type": "S3Bucket",
      "region": "us-east-1",
      "status": "failed",
      "message": "S3 bucket is publicly accessible",
      "compliance_frameworks": ["CIS", "NIST", "SOC2"],
      "remediation": "Configure S3 bucket to block public access"
    }
  ]
}
```

### Advanced Endpoints

#### Executive Summary

**GET** `/api/v1/dashboard/executive-summary?provider=aws&days=30`

```json
{
  "summary_period_days": 30,
  "provider_filter": "aws",
  "security_posture": {
    "total_resources_scanned": 245,
    "security_score": 82.3,
    "critical_findings": 5,
    "high_findings": 12,
    "compliance_frameworks": {
      "CIS": {"compliance_percentage": 78.5},
      "NIST": {"compliance_percentage": 85.2}
    }
  },
  "trending_metrics": [
    {
      "date": "2025-06-24",
      "security_score": 80.1,
      "critical_findings": 7,
      "total_findings": 45
    }
  ]
}
```

#### Batch Scanning

**POST** `/api/v1/batch/scans`

```json
{
  "scans": [
    {
      "provider": "aws",
      "credentials": {...},
      "account_id": "111111111111",
      "regions": ["us-east-1"]
    },
    {
      "provider": "aws",
      "credentials": {...},
      "account_id": "222222222222",
      "regions": ["us-west-2"]
    }
  ],
  "parallel_execution_limit": 3
}
```

#### Remediation Roadmap

**GET** `/api/v1/scans/{scan_id}/remediation-roadmap`

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "total_remediation_items": 8,
  "roadmap": [
    {
      "remediation": "Enable S3 bucket public access block",
      "affected_resources": [
        {"resource_id": "bucket-1", "resource_type": "S3Bucket"},
        {"resource_id": "bucket-2", "resource_type": "S3Bucket"}
      ],
      "estimated_effort": "Low",
      "priority": "Critical",
      "compliance_impact": ["CIS", "NIST"],
      "priority_score": 95,
      "order": 1
    }
  ]
}
```

## 🔧 Configuration

### Environment Variables

```bash
# Application Settings
APP_NAME="Open Security CSPM"
APP_VERSION="1.0.0"
LOG_LEVEL="INFO"
DEBUG="false"

# API Settings
API_HOST="0.0.0.0"
API_PORT="8000"
API_WORKERS="4"

# Redis Configuration
REDIS_URL="redis://localhost:6379"
REDIS_PASSWORD=""
REDIS_DB="0"

# Celery Configuration
CELERY_BROKER_URL="redis://localhost:6379/0"
CELERY_RESULT_BACKEND="redis://localhost:6379/0"

# Security Settings
SECRET_KEY="your-secret-key-here"
CORS_ORIGINS="http://localhost:3000,https://dashboard.wildbox.security"

# Scan Configuration
MAX_CONCURRENT_SCANS="10"
SCAN_TIMEOUT_SECONDS="3600"
DEFAULT_SCAN_REGIONS_AWS="us-east-1,us-west-2"
DEFAULT_SCAN_REGIONS_GCP="us-central1,europe-west1"
DEFAULT_SCAN_REGIONS_AZURE="eastus,westus2"

# Integration Settings
WILDBOX_IDENTITY_URL="http://open-security-identity:8000"
WILDBOX_DASHBOARD_URL="http://open-security-dashboard:3000"
```

### Custom Check Configuration

Create custom security checks by extending the `BaseCheck` class:

```python
from app.checks.framework import BaseCheck, CheckMetadata, CheckSeverity

class MyCustomCheck(BaseCheck):
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="CUSTOM_001",
            title="My Custom Security Check",
            description="Custom check for specific requirements",
            provider=CloudProvider.AWS,
            service="CustomService",
            category="Custom",
            severity=CheckSeverity.HIGH,
            compliance_frameworks=["Internal"],
            remediation="Follow internal security guidelines"
        )
    
    async def execute(self, session, region=None):
        # Your custom check logic here
        return [
            self.create_result(
                resource_id="resource-123",
                resource_type="CustomResource",
                status=CheckStatus.PASSED,
                message="Resource meets custom requirements"
            )
        ]
```

## 🔗 Integration with Wildbox Ecosystem

### Dashboard Integration

The CSPM service integrates seamlessly with the Wildbox Dashboard:

```typescript
// Dashboard API calls
const scanResult = await fetch('/api/cspm/scans', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${token}` },
  body: JSON.stringify(scanConfig)
});

const executiveSummary = await fetch('/api/cspm/dashboard/executive-summary');
```

### Guardian Integration

Security Guardian uses CSPM results for risk correlation:

```python
# Guardian risk assessment
cspm_findings = await cspm_client.get_scan_results(scan_id)
for finding in csmp_findings:
    risk_score = calculate_risk(finding, threat_intel, asset_context)
    await create_alert_if_critical(risk_score, finding)
```

### Responder Integration

Automated response playbooks triggered by CSPM findings:

```yaml
# Playbook: S3 Public Bucket Response
trigger:
  cspm_finding:
    check_id: "AWS_S3_001"
    severity: "critical"

actions:
  - name: "Create Ticket"
    type: "jira"
    priority: "high"
  
  - name: "Notify Team"
    type: "slack"
    channel: "#security-alerts"
  
  - name: "Auto-Remediate"
    type: "aws_lambda"
    function: "block-s3-public-access"
```

## 📈 Performance & Scalability

### Metrics

- **Throughput**: 100+ concurrent scans
- **Latency**: < 2s API response time
- **Scan Duration**: 
  - AWS: 10-20 minutes (full account)
  - GCP: 8-15 minutes (full project)
  - Azure: 12-18 minutes (full subscription)

### Scaling Recommendations

```yaml
# Production deployment
services:
  cspm-api:
    replicas: 3
    resources:
      cpu: "1000m"
      memory: "2Gi"
  
  cspm-worker:
    replicas: 5
    resources:
      cpu: "2000m"
      memory: "4Gi"
  
  redis:
    resources:
      memory: "8Gi"
```

## 🔒 Security Considerations

### Credentials Management

- **Never store credentials in plain text**
- Use AWS IAM roles, GCP service accounts, Azure managed identities when possible
- Implement credential rotation policies
- Encrypt credentials at rest

### Network Security

```yaml
# Network policies
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cspm-network-policy
spec:
  podSelector:
    matchLabels:
      app: csmp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: wildbox-dashboard
```

## 🚀 Roadmap

### v1.1 (Q3 2025)
- [ ] Multi-account AWS Organizations support
- [ ] GCP Folder/Organization scanning
- [ ] Azure Management Groups support
- [ ] Custom compliance frameworks
- [ ] Advanced threat modeling integration

### v1.2 (Q4 2025)
- [ ] Machine learning for anomaly detection
- [ ] Infrastructure as Code scanning
- [ ] Container security integration
- [ ] Cost optimization recommendations
- [ ] Advanced compliance reporting

### v2.0 (Q1 2026)
- [ ] Multi-cloud resource dependency mapping
- [ ] Automated remediation engine
- [ ] Real-time continuous monitoring
- [ ] Advanced analytics and BI integration

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](../CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/your-org/wildbox
cd wildbox/open-security-cspm

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 app/
black app/

# Start development environment
docker-compose -f docker-compose.dev.yml up
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 📞 Support

- **Documentation**: [docs.wildbox.security](https://docs.wildbox.security)
- **Issues**: [GitHub Issues](https://github.com/your-org/wildbox/issues)
- **Community**: [Discord](https://discord.gg/wildbox-security)
- **Enterprise**: [support@wildbox.security](mailto:support@wildbox.security)

---

🛡️ **Secure by Design. Scalable by Nature. Open by Choice.**
