# Open Security Guardian

**The Guardian: Proactive Vulnerability Management**

A comprehensive, Django-based vulnerability lifecycle management platform that moves beyond simple vulnerability scanning to provide risk-based prioritization, automated remediation tracking, and intelligent asset management.

## 🛡️ Overview

Open Security Guardian transforms vulnerability management from a reactive, checkbox exercise into a proactive, risk-driven discipline. By combining asset inventory, vulnerability data, threat intelligence, and business context, it ensures that security teams focus their limited resources on the vulnerabilities that pose the greatest actual risk to the organization.

Built with Django and Django REST Framework, the Guardian provides a modern, scalable, and extensible platform for enterprise vulnerability management.

## 🎯 Key Features

### 🔍 **Intelligent Asset Discovery & Management**
- **Dynamic Asset Inventory**: Automatically discovers and maintains an up-to-date inventory of all assets across your environment
- **Asset Classification**: Categorizes assets by criticality, business function, and risk exposure
- **Dependency Mapping**: Understands relationships between assets and applications
- **Cloud & On-Premise**: Unified view across hybrid infrastructure
- **RESTful API**: Complete API access for asset management and automation

### 📊 **Risk-Based Vulnerability Prioritization**
- **Contextual Risk Scoring**: Goes beyond CVSS scores to include asset criticality, threat intelligence, and exploitability
- **Threat Intelligence Integration**: Leverages open-security-data for real-time threat context
- **Business Impact Analysis**: Considers business criticality and regulatory requirements
- **Attack Surface Analysis**: Understands exposure and accessibility of vulnerable assets
- **Advanced Filtering**: Powerful filtering and search capabilities via API and UI

### 🔄 **Automated Remediation Lifecycle**
- **Workflow Engine**: Configurable remediation workflows with approval processes
- **Ticketing Integration**: Automatically creates and tracks remediation tickets in Jira, ServiceNow, etc.
- **SLA Management**: Enforces remediation SLAs based on risk score and asset criticality
- **Progress Tracking**: Real-time visibility into remediation progress and bottlenecks
- **Verification**: Automated verification of remediation completion
- **Email Notifications**: Automated notifications for status changes and overdue items

### 📈 **Compliance & Reporting**
- **Regulatory Compliance**: Built-in frameworks for NIST CSF, PCI DSS, SOX, HIPAA, GDPR, and custom requirements
- **Compliance Assessments**: Structured assessment workflows with evidence collection
- **Executive Dashboards**: Risk metrics and trends for leadership and board reporting
- **Custom Reports**: Flexible report generation with multiple output formats (PDF, HTML, CSV, JSON)
- **Audit Trails**: Complete audit trail of all vulnerability management activities
- **Trend Analysis**: Historical analysis of vulnerability posture and remediation effectiveness

### 🔗 **Deep Integration**
- **Scanner Agnostic**: Integrates with Nessus, Qualys, Rapid7, OpenVAS, and custom scanners
- **Wildbox Suite**: Deep integration with open-security-api, open-security-data, and open-security-sensor
- **RESTful APIs**: Complete REST API for all functionality
- **Webhook Support**: Real-time notifications via webhooks
- **SIEM/SOAR**: Feeds vulnerability context into security operations workflows
- **Authentication**: Multiple authentication methods (API keys, JWT, session auth)

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Asset Sources  │    │   Discovery      │    │ Asset Database  │
│                 │    │                  │    │                 │
│ • Network Scan  │───▶│ • Active Probing │───▶│ • Inventory     │
│ • Cloud APIs    │    │ • Agent Reports  │    │ • Classification│
│ • CMDB Import   │    │ • DNS Analysis   │    │ • Dependencies  │
│ • Agent Data    │    │ • Certificate    │    │ • Metadata      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│    Scanners     │    │  Vulnerability   │    │  Risk Engine    │
│                 │    │   Processing     │    │                 │
│ • Nessus        │───▶│ • Normalization  │───▶│ • CVSS + Context│
│ • Qualys        │    │ • Deduplication  │    │ • Threat Intel  │
│ • OpenVAS       │    │ • Correlation    │    │ • Asset Critical│
│ • Custom Tools  │    │ • Enrichment     │    │ • Exposure Calc │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Dashboards    │    │   Remediation    │    │  Risk Database  │
│                 │    │   Management     │    │                 │
│ • Executive     │◀───│ • Ticket Create  │◀───│ • Prioritized   │
│ • Operational   │    │ • SLA Tracking   │    │ • Contextualized│
│ • Compliance    │    │ • Progress Mon.  │    │ • Actionable    │
│ • Technical     │    │ • Verification   │    │ • Trackable     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Docker Deployment (Recommended)

```bash
# Clone the repository
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox/open-security-guardian

# Configure environment
cp .env.example .env
# Edit .env with your database and integration settings

# Start the platform
docker-compose up -d

# Initialize the database
docker-compose exec guardian python manage.py migrate
docker-compose exec guardian python manage.py create-admin

# Import initial data
docker-compose exec guardian python manage.py import-assets
docker-compose exec guardian python manage.py sync-scanners
```

### Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Initialize database
python manage.py migrate
python manage.py create-admin

# Start the application
python manage.py runserver 0.0.0.0:8003
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | - | ✅ |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` | ❌ |
| `SECRET_KEY` | Django secret key | auto-generated | ❌ |
| `DEBUG` | Enable debug mode | `false` | ❌ |
| `WILDBOX_API_URL` | Open Security API endpoint | - | ✅ |
| `WILDBOX_DATA_URL` | Open Security Data endpoint | - | ✅ |
| `SCANNER_NESSUS_URL` | Nessus scanner URL | - | ❌ |
| `SCANNER_QUALYS_URL` | Qualys scanner URL | - | ❌ |
| `JIRA_URL` | Jira integration URL | - | ❌ |
| `SERVICENOW_URL` | ServiceNow integration URL | - | ❌ |

### Scanner Configuration

```yaml
# config/scanners.yaml
scanners:
  nessus:
    enabled: true
    url: "https://nessus.example.com:8834"
    username: "admin"
    password: "${NESSUS_PASSWORD}"
    scan_frequency: "daily"
    
  qualys:
    enabled: true
    url: "https://qualysapi.qualys.com"
    username: "api_user"
    password: "${QUALYS_PASSWORD}"
    scan_frequency: "weekly"
    
  openvas:
    enabled: true
    url: "https://openvas.example.com:9392"
    username: "admin"
    password: "${OPENVAS_PASSWORD}"
    scan_frequency: "daily"
```

## 📊 Usage Examples

### Asset Management

```bash
# Discover assets
curl -X POST "http://localhost:8003/api/v1/assets/discover" \
  -H "Authorization: Bearer your-api-key" \
  -d '{"network_range": "10.0.0.0/24", "scan_type": "comprehensive"}'

# Get asset inventory
curl "http://localhost:8003/api/v1/assets?criticality=high&limit=100" \
  -H "Authorization: Bearer your-api-key"

# Update asset criticality
curl -X PATCH "http://localhost:8003/api/v1/assets/12345" \
  -H "Authorization: Bearer your-api-key" \
  -d '{"criticality": "critical", "business_function": "payment_processing"}'
```

### Vulnerability Management

```bash
# Get prioritized vulnerabilities
curl "http://localhost:8003/api/v1/vulnerabilities?priority=critical&status=open" \
  -H "Authorization: Bearer your-api-key"

# Create remediation ticket
curl -X POST "http://localhost:8003/api/v1/vulnerabilities/67890/remediate" \
  -H "Authorization: Bearer your-api-key" \
  -d '{"assignee": "security-team", "due_date": "2025-07-15"}'

# Bulk risk assessment
curl -X POST "http://localhost:8003/api/v1/vulnerabilities/assess" \
  -H "Authorization: Bearer your-api-key" \
  -d '{"vulnerability_ids": [1, 2, 3, 4, 5]}'
```

### Reporting

```bash
# Executive dashboard data
curl "http://localhost:8003/api/v1/reports/executive" \
  -H "Authorization: Bearer your-api-key"

# Compliance report
curl "http://localhost:8003/api/v1/reports/compliance?framework=PCI_DSS" \
  -H "Authorization: Bearer your-api-key"

# Remediation metrics
curl "http://localhost:8003/api/v1/reports/remediation?timeframe=30d" \
  -H "Authorization: Bearer your-api-key"
```

## 🔗 Integration

### With Wildbox Suite

```python
# Example: Using Guardian in a security workflow
from guardian.client import GuardianClient
from open_security_data.client import DataClient

# Initialize clients
guardian = GuardianClient("http://localhost:8003")
data_lake = DataClient("http://localhost:8002")

# Enrich vulnerability with threat intelligence
vuln = guardian.get_vulnerability("CVE-2023-12345")
threat_intel = data_lake.get_threat_intel(vuln.cve_id)

# Update risk score based on threat intelligence
guardian.update_risk_score(vuln.id, 
    threat_intel.exploitability_score,
    threat_intel.active_campaigns)
```

### With External Systems

```python
# JIRA Integration
from guardian.integrations.jira import JiraIntegration

jira = JiraIntegration(
    url="https://company.atlassian.net",
    username="security@company.com",
    password="api-token"
)

# Automatically create tickets for critical vulnerabilities
critical_vulns = guardian.get_vulnerabilities(priority="critical")
for vuln in critical_vulns:
    jira.create_remediation_ticket(vuln)
```

## 🛠️ Development

### Project Structure

```
open-security-guardian/
├── guardian/                    # Main application
│   ├── __init__.py
│   ├── settings.py             # Django settings
│   ├── urls.py                 # URL routing
│   ├── wsgi.py                 # WSGI application
│   └── asgi.py                 # ASGI application
├── apps/                       # Django applications
│   ├── assets/                 # Asset management
│   ├── vulnerabilities/        # Vulnerability tracking
│   ├── scanners/              # Scanner integrations
│   ├── remediation/           # Remediation workflows
│   ├── compliance/            # Compliance frameworks
│   ├── integrations/          # External integrations
│   └── reporting/             # Reports and analytics
├── config/                     # Configuration files
│   ├── scanners.yaml          # Scanner configurations
│   ├── compliance.yaml        # Compliance frameworks
│   └── risk_weights.yaml      # Risk calculation weights
├── docker/                     # Docker configuration
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── nginx.conf
├── scripts/                    # Utility scripts
│   ├── import_assets.py
│   ├── sync_scanners.py
│   └── generate_reports.py
├── tests/                      # Test suite
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── requirements.txt            # Python dependencies
├── manage.py                   # Django management
└── README.md                   # This file
```

### Adding Custom Scanners

1. Create a scanner class in `apps/scanners/`:

```python
from apps.scanners.base import BaseScanner

class CustomScanner(BaseScanner):
    name = "custom_scanner"
    
    def scan(self, targets):
        # Implement your scanning logic
        pass
    
    def parse_results(self, raw_results):
        # Parse results into standard format
        pass
```

2. Register the scanner in `apps/scanners/registry.py`
3. Add configuration to `config/scanners.yaml`

### Custom Risk Scoring

```python
# apps/vulnerabilities/risk_calculator.py
from apps.vulnerabilities.base import BaseRiskCalculator

class CustomRiskCalculator(BaseRiskCalculator):
    def calculate_risk_score(self, vulnerability, asset, threat_intel):
        # Implement custom risk calculation logic
        base_score = vulnerability.cvss_score
        
        # Adjust for asset criticality
        if asset.criticality == 'critical':
            base_score *= 1.5
        
        # Adjust for threat intelligence
        if threat_intel.active_exploitation:
            base_score *= 1.3
            
        return min(base_score, 10.0)
```

## 📈 Monitoring & Observability

### Health Checks

```bash
# Application health
curl http://localhost:8003/health

# Database connectivity
curl http://localhost:8003/health/database

# Scanner connectivity
curl http://localhost:8003/health/scanners

# Integration health
curl http://localhost:8003/health/integrations
```

### Metrics

The Guardian exposes Prometheus metrics at `/metrics`:

- `guardian_assets_total` - Total number of managed assets
- `guardian_vulnerabilities_total` - Total vulnerabilities by severity
- `guardian_scan_duration_seconds` - Scanner execution time
- `guardian_remediation_time_seconds` - Time to remediation by priority
- `guardian_risk_score_distribution` - Distribution of risk scores

### Logging

Structured logging with configurable levels:

```python
# Example log entry
{
    "timestamp": "2025-06-25T10:30:00Z",
    "level": "INFO",
    "service": "guardian",
    "component": "vulnerability_processor",
    "message": "Processed vulnerability scan",
    "asset_id": "12345",
    "scanner": "nessus",
    "vulnerabilities_found": 23,
    "high_severity": 5,
    "critical_severity": 2
}
```

## 🔒 Security Considerations

### Data Protection
- Vulnerability data encryption at rest and in transit
- Secure API key management
- Role-based access control (RBAC)
- Audit logging for all operations

### Scanner Security
- Encrypted communication with all scanners
- Credential rotation for scanner accounts
- Network segmentation for scanner traffic
- Scan result integrity verification

### Integration Security
- OAuth 2.0 for external system authentication
- API rate limiting and throttling
- Input validation and sanitization
- SQL injection and XSS protection

## 📋 Compliance Frameworks

### Built-in Frameworks

- **PCI DSS**: Payment card industry requirements
- **SOX**: Sarbanes-Oxley compliance
- **HIPAA**: Healthcare data protection
- **ISO 27001**: Information security management
- **NIST Cybersecurity Framework**: Risk-based approach
- **Custom**: Define your own compliance requirements

### Compliance Reporting

```python
# Generate PCI DSS compliance report
report = guardian.generate_compliance_report(
    framework="PCI_DSS",
    scope="cardholder_data_environment",
    period="quarterly"
)

# Requirements tracking
requirements = guardian.get_compliance_requirements("PCI_DSS")
for req in requirements:
    print(f"{req.id}: {req.status} - {req.remediation_progress}%")
```

## 🚀 Deployment

### Production Deployment

```bash
# Production environment setup
docker-compose -f docker-compose.prod.yml up -d

# SSL/TLS configuration
./scripts/setup-ssl.sh

# Database backup configuration
./scripts/setup-backups.sh

# Monitoring setup
./scripts/setup-monitoring.sh
```

### High Availability

```yaml
# docker-compose.ha.yml
version: '3.8'
services:
  guardian:
    deploy:
      replicas: 3
      placement:
        constraints:
          - node.role == worker
  
  database:
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
```

### Backup Strategy

```bash
# Database backup
pg_dump guardian_production > guardian_backup_$(date +%Y%m%d).sql

# Configuration backup
tar -czf config_backup_$(date +%Y%m%d).tar.gz config/

# Automated backup scheduling
0 2 * * * /opt/guardian/scripts/backup.sh
```

## 🤝 Contributing

## 🚀 Current Implementation Status

The Open Security Guardian is now fully scaffolded with all core components implemented:

### ✅ Completed Components

#### **Core Infrastructure**
- ✅ Django 5.0 application with PostgreSQL backend
- ✅ Redis integration for caching and Celery
- ✅ Docker containerization with docker-compose
- ✅ Comprehensive environment configuration
- ✅ Production-ready logging and monitoring

#### **Applications & Models**
- ✅ **Assets Management**: Complete asset inventory with discovery and classification
- ✅ **Vulnerability Management**: Full vulnerability lifecycle with risk scoring
- ✅ **Scanner Integration**: Configurable scanner support (Nessus, OpenVAS, Qualys, etc.)
- ✅ **Remediation Workflows**: Ticketing system with SLA tracking
- ✅ **Compliance Management**: Full compliance framework with assessments and evidence
- ✅ **Reporting & Analytics**: Report generation, dashboards, and metrics
- ✅ **External Integrations**: SIEM, ticketing, and notification systems

#### **REST API**
- ✅ Complete REST API with Django REST Framework
- ✅ API authentication (API keys, JWT, session auth)
- ✅ Advanced filtering, searching, and pagination
- ✅ Comprehensive serializers and viewsets
- ✅ OpenAPI/Swagger documentation
- ✅ Rate limiting and throttling

#### **Background Processing**
- ✅ Celery task queue for async processing
- ✅ Scheduled tasks for maintenance and monitoring
- ✅ Email notifications and alerts
- ✅ Data import/export capabilities

#### **Management Commands**
- ✅ Initial setup and demo data loading
- ✅ Vulnerability data import from multiple sources
- ✅ Compliance report generation
- ✅ System maintenance and cleanup

#### **Developer Experience**
- ✅ Comprehensive documentation (README, API docs, Getting Started)
- ✅ Development setup script
- ✅ Docker development environment
- ✅ Example configurations and sample data

### 🔧 Ready for Development

The platform is now ready for:
- **Custom scanner integrations**
- **Frontend development** (React, Vue, or Angular)
- **Advanced reporting features**
- **Machine learning integration**
- **Custom compliance frameworks**
- **Additional third-party integrations**

### 📚 Quick Start

```bash
# Automated development setup
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox/open-security-guardian
./setup_dev.sh --start-server

# Or manual setup
cp .env.example .env
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py setup_guardian --demo-data
python manage.py runserver
```

Access the application:
- **Main Application**: http://localhost:8000/
- **Admin Interface**: http://localhost:8000/admin/ (admin/admin123)
- **API Documentation**: http://localhost:8000/docs/
- **API Endpoints**: http://localhost:8000/api/v1/

## 🤝 Contributing

We welcome contributions to Open Security Guardian! Here's how you can help:

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox/open-security-guardian

# Run automated setup
./setup_dev.sh

# Or manual setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py setup_guardian

# Install development tools
pip install black flake8 pytest pytest-django pytest-cov pre-commit
pre-commit install

# Run tests
python manage.py test
```

### Contribution Areas

- **Scanner Integrations**: Add support for new vulnerability scanners
- **Compliance Frameworks**: Implement new compliance requirements
- **Risk Algorithms**: Improve risk calculation and prioritization
- **Frontend Development**: Build modern web interface
- **Dashboard Features**: Enhance reporting and visualization
- **API Enhancements**: Extend REST API capabilities
- **Documentation**: Improve documentation and examples
- **Testing**: Add comprehensive test coverage

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: 
  - [Getting Started Guide](GETTING_STARTED.md)
  - [API Documentation](API_DOCS.md)
  - [Development Setup](setup_dev.sh)
- **Issues**: Report bugs and feature requests on GitHub
- **Security**: Report security issues responsibly

## 🏆 Acknowledgments

- Built on the solid foundation of the Wildbox Security Suite
- Inspired by the need for better vulnerability management
- Thanks to the open-source security community

---

**Transform your vulnerability management from reactive to proactive with Open Security Guardian.**

*Part of the Wildbox Security Suite - The future of open-source cybersecurity.*
