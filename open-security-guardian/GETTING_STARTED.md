# 🛡️ Open Security Guardian - Quick Start Guide

## Getting Started with Guardian

This guide will help you get the Open Security Guardian platform up and running quickly.

## Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)
- PostgreSQL 15+ (if running without Docker)
- Redis 7+ (if running without Docker)

## Quick Start with Docker

1. **Clone and navigate to the Guardian directory:**
   ```bash
   cd /Users/fab/GitHub/wildbox/open-security-guardian
   ```

2. **Start the platform with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

3. **Initialize the database and create admin user:**
   ```bash
   docker-compose exec guardian python manage.py setup_guardian --create-admin --sample-data
   ```

4. **Access the platform:**
   - Guardian Dashboard: http://localhost:8002
   - API Documentation: http://localhost:8002/docs/
   - Admin Interface: http://localhost:8002/admin/
   - Celery Monitoring: http://localhost:5555

## Manual Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Set up database:**
   ```bash
   python manage.py migrate
   ```

4. **Initialize Guardian:**
   ```bash
   python manage.py setup_guardian --create-admin --sample-data
   ```

5. **Start the development server:**
   ```bash
   python manage.py runserver 0.0.0.0:8002
   ```

## Key Features Implemented

### ✅ Asset Management (`/apps/assets/`)
- **Models**: Comprehensive asset inventory with criticality, environments, and metadata
- **API**: Full CRUD operations, filtering, and bulk actions
- **Features**: Auto-discovery integration, asset grouping, dependency mapping

### ✅ Vulnerability Management (`/apps/vulnerabilities/`)
- **Models**: Advanced vulnerability tracking with risk scoring and lifecycle management
- **API**: Complete vulnerability CRUD, assignment, bulk operations, and analytics
- **Features**: Risk-based prioritization, SLA tracking, history, and attachments

### ✅ Scanner Integration (`/apps/scanners/`)
- **Models**: Multi-scanner support (Nessus, Qualys, OpenVAS, custom)
- **API**: Scanner management, scan scheduling, and result processing
- **Features**: Health monitoring, scan profiles, automated result import

### ✅ Remediation Workflows (`/apps/remediation/`)
- **Models**: Complete workflow management with steps, tickets, and templates
- **API**: Workflow CRUD, progress tracking, and integration management
- **Features**: External ticketing (JIRA, ServiceNow), SLA monitoring, step automation

### ✅ External Integrations (`/apps/integrations/`)
- **Models**: Flexible integration framework for external systems
- **API**: System configuration, sync management, and webhook handling
- **Features**: Bidirectional sync, field mapping, notification channels

### ⚠️ To Be Implemented
- **Compliance App**: Regulatory framework support and reporting
- **Reporting App**: Analytics dashboards and executive reports
- **Frontend UI**: React-based dashboard (currently API-only)

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│     Assets      │    │  Vulnerabilities │    │    Scanners     │
│   Management    │───▶│   Management     │◀───│   Integration   │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         │                        ▼                        │
         │              ┌──────────────────┐               │
         │              │   Remediation    │               │
         └─────────────▶│   Workflows      │◀──────────────┘
                        │                  │
                        └──────────────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │   Integrations   │
                        │  (JIRA, SIEM,    │
                        │   Notifications) │
                        └──────────────────┘
```

## Core Models and Relationships

### Assets (`apps.assets.models`)
- **Asset**: Core asset model with networking, hardware, and software details
- **AssetGroup**: Logical grouping of assets
- **AssetDependency**: Asset interdependencies

### Vulnerabilities (`apps.vulnerabilities.models`)
- **Vulnerability**: Core vulnerability with risk scoring and lifecycle
- **VulnerabilityTemplate**: Reusable vulnerability definitions
- **VulnerabilityHistory**: Change tracking and audit trail
- **VulnerabilityAssessment**: Risk assessment details

### Scanners (`apps.scanners.models`)
- **Scanner**: Scanner configuration and health monitoring
- **ScanProfile**: Scan configuration templates
- **Scan**: Individual scan instances with progress tracking
- **ScanResult**: Individual vulnerability findings

### Remediation (`apps.remediation.models`)
- **RemediationWorkflow**: Main workflow with steps and progress
- **RemediationTicket**: External ticket integration
- **RemediationTemplate**: Workflow templates
- **RemediationStep**: Individual workflow steps

### Integrations (`apps.integrations.models`)
- **ExternalSystem**: External system configurations
- **IntegrationMapping**: Field and data mappings
- **SyncRecord**: Synchronization tracking
- **NotificationChannel**: Alert and notification management

## API Endpoints

All endpoints are available at `/api/v1/` with full OpenAPI documentation at `/docs/`.

### Key Endpoint Collections:
- **Assets**: `/api/v1/assets/` - Asset management and discovery
- **Vulnerabilities**: `/api/v1/vulnerabilities/` - Vulnerability lifecycle
- **Scanners**: `/api/v1/scanners/` - Scanner integration and management
- **Remediation**: `/api/v1/remediation/` - Workflow and ticket management
- **Integrations**: `/api/v1/integrations/` - External system integration

## Configuration

### Environment Variables (`.env`)
```bash
# Database
DATABASE_URL=postgresql://guardian:password@localhost:5432/guardian

# Cache
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key
DEBUG=false

# External Systems
WILDBOX_API_URL=http://localhost:8000
WILDBOX_DATA_URL=http://localhost:8001

# Scanner APIs (optional)
NESSUS_URL=https://nessus.company.com:8834
QUALYS_API_URL=https://qualysapi.qualys.com
```

### Integration with Other Wildbox Components

Guardian integrates seamlessly with other Wildbox components:

- **Open Security API**: Scanner tools and vulnerability testing
- **Open Security Data**: Threat intelligence and IoC feeds  
- **Open Security Sensor**: Host-based monitoring and data collection

## Development

### Adding New Apps
1. Create app: `python manage.py startapp newapp apps/`
2. Add to `INSTALLED_APPS` in `guardian/settings.py`
3. Create models, serializers, views, and URLs
4. Run migrations: `python manage.py makemigrations && python manage.py migrate`

### Key Design Patterns
- **Model Relationships**: Extensive use of foreign keys and many-to-many relationships
- **API Design**: DRF ViewSets with comprehensive filtering and pagination
- **Background Tasks**: Celery for async processing (notifications, sync, etc.)
- **Extensibility**: Plugin-like architecture for scanners and integrations

## Troubleshooting

### Common Issues
1. **Database Connection**: Ensure PostgreSQL is running and credentials are correct
2. **Redis Connection**: Verify Redis is accessible for caching and Celery
3. **Scanner Integration**: Check scanner URLs and authentication in environment
4. **Migrations**: Run `python manage.py migrate` after pulling updates

### Logs and Monitoring
- Application logs: Check Django logs and Celery worker logs
- Health checks: Visit `/health/` endpoint for system status
- Metrics: Prometheus metrics available at `/metrics/`

## Next Steps

1. **Configure Scanners**: Add your vulnerability scanners in the admin interface
2. **Import Assets**: Use the asset discovery features or import from CMDB
3. **Set Up Integrations**: Connect to JIRA, ServiceNow, or other systems
4. **Create Workflows**: Define remediation templates for your organization
5. **Monitor**: Set up dashboards and alerts for vulnerability management

## Support

For issues and questions:
- Review the API documentation at `/docs/`
- Check the Django admin interface for data management
- Monitor Celery tasks for background processing status
- Use the management commands for bulk operations

The Guardian platform provides a solid foundation for enterprise vulnerability management with extensive customization options and integration capabilities.
