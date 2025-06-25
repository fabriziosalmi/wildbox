# 🤖 Wildbox Open Security Automations

**The Automation Nerve Center of the Wildbox Security Platform**

A headless automation engine built on n8n that orchestrates all Wildbox microservices through intelligent workflows. This system handles everything from support ticket triage to threat intelligence analysis, creating a unified automation layer across the entire security platform.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://docker.com)
[![n8n](https://img.shields.io/badge/n8n-Automation-orange.svg)](https://n8n.io)

---

## 🎯 Project Overview

Open Security Automations is the **central orchestration engine** for the Wildbox platform. It connects all microservices through intelligent, visual workflows that automate complex security operations without requiring code changes to individual services.

### 🧠 Core Philosophy

- **Headless by Design**: No UI of its own - orchestrates other services
- **Visual Workflow Logic**: n8n's low-code approach for rapid development
- **Event-Driven Architecture**: Responds to triggers across the platform
- **Service Orchestration**: Maintains service separation while enabling cooperation
- **Intelligence Layer**: Adds smart decision-making between services

### 🎪 What This System Does

- **Support Automation**: Intelligent ticket triage and auto-responses
- **Threat Intelligence**: Daily OSINT reports and IoC enrichment
- **Content Generation**: Automated security reports and documentation
- **Incident Response**: Workflow-driven security playbooks
- **Data Orchestration**: Cross-service data synchronization
- **Monitoring Automation**: Alert correlation and escalation

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Wildbox Automations                      │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Support   │  │ Intelligence │  │   Content   │        │
│  │  Workflows  │  │  Workflows   │  │  Workflows  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 n8n Engine                         │   │
│  │  • Visual Workflow Designer                        │   │
│  │  • JavaScript Code Nodes                           │   │
│  │  • Webhook & Cron Triggers                         │   │
│  │  • HTTP Request Orchestration                      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Wildbox Microservices                       │
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │   API    │ │  Agents  │ │   Data   │ │ Identity │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Guardian │ │ Responder│ │  Sensor  │ │Dashboard │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Access to other Wildbox services

### 1. Start the Automation Engine

```bash
# Clone and navigate
cd wildbox/open-security-automations

# Start n8n with all dependencies
docker-compose up -d

# View logs
docker-compose logs -f n8n
```

### 2. Access n8n Interface

- **Local Development**: http://localhost:5678
- **Production**: Configure through your reverse proxy

### 3. Import Workflows

```bash
# The workflows are automatically available in n8n
# Import them through the n8n UI or use the CLI
```

---

## 📊 Workflow Inventory

| Workflow | Trigger | Purpose | Status |
|----------|---------|---------|--------|
| **Support Ticket Triage** | Email (IMAP) | Automatically categorize and route support emails | ✅ Ready |
| **Daily OSINT Report** | Cron (06:00 UTC) | Generate daily cybersecurity intelligence reports | ✅ Ready |
| **Honeypot Alert Classifier** | Webhook | Classify and enrich honeypot attack logs | ✅ Ready |
| **Vulnerability Sync** | Cron (12:00 UTC) | Sync CVE data across all services | 🔄 Planned |
| **Incident Response Orchestrator** | Webhook | Execute security playbooks automatically | 🔄 Planned |
| **Threat Feed Processor** | Cron (Every 4h) | Process and distribute threat intelligence | 🔄 Planned |

---

## 🔧 Configuration

### Environment Variables

```bash
# n8n Configuration
N8N_BASIC_AUTH_ACTIVE=true
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=your_secure_password

# Wildbox Integration
WILDBOX_API_GATEWAY_URL=http://wildbox-gateway:8000
WILDBOX_API_KEY=your_wildbox_api_key

# External Integrations
SUPPORT_EMAIL_HOST=imap.your-domain.com
SUPPORT_EMAIL_USER=support@wildbox.security
SUPPORT_EMAIL_PASSWORD=your_email_password

# Notification Services
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### Credentials Setup in n8n

1. **Wildbox API Credential**
   - Type: Header Auth
   - Name: `Authorization`
   - Value: `Bearer your_wildbox_api_key`

2. **Email Integration**
   - Type: IMAP
   - Host: Your email server
   - User: support@wildbox.security

3. **External Services**
   - Discord/Slack webhooks for notifications
   - GitHub tokens for issue creation
   - Third-party API keys as needed

---

## 📁 Project Structure

```
open-security-automations/
├── docker-compose.yml           # Main orchestration file
├── n8n-data/                   # Persistent n8n data
│   ├── custom/                 # Custom nodes (future)
│   └── .n8n/                  # n8n internal data
├── workflows/                  # Exported workflow definitions
│   ├── support/
│   │   ├── triage.json         # Support ticket classification
│   │   └── auto_response.json  # Automated responses
│   ├── intelligence/
│   │   ├── daily_report.json   # OSINT report generation
│   │   ├── honeypot_classifier.json # Attack classification
│   │   └── threat_enrichment.json  # IoC enrichment
│   ├── content/
│   │   ├── blog_generator.json # Automated content creation
│   │   └── documentation_sync.json # Doc synchronization
│   └── monitoring/
│       ├── health_checks.json  # Service health monitoring
│       └── alert_correlation.json # Cross-service alerting
├── scripts/
│   ├── export_workflows.sh     # Export all workflows to JSON
│   ├── import_workflows.sh     # Import workflows from JSON
│   └── backup_n8n.sh          # Backup n8n data
├── docs/
│   ├── workflow_design.md      # Workflow design patterns
│   ├── integration_guide.md    # Service integration guide
│   └── troubleshooting.md      # Common issues and solutions
└── README.md                   # This file
```

---

## 🔗 Service Integration

### Wildbox API Gateway
- **Endpoint**: `http://wildbox-gateway:8000`
- **Purpose**: Central API routing to all services
- **Auth**: Bearer token authentication

### Open Security Agents
- **Endpoint**: `http://open-security-agents:8001/v1/`
- **Purpose**: AI-powered analysis and classification
- **Use Cases**: Email triage, log analysis, content generation

### Open Security Data
- **Endpoint**: `http://open-security-data:8002/v1/`
- **Purpose**: Data lake operations and analytics
- **Use Cases**: Log enrichment, report data, metrics

### Other Services
- Integration patterns for all Wildbox microservices
- Webhook endpoints for event-driven workflows
- Health check monitoring for all components

---

## 🛠️ Development

### Adding New Workflows

1. **Design in n8n UI**
   ```bash
   # Access the n8n interface
   open http://localhost:5678
   ```

2. **Test Thoroughly**
   - Use test data
   - Verify all integrations
   - Check error handling

3. **Export and Version**
   ```bash
   # Export workflow from n8n UI
   # Save to appropriate workflows/ subdirectory
   # Commit to Git with descriptive message
   ```

### Workflow Development Guidelines

- **Modular Design**: Keep workflows focused on single purposes
- **Error Handling**: Always include error handling nodes
- **Logging**: Add logging nodes for debugging
- **Documentation**: Include clear node descriptions
- **Testing**: Test with realistic data volumes

### Custom Node Development

```bash
# If you need custom functionality
cd n8n-data/custom/
# Create custom node packages here
# Restart n8n to load new nodes
```

---

## 📈 Monitoring & Maintenance

### Health Monitoring

```bash
# Check n8n status
curl http://localhost:5678/healthz

# Monitor workflow executions
# Use n8n UI execution history

# Check Docker containers
docker-compose ps
```

### Backup & Recovery

```bash
# Backup n8n data
./scripts/backup_n8n.sh

# Export all workflows
./scripts/export_workflows.sh

# Restore from backup
docker-compose down
# Restore n8n-data/ from backup
docker-compose up -d
```

### Performance Optimization

- **Workflow Optimization**: Review execution times in n8n UI
- **Resource Limits**: Configure Docker resource constraints
- **Queue Management**: Monitor n8n job queues
- **Database Maintenance**: Regular SQLite maintenance

---

## 🔒 Security Considerations

### Access Control
- n8n basic authentication enabled
- Secure credential storage in n8n
- Network isolation via Docker networks

### API Security
- All external calls use secure authentication
- Credentials encrypted at rest
- Regular credential rotation

### Data Privacy
- No sensitive data in workflow definitions
- Secure handling of email content
- Audit logging for all operations

---

## 📖 Documentation

- **[Workflow Design Guide](docs/workflow_design.md)**: Best practices for creating workflows
- **[Integration Guide](docs/integration_guide.md)**: How to integrate with Wildbox services
- **[Troubleshooting](docs/troubleshooting.md)**: Common issues and solutions
- **[n8n Documentation](https://docs.n8n.io/)**: Official n8n documentation

---

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch
3. **Design** your workflow in n8n
4. **Test** thoroughly with real data
5. **Export** workflow to JSON
6. **Document** the workflow purpose and usage
7. **Submit** a pull request

### Workflow Contribution Guidelines

- Include clear descriptions for all nodes
- Add error handling for external API calls
- Test with various input scenarios
- Document trigger requirements
- Follow naming conventions

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues)
- **Documentation**: [Wildbox Docs](https://wildbox.security/docs)
- **Community**: [Discord Server](https://discord.gg/wildbox)
- **Email**: support@wildbox.security

---

**Built with ❤️ for the cybersecurity community**
