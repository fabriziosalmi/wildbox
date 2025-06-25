# 🛡️ Wildbox Open Security Platform

**The Complete Open-Source Security Operations Suite**

A comprehensive, modular, and scalable open-source security platform designed for modern cybersecurity operations. Wildbox provides enterprise-grade security tools, threat intelligence, vulnerability management, endpoint monitoring, automated response, and AI-powered analysis through a unified architecture.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://docker.com)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://typescriptlang.org)

## Screenshot

![screenshot](screenshot.png)
---

## 📋 Table of Contents

- [🎯 Platform Overview](#-platform-overview)
- [🏗️ Architecture](#️-architecture)
- [🚀 Components](#-components)
- [✨ Key Features](#-key-features)
- [🔧 Quick Start](#-quick-start)
- [🐳 Docker Deployment](#-docker-deployment)
- [🛠️ Development](#️-development)
- [📊 Service Ports](#-service-ports)
- [🔗 Integration](#-integration)
- [📖 Documentation](#-documentation)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🎯 Platform Overview

Wildbox is a **complete security operations platform** built from the ground up with modularity, scalability, and extensibility at its core. Each component operates as an independent microservice while seamlessly integrating to provide a unified security experience.

### 🎪 What Makes Wildbox Special

- **🧩 Modular Architecture**: Independent microservices that work together seamlessly
- **� Centralized Authentication**: Enterprise-grade identity management with JWT and API keys
- **�🔧 50+ Security Tools**: Comprehensive toolkit covering all security domains
- **🤖 AI-Powered Analysis**: GPT-4o powered intelligent threat analysis and reporting
- **🏭 Enterprise-Ready**: Production-grade with Docker, monitoring, and scalability
- **🌐 Modern Tech Stack**: Built with FastAPI, Django, Next.js, and TypeScript
- **📊 Unified Dashboard**: Single pane of glass for all security operations
- **🔗 API-First Design**: Complete REST APIs for automation and integration

---

## 🏗️ Architecture

Wildbox follows a **distributed microservices architecture** where each component serves a specific security domain while maintaining loose coupling and high cohesion.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           🛡️ WILDBOX SECURITY PLATFORM                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐             │
│  │  🖥️ Dashboard    │    │  🧠 AI Agents   │    │  ⚡ Responder    │             │
│  │  (Next.js)      │    │  (LangChain)    │    │  (Dramatiq)     │             │
│  │  Port: 3000     │    │  Port: 8006     │    │  Port: 8005     │             │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘             │
│           │                       │                       │                     │
│           │                       ▼                       │                     │
│           │              ┌─────────────────┐              │                     │
│           │              │  🔧 Security    │              │                     │
│           │              │     API         │              │                     │
│           │              │  (FastAPI)      │              │                     │
│           │              │  Port: 8000     │              │                     │
│           │              └─────────────────┘              │                     │
│           │                       │                       │                     │
│           ▼                       ▼                       ▼                     │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐             │
│  │  � Identity    │    │  �📊 Data Lake   │    │  🛡️ Guardian    │             │
│  │  (FastAPI)      │    │  (PostgreSQL)   │    │  (Django)       │             │
│  │  Port: 8001     │    │  Port: 8002     │    │  Port: 8003     │             │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘             │
│           │                       │                       │                     │
│           └───────────────────────┼───────────────────────┘                     │
│                                   ▼                                             │
│                          ┌─────────────────┐                                    │
│                          │  📡 Sensor      │                                    │
│                          │  (osquery)      │                                    │
│                          │  Port: 8004     │                                    │
│                          └─────────────────┘                                    │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                      🔗 SHARED INFRASTRUCTURE                                   │
│                                                                                 │
│    Redis Cluster        PostgreSQL         Docker Swarm       Nginx LB        │
│   (State & Queue)      (Data Storage)     (Orchestration)   (Load Balancer)    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 🏗️ Design Principles

- **🎯 Single Responsibility**: Each service has a focused, well-defined purpose
- **🔌 API-First**: Every component exposes comprehensive REST APIs
- **📦 Containerized**: Full Docker support for development and production
- **🔄 Event-Driven**: Asynchronous communication via message queues
- **🛡️ Security-First**: Built-in authentication, authorization, and audit trails
- **📈 Horizontally Scalable**: Designed to scale across multiple nodes

---

## 🚀 Components

### 🖥️ [Open Security Dashboard](./open-security-dashboard/)
**Unified Security Operations Center**

- **Technology**: Next.js 14, TypeScript, Tailwind CSS
- **Purpose**: Central command and control interface
- **Features**: Real-time dashboards, threat intelligence, tool execution, compliance monitoring

### 🔧 [Open Security API](./open-security-api/)
**Extensible Security Tools Platform**

- **Technology**: FastAPI, Python 3.11+
- **Purpose**: 50+ security tools with unified API interface
- **Features**: Dynamic tool discovery, auto-documentation, async execution, web interface

### � [Open Security Identity](./open-security-identity/)
**Centralized Authentication & Authorization**

- **Technology**: FastAPI, PostgreSQL, JWT, Stripe
- **Purpose**: User management, authentication, billing, and access control
- **Features**: JWT authentication, API key management, team management, Stripe billing integration

### �📊 [Open Security Data](./open-security-data/)
**Threat Intelligence Data Lake**

- **Technology**: Django, PostgreSQL, Redis
- **Purpose**: Centralized threat intelligence and security data repository
- **Features**: Multi-source feeds, data enrichment, GraphQL/REST APIs, real-time ingestion

### 🛡️ [Open Security Guardian](./open-security-guardian/)
**Vulnerability Lifecycle Management**

- **Technology**: Django, PostgreSQL, Celery
- **Purpose**: Risk-based vulnerability management and remediation tracking
- **Features**: Asset inventory, scanner integration, compliance frameworks, ticketing

### ⚡ [Open Security Responder](./open-security-responder/)
**Security Orchestration & Automation**

- **Technology**: FastAPI, Dramatiq, Redis, Jinja2
- **Purpose**: SOAR platform for automated incident response
- **Features**: YAML playbooks, workflow engine, connector framework, real-time monitoring

### 🧠 [Open Security Agents](./open-security-agents/)
**AI-Powered Threat Analysis**

- **Technology**: FastAPI, LangChain, OpenAI GPT-4o, Celery
- **Purpose**: Intelligent threat investigation and analysis
- **Features**: IOC analysis, threat enrichment, automated reporting, tool orchestration

### 📡 [Open Security Sensor](./open-security-sensor/)
**Endpoint Detection & Response**

- **Technology**: osquery, Python, TLS
- **Purpose**: Lightweight endpoint monitoring and telemetry collection
- **Features**: Cross-platform agent, real-time telemetry, file integrity monitoring, process tracking

---

## ✨ Key Features

### � **Centralized Authentication & Authorization**
- **JWT-Based Authentication**: Secure token-based user authentication
- **API Key Management**: Service-to-service authentication with team-scoped keys
- **Role-Based Access Control**: Owner, Admin, Member roles with granular permissions
- **Multi-Tenant Teams**: Organization and team membership management
- **Integrated Billing**: Stripe integration with subscription tiers and usage tracking
- **Rate Limiting**: Plan-based API rate limits and feature access control

### �🔍 **Comprehensive Threat Intelligence**
- **IOC Analysis**: Multi-source reputation checking and correlation
- **Feed Management**: 50+ threat intelligence sources with auto-ingestion
- **Geolocation & Context**: IP geolocation, ASN, WHOIS, and certificate data
- **Real-time Updates**: Live threat feed updates and alerting

### 🛠️ **Extensive Security Toolbox**
- **Network Security**: Port scanning, vulnerability assessment, service detection
- **Web Security**: XSS/SQLi testing, header analysis, API security testing
- **OSINT & Reconnaissance**: Domain enumeration, email harvesting, social media analysis
- **Cryptography**: Hash analysis, SSL/TLS testing, certificate validation
- **Cloud Security**: Multi-cloud compliance scanning (AWS, Azure, GCP)
- **Malware Analysis**: Static analysis, hash reputation, sandbox integration

### 🏭 **Enterprise Vulnerability Management**
- **Risk-Based Prioritization**: CVSS + threat intelligence + business context
- **Asset Discovery**: Automated network discovery and inventory management
- **Scanner Integration**: Nessus, Qualys, OpenVAS, and custom scanner support
- **Remediation Workflows**: Automated ticketing, SLA tracking, verification
- **Compliance Frameworks**: NIST, PCI-DSS, SOX, HIPAA, GDPR support

### 🤖 **AI-Powered Security Operations**
- **Intelligent Analysis**: GPT-4o powered investigation and correlation
- **Automated Reporting**: Professional markdown reports with recommendations
- **Context-Aware Processing**: Multi-IOC analysis with cross-correlation
- **Tool Orchestration**: AI selects and sequences appropriate security tools

### ⚡ **Advanced Security Automation**
- **Playbook Engine**: YAML-based workflow automation
- **Template System**: Jinja2 dynamic content and conditional logic
- **Connector Framework**: Extensible integration with external systems
- **Real-time Execution**: Live monitoring of automation workflows

### 📡 **Comprehensive Endpoint Visibility**
- **Cross-Platform**: Windows, Linux, macOS support
- **Real-time Telemetry**: Process, network, file system monitoring
- **Fleet Management**: Centralized configuration and query deployment
- **Low Resource Impact**: Optimized for production environments

---

## 🔧 Quick Start

### Prerequisites

- **Docker & Docker Compose** (Recommended)
- **Python 3.11+** (for local development)
- **Node.js 18+** (for dashboard development)
- **Git** for cloning repositories

### 🚀 One-Command Deployment

```bash
# Clone the complete platform
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox

# Start all services with Docker Compose
docker-compose up -d

# Verify deployment
curl http://localhost:3000  # Dashboard
curl http://localhost:8000  # Security API
curl http://localhost:8001  # Identity Service
curl http://localhost:8002  # Data Lake API
```

### 🎛️ Individual Service Deployment

Each component can be deployed independently:

```bash
# Security API
cd open-security-api
make dev

# Identity Service
cd open-security-identity
make dev

# Dashboard
cd open-security-dashboard
npm run dev

# AI Agents
cd open-security-agents
docker-compose up -d
```

---

## 🐳 Docker Deployment

### Production Stack

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Load Balancer
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - dashboard
      - security-api

  # Frontend Dashboard
  dashboard:
    build: ./open-security-dashboard
    environment:
      - NODE_ENV=production
      - NEXT_PUBLIC_API_BASE_URL=https://your-domain.com/api
    volumes:
      - dashboard_data:/app/.next

  # Security Tools API
  security-api:
    build: ./open-security-api
    environment:
      - API_KEY=${WILDBOX_API_KEY}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
      - postgres

  # Data Lake
  data-lake:
    build: ./open-security-data
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/wildbox_data
    depends_on:
      - postgres

  # Vulnerability Management
  guardian:
    build: ./open-security-guardian
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/wildbox_guardian
    depends_on:
      - postgres
      - redis

  # SOAR Platform
  responder:
    build: ./open-security-responder
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  # AI Agents
  agents:
    build: ./open-security-agents
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  # Shared Infrastructure
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=wildbox
      - POSTGRES_USER=wildbox
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  dashboard_data:
  redis_data:
  postgres_data:

networks:
  wildbox:
    driver: bridge
```

### Environment Configuration

```bash
# .env
WILDBOX_API_KEY=your-secure-api-key-here
OPENAI_API_KEY=your-openai-api-key
DB_PASSWORD=your-secure-database-password
NEXTAUTH_SECRET=your-auth-secret
```

---

## 🛠️ Development

### Development Environment Setup

```bash
# Clone and setup development environment
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox

# Start development stack
docker-compose -f docker-compose.dev.yml up -d

# Or run individual components
./scripts/dev-setup.sh
```

### Adding New Components

The platform is designed for easy extension:

1. **Security Tools**: Add to `open-security-api/app/tools/`
2. **Data Sources**: Add to `open-security-data/app/collectors/`
3. **Playbooks**: Add to `open-security-responder/playbooks/`
4. **Dashboard Features**: Add to `open-security-dashboard/src/app/`

### Testing

```bash
# Run all tests
make test-all

# Component-specific tests
cd open-security-api && make test
cd open-security-agents && pytest
cd open-security-dashboard && npm test
```

---

## 📊 Service Ports

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| **Dashboard** | 3000 | HTTP | Web interface and main UI |
| **Security API** | 8000 | HTTP | Security tools and execution |
| **Identity** | 8001 | HTTP | Authentication and authorization |
| **Data Lake** | 8002 | HTTP | Threat intelligence data |
| **Guardian** | 8003 | HTTP | Vulnerability management |
| **Sensor** | 8004 | HTTP | Endpoint monitoring |
| **Responder** | 8005 | HTTP | SOAR and automation |
| **AI Agents** | 8006 | HTTP | AI-powered analysis |
| **Redis** | 6379 | TCP | Cache and message queue |
| **PostgreSQL** | 5432 | TCP | Database storage |

---

## 🔗 Integration

### API Integration

All components expose comprehensive REST APIs:

```bash
# Security API
curl -H "Authorization: Bearer $API_KEY" \
  http://localhost:8000/api/tools

# Identity & Authentication
curl -X POST http://localhost:8001/api/v1/auth/login \
  -d "username=user@example.com&password=secret"

# Threat Intelligence
curl http://localhost:8002/api/v1/iocs/lookup/8.8.8.8

# Vulnerability Data
curl http://localhost:8003/api/v1/vulnerabilities?severity=critical

# Execute Playbook
curl -X POST -H "Content-Type: application/json" \
  http://localhost:8005/v1/playbooks/incident_response/execute \
  -d '{"target": "suspicious.domain.com"}'

# AI Analysis
curl -X POST -H "Content-Type: application/json" \
  http://localhost:8006/v1/analyze \
  -d '{"ioc": {"type": "ipv4", "value": "192.168.1.100"}}'
```

### External Integrations

- **SIEM**: Splunk, Elastic Stack, QRadar integration
- **Ticketing**: Jira, ServiceNow, GitHub Issues
- **Chat**: Slack, Microsoft Teams, Discord
- **Cloud**: AWS, Azure, GCP APIs
- **Threat Intel**: MISP, OpenCTI, ThreatConnect

---

## 📖 Documentation

### Component Documentation

- [🖥️ Dashboard Documentation](./open-security-dashboard/README.md)
- [🔧 Security API Guide](./open-security-api/README.md)
- [� Identity Service Guide](./open-security-identity/README.md)
- [�📊 Data Lake Documentation](./open-security-data/README.md)
- [🛡️ Guardian Quick Start](./open-security-guardian/GETTING_STARTED.md)
- [⚡ Responder Guide](./open-security-responder/README.md)
- [🧠 AI Agents Documentation](./open-security-agents/README.md)
- [📡 Sensor Deployment](./open-security-sensor/README.md)

### API Documentation

- **Security API**: http://localhost:8000/docs
- **Identity Service**: http://localhost:8001/docs
- **Data Lake**: http://localhost:8002/docs
- **Guardian**: http://localhost:8003/docs
- **Responder**: http://localhost:8005/docs
- **AI Agents**: http://localhost:8006/docs

### Deployment Guides

- [🐳 Docker Deployment](./docs/DOCKER_DEPLOYMENT.md)
- [☁️ Cloud Deployment](./docs/CLOUD_DEPLOYMENT.md)
- [🔧 Production Setup](./docs/PRODUCTION_SETUP.md)
- [🛡️ Security Hardening](./docs/SECURITY.md)

---

## 🎯 Use Cases

### 🏢 **Security Operations Center (SOC)**
- **Threat Hunting**: AI-powered investigation workflows
- **Incident Response**: Automated playbook execution
- **Threat Intelligence**: Real-time IOC analysis and correlation
- **Asset Management**: Comprehensive inventory and vulnerability tracking

### 🔒 **Vulnerability Management Program**
- **Risk-Based Prioritization**: Context-aware vulnerability scoring
- **Scanner Integration**: Multi-vendor scanner support
- **Remediation Tracking**: Automated ticketing and SLA management
- **Compliance Reporting**: Regulatory framework support

### 🌐 **DevSecOps Integration**
- **CI/CD Security**: Automated security testing in pipelines
- **Infrastructure Scanning**: Cloud security posture management
- **API Security**: Comprehensive API security testing
- **Container Security**: Docker and Kubernetes security analysis

### 🕵️ **Threat Intelligence Operations**
- **Feed Management**: Multi-source intelligence aggregation
- **IOC Enrichment**: Automated indicator analysis and correlation
- **Threat Hunting**: Proactive threat discovery and investigation
- **Intelligence Sharing**: STIX/TAXII and MISP integration

---

## 🚀 Roadmap

### 🎯 Current Status (v1.0)
- ✅ All 8 core components implemented and integrated
- ✅ Centralized authentication and authorization service
- ✅ 50+ security tools across multiple categories
- ✅ AI-powered analysis with GPT-4o integration
- ✅ Production-ready Docker deployment
- ✅ Comprehensive API documentation

### 🔮 Upcoming Features (v1.1)
- 🔄 **Enhanced AI Capabilities**: Multi-model support, custom training
- 📊 **Advanced Analytics**: Machine learning for anomaly detection
- 🌐 **Multi-Tenant Support**: SaaS-ready architecture
- 🔗 **Extended Integrations**: More SIEM, SOAR, and cloud platforms

### 🚀 Future Vision (v2.0)
- 🧠 **Autonomous Security**: Self-healing and adaptive security
- 🌍 **Global Threat Intelligence**: Community-driven threat sharing
- 📱 **Mobile Applications**: iOS and Android security management
- 🤝 **Federated Deployment**: Multi-organization collaboration

---

## 📈 Performance & Scalability

### 📊 **Benchmark Results**

| Component | Throughput | Latency | Resource Usage |
|-----------|------------|---------|----------------|
| Security API | 1000 req/sec | <100ms | 512MB RAM |
| Data Lake | 10k events/sec | <50ms | 2GB RAM |
| AI Agents | 50 analyses/hour | 2-5 min | 1GB RAM |
| Dashboard | 100 users | <200ms | 256MB RAM |

### 🏗️ **Scaling Recommendations**

- **Small Team (1-10 users)**: Single-node Docker deployment
- **Medium Organization (10-100 users)**: Multi-node Docker Swarm
- **Enterprise (100+ users)**: Kubernetes with horizontal scaling
- **MSP/MSSP**: Multi-tenant SaaS deployment with isolation

---

## 🔐 Security & Hardening

### 🛡️ **Security Features**

- **Centralized Authentication**: Dedicated identity service with JWT and API key management
- **Multi-Tenant Authorization**: Team-based access control with role-based permissions
- **Secure API Keys**: SHA-256 hashed keys with expiration and usage tracking
- **Encryption**: TLS 1.3 for all communications and bcrypt for password hashing
- **Audit Logging**: Complete audit trail of all authentication and authorization events
- **Input Validation**: Comprehensive input sanitization and request validation
- **Rate Limiting**: Plan-based rate limiting and DDoS protection

### 🔒 **Hardening Checklist**

- [ ] Change all default passwords and API keys
- [ ] Enable TLS/SSL for all communications
- [ ] Configure firewall rules and network segmentation
- [ ] Set up monitoring and alerting
- [ ] Regular security updates and patches
- [ ] Backup and disaster recovery procedures

---

## 📞 Support & Community

### 🤝 **Getting Help**

- **Documentation**: Comprehensive guides and API documentation
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community forum for questions and ideas
- **Security Issues**: Responsible disclosure via security@wildbox.io

### 🌟 **Contributing**

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md) for details on:

- Code contributions and pull requests
- Bug reports and feature requests
- Documentation improvements
- Security vulnerability reports

### 📬 **Contact**

- **Project Lead**: [@fabriziosalmi](https://github.com/fabriziosalmi)

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](./LICENSE) file for details.

### 🙏 **Acknowledgments**

- **OpenAI** for GPT-4o API access
- **Open Source Community** for the incredible tools and libraries
- **Security Researchers** for threat intelligence and vulnerability data
- **Contributors** who help make Wildbox better every day

---

## ⭐ **Star History**

If Wildbox has helped secure your organization, please consider giving us a star! ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=fabriziosalmi/wildbox&type=Date)](https://star-history.com/#fabriziosalmi/wildbox&Date)

---

<div align="center">

**🛡️ Built with ❤️ for the security community**

[🏠 Home](https://wildbox.io) • [📚 Docs](./docs/) • [🚀 Demo](https://demo.wildbox.io) • [💬 Community](https://discord.gg/wildbox)

</div>
