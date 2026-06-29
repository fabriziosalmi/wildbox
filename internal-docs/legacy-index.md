#  Wildbox Security Platform - Documentation

Welcome to the Wildbox Security Platform documentation. This site contains comprehensive guides and resources for deploying, securing, and using the platform.

> **Interactive Documentation Available**: [Open the Interactive Documentation Portal](docs.html) for a guided experience with integrated API reference and dynamic markdown rendering.

##  Getting Started

- **[Quickstart Guide](guides/quickstart.md)** - Deploy Wildbox in 5 minutes with Docker Compose
- **[Credentials Reference](guides/credentials.md)** - Default credentials and authentication setup
- **[Deployment Guide](guides/deployment.md)** - Detailed production deployment procedures

##  Security

The Wildbox Security Platform has completed comprehensive security hardening, including dedicated security audits for critical services.

### Quick Links
- **[Security Status](security/status.md)**  - Current security status and verification results
- **[Security Policy](security/policy.md)** - Complete security requirements and best practices
- **[Platform Security Audit](security/audit-report.md)** - Platform-wide security analysis and fixes
- **[Tools Service Security Audit](security/tools-service-audit.md)**  - Command injection protection audit (8.5/10, 0 vulnerabilities)
- **[Security Improvements Summary](security/improvements-summary.md)** - Executive overview of security enhancements
- **[Remediation Checklist](security/remediation-checklist.md)** - Step-by-step implementation procedures
- **[Security Findings (JSON)](security/findings.json)** - Machine-readable format for CI/CD integration

### Latest Security Achievements
-  **Tools Service**: Command injection protection verified (Nov 2025)
-  **55 Security Tools**: All audited and production-ready
-  **Gateway Hardening**: HTTP→HTTPS redirect enforced
-  **Database Security**: Password standardization across services

##  Documentation Sections

### Guides
- **[Quickstart](guides/quickstart.md)** - Get up and running quickly
- **[Credentials](guides/credentials.md)** - Authentication and credential management
- **[Deployment](guides/deployment.md)** - Production deployment procedures

### Security
- **[Status Report](security/status.md)** - Current vulnerability metrics and verification status
- **[Security Policy](security/policy.md)** - Comprehensive security policies and requirements
- **[Audit Report](security/audit-report.md)** - Detailed technical security analysis
- **[Improvements Summary](security/improvements-summary.md)** - Overview of all security improvements
- **[Remediation Guide](security/remediation-checklist.md)** - Implementation procedures
- **[Findings (JSON)](security/findings.json)** - Machine-readable findings

##  Choose Your Path

### 👤 I'm a Developer
1. Start with [Quickstart Guide](guides/quickstart.md)
2. Reference [Credentials Guide](guides/credentials.md) for authentication
3. Check [Security Policy](security/policy.md) for security requirements

### 👨‍💼 I'm a System Administrator
1. Read [Deployment Guide](guides/deployment.md)
2. Review [Security Status](security/status.md)
3. Implement [Remediation Checklist](security/remediation-checklist.md)

###  I'm a Security Officer
1. Check [Security Status](security/status.md) for current metrics
2. Review [Security Policy](security/policy.md) for compliance
3. Analyze [Audit Report](security/audit-report.md) for details
4. Use [Findings (JSON)](security/findings.json) for CI/CD integration

### 🏢 I'm Evaluating This Platform
1. Read [Security Improvements Summary](security/improvements-summary.md)
2. Check [Security Status](security/status.md) verification results
3. Review [Quickstart](guides/quickstart.md) for demo deployment

## 🌟 Key Features

### **Production-Ready Security**
- JWT authentication with HS256
- bcrypt password hashing (12+ rounds)
- Bearer token validation on all critical endpoints
- Comprehensive security headers
- Restricted CORS configuration
- Command injection protection (verified)

 **AI-Powered Security Analysis** 
- **Local LLM Integration**: Ollama container with OpenAI-compatible API
- **Privacy-First**: All AI analysis runs locally, no data sent to external services
- **Threat Intelligence**: AI-enhanced security insights and recommendations
- **Security Automation**: Intelligent playbook execution and decision support

 **Comprehensive Security Tooling**
- **55+ Security Tools**: Network scanning, OSINT, cryptography, web security
- **API-First Architecture**: RESTful API with OpenAPI documentation
- **Async Execution**: Background task processing with Celery + Redis
- **Production-Ready**: Security-audited and hardened

 **Comprehensive Documentation**
- Security audit reports (platform + services)
- Deployment procedures
- Credential management guides
- Policy and best practices

 **Community-Driven Development**
- Beta Phase (Security-Hardened)
- Open to community feedback
- Active development and improvements
- Transparent security status

##  Support & Feedback

- **Issues**: [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions)
- **Security Reports**: fabrizio.salmi@gmail.com

##  What's in the Repo?

**Main Documentation** (at repository root)
- `README.md` - Main project overview
- `SECURITY.md` - Security policy (also in docs/)
- `DEPLOYMENT.md` - Deployment guide (also in docs/)
- `QUICKSTART.md` - Quick start (also in docs/)

**Organized Documentation** (in `/docs`)
- `/docs/security/` - All security-related documentation
- `/docs/guides/` - Deployment and configuration guides
- `/docs/index.md` - This documentation home page

##  Community Maturity

Wildbox is in the **Beta Phase (Security-Hardened)** and reaches **community maturity through**:
-  Platform security hardening (completed)
-  Tools service security audit (8.5/10, 0 vulnerabilities)
-  AI/LLM integration (local Ollama deployment)
- 🤝 Community feedback and beta testing
-  Bug reports and issue tracking
- 💡 Feature requests and improvements
-  Real-world deployment experiences

Help us build a mature, trusted security platform!

##  What's New in v0.2.0

- ** Tools Service Security Audit**: Command injection protection verified
- ** Local LLM Integration**: Ollama container with OpenAI-compatible API
- ** 55+ Security Tools**: Production-ready with async execution
- ** Gateway Hardening**: HTTP→HTTPS redirect enforced
- ** Enhanced Documentation**: Security audit reports and guides

---

**Last Updated**: November 16, 2025
**Status**: Beta Phase - Security-Hardened
**Tools Service Security**: 8.5/10 (0 command injection vulnerabilities)
**Platform Security**: Gateway hardened, database standardized
