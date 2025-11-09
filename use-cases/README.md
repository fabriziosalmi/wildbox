# Wildbox Use Cases

This directory contains real-world use case examples demonstrating how to use Wildbox for various security operations scenarios.

## 📚 Available Use Cases

### 1. [Web Attack Detection](web-attack-detection/)
**Status**: ✅ Complete
**Difficulty**: Beginner
**Components Used**: Sensor, Data Lake

Demonstrates log ingestion and parsing for detecting common web application attacks including:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Brute Force Attacks
- Security Scanner Activity

**What you'll learn**:
- How to configure the Wildbox Sensor for log forwarding
- How to ingest and parse nginx/apache access logs
- How to query and analyze ingested events via the Data Lake API
- How to identify attack patterns in web traffic

**Quick Start**:
```bash
cd web-attack-detection
./quick-start.sh
```

---

## 🎯 Coming Soon

### 2. Cloud Security Monitoring (Planned)
**Components**: CSPM, Data Lake, Agents

Monitor AWS/Azure/GCP for security misconfigurations and compliance violations.

### 3. Threat Intelligence Enrichment (Planned)
**Components**: Data Lake, Threat Feeds, Agents

Enrich security events with threat intelligence from 50+ sources.

### 4. Automated Incident Response (Planned)
**Components**: Responder, Agents, Gateway

Automatically respond to security incidents with YAML-based playbooks.

### 5. Endpoint Threat Hunting (Planned)
**Components**: Sensor, Data Lake, Agents

Hunt for threats across your endpoint fleet using osquery.

### 6. API Security Monitoring (Planned)
**Components**: Gateway, Data Lake, Agents

Monitor and protect your APIs from abuse and attacks.

---

## 📋 Use Case Template

Want to contribute a use case? Use this structure:

```
use-cases/
└── your-use-case-name/
    ├── README.md              # Main documentation
    ├── quick-start.sh         # Automated setup script
    ├── sample-data/           # Sample data for testing
    │   └── generate.py        # Data generator (optional)
    ├── configs/               # Configuration files
    │   └── config.yaml
    └── docs/                  # Additional documentation
        ├── architecture.md
        └── troubleshooting.md
```

### Required Sections in README.md:
1. **Overview** - What the use case demonstrates
2. **Architecture** - Component diagram
3. **Prerequisites** - What's needed to run it
4. **Quick Start** - Step-by-step setup instructions
5. **Testing** - How to verify it's working
6. **Next Steps** - How to extend the use case

---

## 🏗️ Use Case Difficulty Levels

| Level | Description | Best For |
|-------|-------------|----------|
| **Beginner** | Single component, basic setup | Learning Wildbox basics |
| **Intermediate** | Multiple components, some integration | Real-world deployments |
| **Advanced** | Full platform, custom integrations | Production environments |

---

## 🤝 Contributing Use Cases

We welcome community contributions! To submit a use case:

1. **Fork the repository**
2. **Create your use case** following the template above
3. **Test thoroughly** - Ensure it works on a fresh installation
4. **Document completely** - Clear instructions for users
5. **Submit a Pull Request** - With a description of the use case

### Guidelines:
- ✅ Use real-world scenarios
- ✅ Include sample data
- ✅ Provide automated setup scripts
- ✅ Document all dependencies
- ✅ Test on clean installation
- ❌ Don't include sensitive data
- ❌ Don't require external paid services (unless clearly marked optional)

---

## 📖 Additional Resources

- [Wildbox Main Documentation](../docs/)
- [Component Documentation](../README.md#-components)
- [QUICKSTART Guide](../docs/guides/quickstart.md)
- [API Documentation](http://localhost:8001/docs) (when running)

---

## 💡 Use Case Ideas

Have an idea for a use case? Open an issue with the `use-case-idea` label:

- Container Security Monitoring
- DNS Tunneling Detection
- Insider Threat Detection
- Compliance Automation (PCI-DSS, HIPAA, etc.)
- Malware Analysis Workflow
- Zero Trust Network Monitoring
- IoT Device Security
- Supply Chain Security

---

## 📄 License

All use cases are part of the Wildbox project and licensed under the MIT License.
