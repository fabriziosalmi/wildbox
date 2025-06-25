# Open Security Guardian - Django Applications

This directory contains all the Django applications that make up the Guardian platform.

## Applications

- **assets**: Asset discovery, inventory, and management
- **vulnerabilities**: Vulnerability processing, correlation, and lifecycle management
- **scanners**: Integration with vulnerability scanners (Nessus, Qualys, OpenVAS, etc.)
- **remediation**: Remediation workflow management and ticket tracking
- **compliance**: Compliance framework support and reporting
- **integrations**: External system integrations (JIRA, ServiceNow, SIEM, etc.)
- **reporting**: Analytics, dashboards, and report generation
- **core**: Core functionality shared across applications

## Common Patterns

Each application follows Django best practices:
- Models for data representation
- Views for API endpoints
- Serializers for data transformation
- Tasks for background processing
- Tests for quality assurance
