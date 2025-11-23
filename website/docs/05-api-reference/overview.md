---
sidebar_position: 1
---

# API Reference Overview

Wildbox provides comprehensive RESTful APIs for all its services. All APIs follow OpenAPI 3.0 specification and include interactive documentation.

## Available APIs

### Identity Service API

Authentication, authorization, user management, team management, and subscription billing.

- **Base URL**: `http://localhost:8001`
- **Documentation**: [Identity API](/docs/api-reference/identity)
- **Key Features**:
  - User registration and authentication
  - Team and role management
  - API key lifecycle management
  - Subscription and billing (Stripe integration)
  - Rate limiting and permissions

**Quick Example:**
```bash
# Register a new user
curl -X POST http://localhost:8001/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure_password",
    "full_name": "John Doe"
  }'
```

### Tools API

Unified API for 50+ security tools with dynamic discovery and execution.

- **Base URL**: `http://localhost:8000`
- **Documentation**: [Tools API](/docs/api-reference/tools)
- **Key Features**:
  - Dynamic tool discovery
  - Async tool execution
  - Schema validation
  - Timeout handling
  - Result caching

**Quick Example:**
```bash
# List available tools
curl http://localhost:8000/api/v1/tools

# Execute a tool
curl -X POST http://localhost:8000/api/v1/tools/whois/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Data Lake API

Threat intelligence aggregation, IOC lookup, and enrichment from 50+ sources.

- **Base URL**: `http://localhost:8002`
- **Documentation**: [Data API](/docs/api-reference/data)
- **Key Features**:
  - Multi-source threat intelligence
  - IOC lookup and enrichment
  - Geolocation and reputation scoring
  - Real-time data collection
  - Advanced filtering and search

**Quick Example:**
```bash
# Search for IOCs
curl http://localhost:8002/api/v1/iocs/search?type=ip&value=1.1.1.1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### AI Agents API

GPT-4 powered security analysis, report generation, and automated insights.

- **Base URL**: `http://localhost:8006`
- **Documentation**: [Agents API](/docs/api-reference/agents)
- **Key Features**:
  - AI-powered threat analysis
  - Automated report generation
  - Natural language querying
  - Tool orchestration
  - Context-aware responses

**Quick Example:**
```bash
# Analyze a security event
curl -X POST http://localhost:8006/api/v1/analyze \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event": "Multiple failed login attempts from 192.168.1.100",
    "context": "Production web server"
  }'
```

### Responder API

SOAR platform for incident response automation and playbook execution.

- **Base URL**: `http://localhost:8018`
- **Documentation**: [Responder API](/docs/api-reference/responder)
- **Key Features**:
  - YAML-based playbook definition
  - Async workflow execution
  - External system integrations
  - Real-time execution monitoring
  - Variable interpolation

**Quick Example:**
```bash
# List playbooks
curl http://localhost:8018/api/v1/playbooks \
  -H "Authorization: Bearer YOUR_TOKEN"

# Execute a playbook
curl -X POST http://localhost:8018/api/v1/playbooks/1/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"params": {"target": "192.168.1.100"}}'
```

### CSPM API

Multi-cloud security posture management and compliance scanning.

- **Base URL**: `http://localhost:8019`
- **Documentation**: [CSPM API](/docs/api-reference/cspm)
- **Key Features**:
  - Multi-cloud support (AWS, Azure, GCP)
  - 200+ security checks
  - Compliance frameworks (CIS, NIST, SOC2, PCI-DSS)
  - Risk-based prioritization
  - Automated remediation recommendations

**Quick Example:**
```bash
# List available checks
curl http://localhost:8019/api/v1/checks \
  -H "Authorization: Bearer YOUR_TOKEN"

# Start a scan
curl -X POST http://localhost:8019/api/v1/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "account_id": "123456789012",
    "frameworks": ["cis", "nist"]
  }'
```

## Authentication

All APIs require authentication using either:

### 1. JWT Tokens (User Authentication)

```bash
# Login to get token
curl -X POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password"
  }'

# Use token
curl http://localhost:8000/api/v1/tools \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 2. API Keys (Service Authentication)

```bash
# Create API key
curl -X POST http://localhost:8001/api/v1/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API Key",
    "permissions": ["read", "write"]
  }'

# Use API key
curl http://localhost:8000/api/v1/tools \
  -H "X-API-Key: YOUR_API_KEY"
```

## Rate Limiting

All APIs implement rate limiting to ensure fair usage:

- **Free Plan**: 100 requests/minute
- **Personal Plan**: 1,000 requests/minute
- **Business Plan**: 10,000 requests/minute
- **Enterprise Plan**: Unlimited

Rate limit headers are included in all responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1699564800
```

## Error Handling

All APIs use standard HTTP status codes and return JSON error responses:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Missing required field: email",
    "details": {
      "field": "email",
      "reason": "required"
    }
  }
}
```

Common status codes:
- `200 OK` - Request successful
- `201 Created` - Resource created
- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

## Interactive Documentation

Each service provides interactive API documentation powered by Swagger UI:

- **Identity**: http://localhost:8001/docs
- **Tools**: http://localhost:8000/docs
- **Data**: http://localhost:8002/docs
- **Agents**: http://localhost:8006/docs
- **Responder**: http://localhost:8018/docs
- **CSPM**: http://localhost:8019/docs

## SDKs and Client Libraries

Official SDKs are coming soon! In the meantime, you can use standard HTTP clients:

### Python

```python
import requests

# Using requests
response = requests.get(
    'http://localhost:8000/api/v1/tools',
    headers={'Authorization': 'Bearer YOUR_TOKEN'}
)
tools = response.json()
```

### JavaScript/TypeScript

```typescript
// Using fetch
const response = await fetch('http://localhost:8000/api/v1/tools', {
  headers: {
    'Authorization': 'Bearer YOUR_TOKEN'
  }
});
const tools = await response.json();
```

### cURL

```bash
curl http://localhost:8000/api/v1/tools \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Support

- [Full API Documentation](/docs/api-reference)
- [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions)
- [Report Issues](https://github.com/fabriziosalmi/wildbox/issues)
