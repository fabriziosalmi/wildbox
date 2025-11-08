# Wildbox API Documentation

Complete API reference documentation for all Wildbox microservices with examples, error handling, and authentication details.

## 📚 Documentation Status

| Service | Status | Files |
|---------|--------|-------|
| **Identity Service** | ✅ Complete | [endpoints.md](identity/endpoints.md) |
| **Guardian Service** | ✅ Complete | [endpoints.md](guardian/endpoints.md) |
| **Agents Service** | ✅ Complete | [endpoints.md](agents/endpoints.md) |
| **Data Service** | ✅ Complete | [endpoints.md](data/endpoints.md) |
| **Tools Service** | ✅ Complete | [endpoints.md](tools/endpoints.md) |
| **Responder Service** | ✅ Complete | [endpoints.md](responder/endpoints.md) |
| **CSPM Service** | 📋 Planned | Coming soon |

## 🚀 Quick Start

### Access API Documentation

**Interactive HTML Portal**:
- Local: [http://localhost/landing-page/api-reference.html](../api-reference.html)
- GitHub Pages: [https://www.wildbox.io/docs/api-reference.html](../api-reference.html)

**Live OpenAPI Endpoints** (during development):
- Identity Service: [http://localhost:8000/docs](http://localhost:8000/docs)
- Guardian Service: [http://localhost:8001/docs](http://localhost:8001/docs)
- Agents Service: [http://localhost:8002/docs](http://localhost:8002/docs)
- Data Service: [http://localhost:8006/docs](http://localhost:8006/docs)
- Tools Service: [http://localhost:8013/docs](http://localhost:8013/docs)

## 📖 Available Documentation

### Identity Service
- **Description**: User authentication, JWT tokens, user management
- **Port**: 8000
- **Documentation**: [Full Endpoint Reference](identity/endpoints.md)
- **Live Docs**: [Swagger UI](http://localhost:8000/docs) | [OpenAPI Schema](http://localhost:8000/openapi.json)

### Guardian Service
- **Description**: Integration management, queue monitoring, orchestration
- **Port**: 8001
- **Documentation**: [Full Endpoint Reference](guardian/endpoints.md)
- **Live Docs**: [Swagger UI](http://localhost:8001/docs) | [OpenAPI Schema](http://localhost:8001/openapi.json)

### Agents Service
- **Description**: AI-powered threat analysis, intelligence enrichment
- **Port**: 8004
- **Documentation**: [Full Endpoint Reference](agents/endpoints.md)
- **Live Docs**: [Swagger UI](http://localhost:8004/docs) | [OpenAPI Schema](http://localhost:8004/openapi.json)

### Data Service
- **Description**: Security data aggregation, analysis, reporting
- **Port**: 8006
- **Documentation**: [Full Endpoint Reference](data/endpoints.md)
- **Live Docs**: [Swagger UI](http://localhost:8006/docs) | [OpenAPI Schema](http://localhost:8006/openapi.json)

### Tools Service
- **Description**: Security tool execution, resource management
- **Port**: 8013
- **Documentation**: [Full Endpoint Reference](tools/endpoints.md)
- **Live Docs**: [Swagger UI](http://localhost:8013/docs) | [OpenAPI Schema](http://localhost:8013/openapi.json)

### Responder Service
- **Description**: Incident response, playbook execution, remediation
- **Port**: 8018
- **Documentation**: [Full Endpoint Reference](responder/endpoints.md)
- **Live Docs**: [Swagger UI](http://localhost:8018/docs) | [OpenAPI Schema](http://localhost:8018/openapi.json)

## 🛠️ Creating API Documentation

### Template Files

Use these templates when documenting a new service:

**Markdown Template**: See [TEMPLATE.md](TEMPLATE.md) for the complete markdown structure with all sections.

### Step-by-Step Guide

1. **Create service directory**:
   ```bash
   mkdir -p docs/api/[service-name]
   ```

2. **Copy template and customize**:
   ```bash
   cp docs/api/TEMPLATE.md docs/api/[service-name]/endpoints.md
   ```

3. **Document endpoints**:
   - List all endpoints (GET, POST, PUT, DELETE, PATCH)
   - Include path, authentication requirements
   - Document all parameters with types
   - Provide request/response examples
   - Document error codes and responses

4. **Add examples**:
   - Complete curl examples for each endpoint
   - Real-world workflow examples
   - Error handling examples
   - Authentication flows

5. **Update this README**:
   - Mark service as complete in the status table
   - Add link to the endpoint documentation file
   - Update any service-specific information

### Documentation Structure

Each service documentation should follow this structure:

```
docs/api/
├── [service-name]/
│   ├── endpoints.md          # Complete endpoint reference
│   ├── authentication.md     # (Optional) Detailed auth info
│   └── examples/             # (Optional) Code examples
│       ├── python.md
│       ├── javascript.md
│       └── curl.md
└── README.md                 # This file
```

### Minimum Required Sections

For each service documentation:

1. **Overview** - Service purpose and capabilities
2. **Authentication** - How to authenticate with the service
3. **Endpoints** - Complete list of all API endpoints
4. **Error Handling** - Error codes and response formats
5. **Rate Limiting** - Rate limit information
6. **Examples** - Real-world usage examples
7. **Related Documentation** - Links to other resources

### Endpoint Documentation Requirements

For each endpoint, document:

- **HTTP Method** (GET, POST, PUT, DELETE, PATCH)
- **Full path** (`/v1/resource`)
- **Authentication requirement** (Yes/No, required scope)
- **Query parameters** (for GET/DELETE)
- **Request body** (for POST/PUT/PATCH) with example JSON
- **Response body** with example JSON
- **Error responses** (400, 401, 403, 404, etc.)
- **Rate limiting** (if different from default)
- **Complete curl example**
- **Parameter table** with types and descriptions

## 🔍 SEO Optimization

Each API documentation page is optimized for search engines:

- **Descriptive titles** - Service name and "API Reference"
- **Meta descriptions** - Clear summary of service capabilities
- **Structured data** - Endpoints listed with HTTP methods
- **Internal linking** - Cross-references between services
- **Headers hierarchy** - H1, H2, H3 structure for readability
- **Code examples** - Searchable curl commands
- **Parameters documented** - All query/path parameters indexed

### SEO Keywords

Each service documentation targets:
- Service name + "API"
- "Wildbox" + service function
- HTTP methods + endpoint paths
- Authentication type + service
- "API Reference" + service

Example: "Wildbox Identity Service API", "JWT Token Authentication", "User Management Endpoints"

## 📝 Contributing Documentation

To contribute API documentation:

1. **Choose a service** from the "In Progress" list
2. **Follow the template** in [TEMPLATE.md](TEMPLATE.md)
3. **Test examples** with running services
4. **Include real examples** from live API responses
5. **Document all endpoints** - no stubs or "coming soon"
6. **Update the status** in this README
7. **Submit via pull request**

## 🔗 Related Resources

- [API Reference Hub](../api-reference.html) - Interactive documentation portal
- [Security Policy](../security/policy.md) - Authentication and security requirements
- [Quickstart Guide](../guides/quickstart.md) - Getting started with APIs
- [Deployment Guide](../guides/deployment.md) - Production deployment info

## ❓ FAQ

**Q: How long are rate limits?**
A: Standard endpoints have 100 requests/minute per user. Check individual service docs for specific limits.

**Q: How do I refresh my JWT token?**
A: Use the `/auth/refresh` endpoint with your current valid token. See Identity Service docs.

**Q: Where can I test the APIs?**
A: Use the live Swagger UI at each service's `/docs` endpoint, or use curl examples from the documentation.

**Q: What formats are supported?**
A: All APIs use JSON for request/response bodies. Some endpoints support CSV export.

**Q: How do I report API bugs?**
A: Open an issue on [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues) with the service name and endpoint.

## 📊 Documentation Roadmap

**Phase 1 (Complete)**:
- ✅ Identity Service - Full endpoint documentation
- ✅ API documentation template
- ✅ HTML reference portal

**Phase 2 (In Progress)**:
- 🔄 Guardian Service API documentation
- 🔄 Agents Service API documentation
- 🔄 Data Service API documentation

**Phase 3 (Planned)**:
- 📋 Tools Service API documentation
- 📋 Responder Service API documentation
- 📋 CSPM Service API documentation
- 📋 Code examples (Python, JavaScript, Go)
- 📋 Postman collections

## 📄 License

All documentation is licensed under the MIT License. See [LICENSE](../../LICENSE) for details.

---

**Last Updated**: November 7, 2024
**Version**: 1.0
**Status**: Active Development
**Maintainer**: Wildbox Community
