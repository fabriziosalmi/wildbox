# Wildbox API Documentation

Endpoint references for the Wildbox microservices, with request examples,
error handling and authentication details.

## Service References

Each reference is written by hand. Where one disagrees with a running service,
the service is right: please
[open an issue](https://github.com/fabriziosalmi/wildbox/issues) naming the
service and the endpoint.

| Service | Reference | OpenAPI (Redoc) |
| --------- | ----------- | ----------------- |
| **Identity** | [endpoints.md](identity/endpoints.md) | - |
| **Tools** | [endpoints.md](tools/endpoints.md) | - |
| **Data** | [endpoints.md](data/endpoints.md) | - |
| **Guardian** | [endpoints.md](guardian/endpoints.md) | - |
| **Responder** | [endpoints.md](responder/endpoints.md) | [responder-api.html](responder-api.html) |
| **Agents** | [endpoints.md](agents/endpoints.md) | [agents-api.html](agents-api.html) |
| **CSPM** | Not written yet. The service runs (31 checks across AWS, Azure and GCP); its routes are under `/api/v1/cspm/` | - |

## Reaching the APIs

In a deployment every API is reached through the gateway, over HTTPS on port
443. The gateway path for each service, and whether it requires
authentication, is listed in the
[gateway routes table](https://www.wildbox.io/docs.html#gateway-routes). The
local port each service listens on is defined in `docker-compose.yml`; the
backend ports are bound to `127.0.0.1` only.

To authenticate, log in with a form-encoded `POST /auth/jwt/login` (fields
`username` and `password`) and send the returned `access_token` as
`Authorization: Bearer <token>`. The gateway also accepts an API key in the
`X-API-Key` header. The [Quick Start](../guides/quickstart.md) shows the
complete sequence.

The interactive overview is the [API reference page](../api-reference.html).

## Creating API Documentation

### Template Files

Use these templates when documenting a new service:

**Markdown Template**: See [TEMPLATE.md](https://github.com/fabriziosalmi/wildbox/blob/main/docs/api/TEMPLATE.md) for the complete markdown structure with all sections.

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
   - Add the service to the table above
   - Link the endpoint documentation file

### Documentation Structure

Each service documentation should follow this structure:

```bash
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

## Contributing Documentation

To contribute API documentation:

1. **Choose a service** without a reference (currently CSPM), or one whose
   reference has drifted from the code
2. **Follow the template** in [TEMPLATE.md](https://github.com/fabriziosalmi/wildbox/blob/main/docs/api/TEMPLATE.md)
3. **Test examples** with running services
4. **Include real examples** from live API responses
5. **Document all endpoints** - no stubs or placeholder sections
6. **Update the table** in this README
7. **Submit via pull request**

## Related Resources

- [API Reference Hub](../api-reference.html) - Interactive documentation portal
- [Security Policy](../security/policy.md) - Authentication and security requirements
- [Quickstart Guide](../guides/quickstart.md) - Getting started with APIs
- [Deployment Guide](../guides/deployment.md) - Production deployment info

## FAQ

**Q: What are the rate limits?**
A: The gateway limits requests per team. The budget comes from
`RATE_LIMIT_PER_HOUR` in `.env`, and every authenticated response carries
`X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`.

**Q: How do I refresh my JWT token?**
A: There is no refresh endpoint. When a token expires, log in again. The
lifetime is `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` in the identity service settings
(30 minutes unless you set it).

**Q: Where can I test the APIs?**
A: With the curl examples in each reference, against your own deployment.

**Q: How do I report API bugs?**
A: Open an issue on [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues) with the service name and endpoint.

## License

All documentation is licensed under the MIT License. See [LICENSE](https://github.com/fabriziosalmi/wildbox/blob/main/LICENSE) for details.
