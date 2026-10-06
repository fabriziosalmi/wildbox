# Wildbox API Documentation

Endpoint references for the Wildbox microservices, with request examples,
error handling and authentication details.

## Service References

Each reference is written by hand. Where one disagrees with a running service,
the service is right: please
[open an issue](https://github.com/fabriziosalmi/wildbox/issues) naming the
service and the endpoint.

| Service | Reference |
| --------- | ----------- |
| **Identity** | [endpoints.md](identity/endpoints.md) |
| **Tools** | [endpoints.md](tools/endpoints.md) |
| **Data** | [endpoints.md](data/endpoints.md) |
| **Guardian** | [endpoints.md](guardian/endpoints.md) |
| **Responder** | [endpoints.md](responder/endpoints.md) |
| **Agents** | [endpoints.md](agents/endpoints.md) |
| **CSPM** | [endpoints.md](cspm/endpoints.md). The service scans AWS only, with 22 checks; a scan request for GCP or Azure is refused with `400` |

### OpenAPI Schemas

No generated OpenAPI page is published. The two that were (`agents-api.html`
and `responder-api.html`, now redirects to the references above) each held a
schema exported once from the service; nothing regenerated them, and they
listed the routes without their authentication. The scripts that wrote them
(`scripts/generate-api-docs*`) are gone for the same reason.

A running service is the source for a machine-readable schema:

- identity, tools, data, responder, agents and cspm serve `/openapi.json` on
  their local port when `ENVIRONMENT` is `development`, and answer 404 for it
  otherwise;
- guardian serves `/api/schema/` when `DEBUG` is on.

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
`X-API-Key` header. Create one with `POST /api/v1/identity/api-keys` (a user
key) or `POST /api/v1/identity/teams/{team_id}/api-keys` (a team key). The
[Quick Start](../guides/quickstart.md) shows the complete sequence.

Login, tokens, logout and the failed-login lockout are described in the
[Authentication and sessions guide](../guides/authentication.md). The
[API reference page](../api-reference.html) is a one-page overview.

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

1. **Choose a reference** in the table above that has drifted from the code,
   or a route its reference does not list
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
A: The gateway allows `RATE_LIMIT_PER_HOUR` requests per hour per team
(10000 unless `.env` sets it), enforced in fixed 60-second windows of one
sixtieth of that figure, 166 with the default. The gateway refuses to start
when the value is not a whole number from 1 to 1,000,000,000. Responses on
routes the gateway authenticates carry `X-RateLimit-Limit`,
`X-RateLimit-Remaining` and `X-RateLimit-Reset` for the current minute, and
`X-RateLimit-Policy` with the hourly figure (`10000;w=3600` by default). Some
services add their own limits: the agents service, for example, accepts 5
analysis requests per minute per user by default
([agents reference](agents/endpoints.md#rate-limiting)).

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
