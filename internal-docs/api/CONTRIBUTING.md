# Contributing API Documentation

Thank you for contributing to Wildbox API documentation! This guide explains how to document a service's endpoints for the Wildbox API Reference.

## 📋 Quick Checklist

- [ ] Choose an undocumented service from [README.md](README.md)
- [ ] Create service directory: `docs/api/[service-name]/`
- [ ] Copy and customize [TEMPLATE.md](TEMPLATE.md)
- [ ] Document all endpoints (GET, POST, PUT, DELETE, etc.)
- [ ] Provide curl examples for each endpoint
- [ ] Document error codes and responses
- [ ] Test examples against running services
- [ ] Update [README.md](README.md) status table
- [ ] Submit pull request

## 🎯 Services Needing Documentation

Priority order (highest impact first):

1. **Guardian Service** (8001) - Integration management
2. **Agents Service** (8002) - AI threat analysis
3. **Data Service** (8006) - Data aggregation
4. **Tools Service** (8013) - Security tool execution
5. **Responder Service** (8018) - Incident response
6. **CSPM Service** - Cloud security posture

## 📖 Documentation Template Structure

Each service documentation should include:

```markdown
# [Service Name] Service API

- Overview
- Table of Contents
- Authentication requirements
- Endpoint groups (organized logically)
  - Each endpoint with full documentation
- Error codes table
- Rate limiting info
- Complete examples
- Related documentation links
```

## ✍️ Writing Guidelines

### Endpoint Documentation

For each endpoint, include:

1. **Endpoint Definition**:
   ```markdown
   ### GET /resource

   Brief description of what this endpoint does.

   **Method**: `GET`
   **Endpoint**: `/v1/resource`
   **Authentication**: Required (Bearer Token)
   **Rate Limit**: 100 requests/minute
   ```

2. **Parameters Table**:
   ```markdown
   | Name | Type | Required | Description |
   |------|------|----------|-------------|
   | id | string | Yes | Resource identifier |
   | limit | integer | No | Result limit (default: 20) |
   ```

3. **Request Example**:
   ```bash
   curl -X GET "http://localhost:8000/resource" \
     -H "Authorization: Bearer {token}"
   ```

4. **Response Examples**:
   - Success (200, 201, 204)
   - Errors (400, 401, 404, 429, 500)
   - Complete JSON with all fields

5. **Real-World Workflow**:
   - Show how endpoints work together
   - Include authentication flow
   - Demonstrate error handling

### Code Examples

All examples must be:
- **Real and tested**: Verify against running services
- **Actionable**: Users can copy and run them
- **Consistent**: Same formatting across service docs
- **Annotated**: Comments explaining non-obvious parts

### Descriptions

- **Clear**: Use simple, direct language
- **Specific**: Explain the exact behavior
- **Accurate**: Match actual API behavior
- **Complete**: Include all relevant details

## 🔄 Process

### Step 1: Set Up

```bash
# Clone and navigate to project
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox

# Create feature branch
git checkout -b docs/guardian-api

# Create service directory
mkdir -p docs/api/guardian
```

### Step 2: Get Service Information

Run the service and explore its API:

```bash
# Start services (if not running)
docker-compose up -d

# Check service is running
curl http://localhost:8001/health

# Get OpenAPI schema
curl http://localhost:8001/openapi.json | jq '.'

# View interactive documentation
# Open http://localhost:8001/docs in browser
```

### Step 3: Document Endpoints

1. **Copy template**:
   ```bash
   cp docs/api/TEMPLATE.md docs/api/guardian/endpoints.md
   ```

2. **Customize header**:
   - Service name
   - Service port
   - Base URL
   - Description

3. **Document each endpoint**:
   - Extract from OpenAPI spec
   - Test with curl commands
   - Document parameters
   - Provide examples

4. **Verify examples**:
   ```bash
   # Test each curl example
   curl -X POST http://localhost:8001/v1/resource \
     -H "Authorization: Bearer {test-token}" \
     -H "Content-Type: application/json" \
     -d '{...}'
   ```

### Step 4: Update Index

Edit [README.md](README.md):

```markdown
| **Guardian Service** | ✅ Complete | [endpoints.md](guardian/endpoints.md) |
```

### Step 5: Submit Pull Request

```bash
# Commit changes
git add docs/api/
git commit -m "docs: Add Guardian Service API documentation

- Document all integration endpoints
- Include authentication examples
- Provide error handling patterns
- Add webhook examples
- Complete SEO optimization"

# Push and create PR
git push origin docs/guardian-api
```

## 📊 Example: Guardian Service

Here's what a complete Guardian Service documentation would include:

### Authentication
- How to get tokens
- Bearer token format
- Webhook signature validation

### Endpoints by Group

**Integration Management**:
- GET /v1/integrations - List integrations
- POST /v1/integrations - Create integration
- GET /v1/integrations/{id} - Get integration
- PUT /v1/integrations/{id} - Update integration
- DELETE /v1/integrations/{id} - Delete integration
- POST /v1/integrations/{id}/test - Test connection

**Queue Monitoring**:
- GET /v1/queue/status - Queue status
- GET /v1/queue/tasks - List queued tasks
- POST /v1/queue/tasks/{id}/retry - Retry task
- POST /v1/queue/tasks/{id}/cancel - Cancel task

**Webhook Management**:
- GET /v1/webhooks - List webhooks
- POST /v1/webhooks - Create webhook
- POST /v1/webhooks/{id}/test - Test webhook
- DELETE /v1/webhooks/{id} - Delete webhook

## 🧪 Testing Examples

Before submitting, verify all examples work:

```bash
# Get authentication token
TOKEN=$(curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}' \
  | jq -r '.data.token')

# Test each endpoint example
curl -X GET http://localhost:8001/v1/integrations \
  -H "Authorization: Bearer $TOKEN"

# Verify response format
curl -X POST http://localhost:8001/v1/integrations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{...}' | jq '.'
```

## 📝 Common Patterns

### Authentication Examples

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password"
  }' | jq -r '.data.token')

# Use token in requests
curl -H "Authorization: Bearer $TOKEN" ...
```

### Error Handling

```bash
# Document common errors for each endpoint
# Example: 400 Bad Request

{
  "error": "Bad Request",
  "message": "Field 'name' is required",
  "status": "error",
  "validation_errors": {
    "name": "This field is required"
  }
}
```

### Pagination

```bash
# Document pagination parameters
curl -X GET "http://localhost:8001/v1/resource?limit=10&offset=20" \
  -H "Authorization: Bearer {token}"

# Example response
{
  "data": [...],
  "pagination": {
    "limit": 10,
    "offset": 20,
    "total": 150,
    "pages": 15
  }
}
```

## 🎨 SEO Best Practices

Make documentation searchable:

1. **Use descriptive headers** - Include service name and action
2. **Document parameters** - Search engines index parameter names
3. **Provide examples** - Searchable curl commands
4. **Link related docs** - Internal cross-linking improves SEO
5. **Use consistent terminology** - Same words throughout

## 🚀 Going Further

### Additional Sections (Optional)

- **Webhook Payload Examples** - If service supports webhooks
- **Rate Limit Strategy** - How to handle rate limiting
- **Batch Operations** - If service supports bulk requests
- **Pagination Patterns** - If service supports pagination
- **Filtering Syntax** - Query parameter filter documentation
- **Sorting Options** - Sort parameter documentation
- **Code Examples** - Python, JavaScript, Go examples

### Code Samples Directory

Create `docs/api/[service]/examples/`:

```
examples/
├── README.md
├── curl/
│   ├── authentication.sh
│   ├── list-resources.sh
│   └── create-resource.sh
├── python/
│   ├── example.py
│   └── requirements.txt
└── javascript/
    ├── example.js
    └── package.json
```

## ❓ Questions?

- Check existing documentation in [docs/api/identity/](identity/)
- Review the [TEMPLATE.md](TEMPLATE.md) for structure
- Open [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions) for help
- Report issues on [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues)

## 📚 Resources

- [API Documentation Roadmap](README.md)
- [Documentation Template](TEMPLATE.md)
- [Identity Service Example](identity/endpoints.md)
- [Interactive API Portal](../api-reference.html)
- [Main Documentation](../)

---

Thank you for contributing to making Wildbox better! 🛡️
