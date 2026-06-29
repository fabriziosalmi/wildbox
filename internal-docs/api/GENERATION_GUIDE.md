# API Documentation Generation Guide

This guide explains how to automatically generate static OpenAPI documentation for all Wildbox microservices.

## Overview

The Wildbox platform includes a Python script that:
1. Starts all microservices using Docker Compose
2. Waits for services to be healthy
3. Fetches OpenAPI schemas from each service
4. Generates static HTML documentation using ReDoc
5. Creates an index page linking all APIs

## Prerequisites

- Docker and Docker Compose installed
- Python 3.7+
- `requests` library (`pip install requests`)
- Sufficient disk space for Docker images (~3-5GB)

## Quick Start

### Generate API Documentation

```bash
# From the project root directory
python3 scripts/generate-api-docs.py
```

The script will:
- Start Docker Compose services
- Generate HTML files in `docs/api/`
- Create a swagger-index.html file
- Automatically stop all services when complete

### View Generated Documentation

After generation completes, you'll find:

```
docs/api/
├── swagger-index.html       # Index page with all APIs
├── api-api.html            # API / Tools Service
├── identity-api.html       # Identity & Auth Service
├── data-api.html           # Data Service
├── guardian-api.html       # Guardian Service
├── responder-api.html      # Responder Service
└── agents-api.html         # Agents Service
```

Open `docs/api/swagger-index.html` in a browser to view all APIs.

## Services Documented

| Service | Port | Description |
|---------|------|-------------|
| API | 8000 | Security tool execution and orchestration |
| Identity | 8001 | Authentication, authorization, user management |
| Data | 8002 | Threat intelligence and data aggregation |
| Guardian | 8013 | Integration management and orchestration |
| Responder | 8018 | Incident response and remediation |
| Agents | 8006 | AI-powered threat analysis |

## Environment Setup

Before generating documentation, ensure your `.env` file is properly configured:

```bash
cp .env.example .env
# Edit .env with your configuration
```

Key variables needed:
- `DATABASE_URL` - PostgreSQL connection
- `REDIS_URL` - Redis connection
- `JWT_SECRET_KEY` - JWT signing key
- Other service-specific variables

See [SECURITY.md](../../SECURITY.md) for production configuration.

## Manual Generation with Bash Script

Alternative method using pure Bash:

```bash
bash scripts/generate-api-docs.sh
```

## Troubleshooting

### Services fail to start

```bash
# Check Docker is running
docker ps

# Check logs
docker-compose logs <service-name>

# Clean up and retry
docker-compose down -v
python3 scripts/generate-api-docs.py
```

### Script hangs waiting for services

- Services may take 30+ seconds to start
- Check individual service health: `curl http://localhost:8000/health`
- Increase `max_retries` in the Python script if needed

### Generated files are empty

- OpenAPI endpoints may have changed
- Check service logs: `docker-compose logs`
- Verify services are exposing `/openapi.json`

### Port conflicts

If ports are already in use:
- Change port mappings in `docker-compose.yml`
- Or stop conflicting containers: `docker stop <container>`

## Customization

### Modify Output Format

Edit `scripts/generate-api-docs.py` to:
- Change CSS themes
- Modify HTML templates
- Add custom branding
- Include additional metadata

### Extend with Additional Services

Add services to `SERVICES` list in the script:

```python
SERVICES = [
    ('service-name', 8000, 'container-name'),
    # ... more services
]
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Generate API Docs
on: [push]
jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: docker/setup-buildx-action@v1
      - run: python3 scripts/generate-api-docs.py
      - uses: actions/upload-artifact@v2
        with:
          name: api-docs
          path: docs/api/
```

## Development

### Using Generated Docs in Development

The documentation portal automatically checks for generated HTML files:

1. Run the generation script
2. Access `docs/docs.html` in your browser
3. Click on "API Reference" to view generated docs

### Regenerating After Changes

When API services are updated:

```bash
# Regenerate all documentation
python3 scripts/generate-api-docs.py

# Commit changes
git add docs/api/
git commit -m "docs: Regenerate API documentation from services"
```

## Performance Notes

- Initial generation takes 2-5 minutes (service startup time)
- Subsequent generations are faster
- Generated HTML files are standalone (no external dependencies for ReDoc)
- Each API documentation file is ~200-500KB

## Security Considerations

- Generated docs contain API endpoint information
- No credentials are embedded in generated documentation
- Services use default test credentials during generation
- Always use production credentials when deploying

## Feedback & Issues

For issues with documentation generation:
1. Check [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues)
2. Enable debug logging in the Python script
3. Share error messages and service logs

## See Also

- [API Documentation Index](swagger-index.html) - View all APIs
- [API README](README.md) - Documentation overview
- [SECURITY.md](../../SECURITY.md) - Security requirements
- [DEPLOYMENT.md](../../DEPLOYMENT.md) - Production deployment
