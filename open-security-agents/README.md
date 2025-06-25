# 🧠 Open Security Agents

AI-powered threat intelligence enrichment service for the Wildbox security platform.

## Overview

Open Security Agents provides "Threat Enrichment as a Service" through an AI-driven analysis engine. The service uses Large Language Models (LLMs) to automatically investigate Indicators of Compromise (IOCs) and generate comprehensive threat intelligence reports.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI       │    │   Celery        │    │   LangChain     │
│   REST API      │───▶│   Task Queue    │───▶│   AI Agents     │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   API Models    │    │   Redis         │    │   Wildbox       │
│   (Pydantic)    │    │   Result Store  │    │   Tool Belt     │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Features

- **AI-Powered Analysis**: Uses GPT-4o to perform intelligent threat analysis
- **Asynchronous Processing**: Long-running analysis tasks handled via Celery
- **Multi-IOC Support**: Analyzes IPs, domains, URLs, hashes, and more
- **Tool Integration**: Leverages the entire Wildbox security toolkit
- **Markdown Reports**: Generates human-readable intelligence reports

## Quick Start

### Docker (Recommended)

```bash
# Start all services
docker-compose up -d

# Check service health
curl http://localhost:8004/health
```

### Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your API keys

# Start Redis
redis-server

# Start Celery worker
celery -A app.worker worker --loglevel=info

# Start API server
uvicorn app.main:app --host 0.0.0.0 --port 8004 --reload
```

## API Usage

### Analyze an IOC

```bash
# Submit analysis request
curl -X POST http://localhost:8004/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "ipv4", "value": "8.8.8.8"}}'

# Response: {"task_id": "abc-123", "status": "pending", ...}
```

### Check Analysis Status

```bash
# Get task status
curl http://localhost:8004/v1/analyze/abc-123

# When complete, returns full analysis report
```

## Configuration

Environment variables:

- `OPENAI_API_KEY`: OpenAI API key for GPT-4o
- `REDIS_URL`: Redis connection URL
- `WILDBOX_API_URL`: Open Security API base URL
- `WILDBOX_DATA_URL`: Open Security Data base URL
- `DEBUG`: Enable debug mode

## Supported IOC Types

- **IPv4/IPv6**: IP address analysis
- **Domain**: Domain reputation and WHOIS
- **URL**: URL analysis and categorization
- **Hash**: File hash reputation (MD5, SHA1, SHA256)
- **Email**: Email address investigation

## Architecture Components

### ThreatEnrichmentAgent

The core AI agent that orchestrates the analysis process:

1. **IOC Classification**: Determines IOC type and appropriate tools
2. **Tool Execution**: Runs security tools in logical sequence
3. **Evidence Collection**: Gathers and correlates findings
4. **Report Generation**: Creates final intelligence report

### Tool Belt

Security tools available to the AI agent:

- Port scanning and service detection
- WHOIS lookups and domain analysis
- Reputation checks across multiple sources
- Threat intelligence database queries
- URL analysis and screenshot capture
- Hash analysis and sandbox integration

## Development

### Adding New Tools

1. Implement tool in `app/tools/langchain_tools.py`
2. Add API integration in `app/tools/wildbox_client.py`
3. Update agent prompt with tool description

### Testing

```bash
# Run tests
pytest

# Test specific analysis
python scripts/test_agents.py
```

## Deployment

Production deployment uses Docker with:

- Redis for task queue and result storage
- Multiple Celery workers for parallel processing
- Nginx for load balancing and SSL termination
- Monitoring with health checks and metrics

## Security

- All API communications use internal authentication
- LLM prompts are sanitized to prevent injection
- IOC data is validated before processing
- Results are temporarily stored and auto-expire

## License

Part of the Wildbox Open Security Platform
