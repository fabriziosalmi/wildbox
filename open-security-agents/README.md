# 🧠 Open Security Agents

AI-powered threat intelligence enrichment service for the Wildbox security platform.

## Overview

Open Security Agents provides "Threat Enrichment as a Service" through an AI-driven analysis engine. The service uses Large Language Models (LLMs) to automatically investigate Indicators of Compromise (IOCs) and generate comprehensive threat intelligence reports.

**Now includes containerized local LLM support!** Run AI analysis without external API dependencies using vLLM and Qwen2.5-0.5B-Instruct.

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
│   API Models    │    │   Redis         │    │   vLLM API      │
│   (Pydantic)    │    │   Result Store  │    │   Qwen2.5-0.5B  │
│                 │    │                 │    │   (Local LLM)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                              ┌─────────────────┐
                                              │   Wildbox       │
                                              │   Tool Belt     │
                                              │   (55+ tools)   │
                                              └─────────────────┘
```

## Features

- **AI-Powered Analysis**: Uses LLM reasoning to perform intelligent threat analysis
- **Local LLM Support**: Run without external API costs using containerized vLLM + Qwen2.5
- **Asynchronous Processing**: Long-running analysis tasks handled via Celery
- **Multi-IOC Support**: Analyzes IPs, domains, URLs, hashes, and more
- **Tool Integration**: Leverages the entire Wildbox security toolkit (55+ tools)
- **Markdown Reports**: Generates human-readable intelligence reports
- **Flexible Deployment**: Use local LLM (free) or OpenAI API (higher quality)

## Quick Start

### Docker with Local LLM (Recommended)

```bash
# Start all services including local LLM
docker-compose up -d

# Wait for LLM model download (first run only, ~1GB)
docker-compose logs -f llm

# Check service health
curl http://localhost:8006/health

# Test LLM endpoint
curl http://localhost:8080/health
```

**Note:** GPU recommended for best performance. See [LLM_SETUP.md](LLM_SETUP.md) for CPU-only configuration.

### Docker with OpenAI API

```bash
# Set OpenAI API key
export OPENAI_API_KEY="sk-your-key-here"
export OPENAI_BASE_URL=""  # Empty = use OpenAI
export OPENAI_MODEL="gpt-4o"

# Start services (LLM container not needed)
docker-compose up -d agents redis
```

## Configuration

See [LLM_SETUP.md](LLM_SETUP.md) for detailed configuration guide.

### LLM Options

| Option | Speed | Quality | Cost | Use Case |
|--------|-------|---------|------|----------|
| **Local vLLM (GPU)** | ⭐⭐⭐ | ⭐⭐⭐ | Free | Development, low-volume |
| **Local vLLM (CPU)** | ⭐ | ⭐⭐⭐ | Free | Testing only |
| **OpenAI GPT-4o** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | $0.01-0.05 | Production, high-priority |

### Environment Variables

- `OPENAI_API_KEY`: API key (use "wildbox-local-llm" for local vLLM)
- `OPENAI_BASE_URL`: LLM endpoint (default: `http://llm:8000/v1` for local)
- `OPENAI_MODEL`: Model name (default: `qwen3-0.6b` for local)
- `REDIS_URL`: Redis connection URL
- `WILDBOX_API_URL`: Open Security API base URL
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
