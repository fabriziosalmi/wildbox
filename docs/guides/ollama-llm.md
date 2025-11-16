# Ollama LLM Integration Guide

Wildbox integrates **Ollama** for local LLM (Large Language Model) processing, providing AI-powered security analysis without sending data to external services.

---

## Overview

### What is Ollama?

Ollama is a lightweight, self-hosted LLM runtime that allows you to run models like **Llama 2**, **Code Llama**, **Mistral**, and others locally on your infrastructure.

### Why Local LLM?

 **Privacy**: All data stays within your infrastructure
 **Security**: No API keys or external dependencies
 **Cost**: No per-request charges
 **Speed**: Reduced latency for real-time analysis
 **Compliance**: Meets data residency requirements

---

## Quick Start

### 1. Service is Pre-Configured

Ollama is already included in `docker-compose.yml`:

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    container_name: wildbox-ollama
    ports:
      - "11434:11434"  # Ollama API
    environment:
      - OLLAMA_ORIGINS=*
    volumes:
      - llm_cache:/root/.ollama  # Model cache
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### 2. Start the Service

```bash
# Start all services including Ollama
docker-compose up -d

# Verify Ollama is running
curl http://localhost:11434/api/tags
```

### 3. Pull a Model

```bash
# Pull Llama 2 (recommended for security analysis)
docker exec wildbox-ollama ollama pull llama2

# Or pull a smaller model for faster responses
docker exec wildbox-ollama ollama pull llama2:7b

# For code analysis
docker exec wildbox-ollama ollama pull codellama
```

---

## Available Models

| Model | Size | Use Case | Recommended |
|-------|------|----------|-------------|
| `llama2` | 7B/13B/70B | General security analysis |  Yes (7B or 13B) |
| `codellama` | 7B/13B | Code review, vulnerability detection |  Yes (for code analysis) |
| `mistral` | 7B | Fast general-purpose | ⚡ Good for quick analysis |
| `phi` | 2.7B | Lightweight, fast |  For resource-constrained environments |

**Note:** Larger models provide better analysis but require more RAM (7B ≈ 8GB, 13B ≈ 16GB, 70B ≈ 64GB).

---

## OpenAI-Compatible API

Ollama provides an **OpenAI-compatible API endpoint**, allowing Wildbox AI services to use it as a drop-in replacement for OpenAI.

### Configuration

In `.env`:

```bash
# Option 1: Use local Ollama (default)
OPENAI_API_KEY=ollama
OPENAI_API_BASE=http://wildbox-ollama:11434/v1

# Option 2: Use OpenAI (requires API key)
OPENAI_API_KEY=sk-your-openai-key
OPENAI_API_BASE=https://api.openai.com/v1
```

### Testing the API

```bash
# Test Ollama API (OpenAI-compatible)
curl http://localhost:11434/v1/models

# Test chat completion
curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2",
    "messages": [{"role": "user", "content": "Analyze this SQL query for injection vulnerabilities: SELECT * FROM users WHERE id = " + userId}]
  }'
```

---

## Integration with Wildbox Services

### AI Agents Service

The AI Agents service automatically uses Ollama for:
- **Threat analysis**: Analyzing suspicious patterns
- **Incident response**: Generating response playbooks
- **Log analysis**: Identifying anomalies
- **Vulnerability assessment**: Code review and security checks

### Guardian Service

Guardian uses LLM for:
- **Policy interpretation**: Understanding complex security policies
- **Anomaly detection**: Identifying unusual behavior patterns
- **Recommendations**: Suggesting remediation steps

---

## Performance Tuning

### GPU Acceleration (Optional)

If you have an NVIDIA GPU:

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

### Memory Limits

```yaml
services:
  ollama:
    deploy:
      resources:
        limits:
          memory: 16G  # Adjust based on model size
        reservations:
          memory: 8G
```

---

## Model Management

### List Installed Models

```bash
docker exec wildbox-ollama ollama list
```

### Remove a Model

```bash
docker exec wildbox-ollama ollama rm llama2
```

### Update a Model

```bash
docker exec wildbox-ollama ollama pull llama2
```

---

## Monitoring

### Check Ollama Health

```bash
curl http://localhost:11434/api/tags | jq
```

### View Ollama Logs

```bash
docker logs wildbox-ollama --tail 100 -f
```

### Resource Usage

```bash
docker stats wildbox-ollama
```

---

## Troubleshooting

### Model Download Fails

```bash
# Check disk space
df -h

# Check network connectivity
docker exec wildbox-ollama curl -I https://ollama.ai

# Retry download
docker exec wildbox-ollama ollama pull llama2
```

### High Memory Usage

- Use smaller models (7B instead of 13B/70B)
- Set memory limits in docker-compose.yml
- Reduce concurrent requests

### Slow Response Times

- Use GPU acceleration if available
- Use smaller models (e.g., phi 2.7B)
- Increase `num_thread` parameter in model configuration

---

## Security Considerations

### Network Isolation

By default, Ollama is only accessible within the Docker network:

```yaml
# Good (default): Internal only
networks:
  - wildbox-internal

# Bad: Exposed to internet
ports:
  - "0.0.0.0:11434:11434"  # Don't do this!
```

### Model Verification

Always verify models come from official sources:

```bash
# Official Ollama library
docker exec wildbox-ollama ollama pull llama2

# NOT recommended: Unknown sources
# docker exec wildbox-ollama ollama pull untrusted/model
```

### Data Privacy

-  All processing happens locally
-  No data sent to external APIs
-  Models cached in Docker volume
-  GDPR/compliance-friendly

---

## Advanced: Custom Models

### Use Your Own Fine-Tuned Model

```bash
# Create Modelfile
cat > Modelfile <<EOF
FROM llama2
SYSTEM You are a cybersecurity expert specializing in threat detection.
EOF

# Build custom model
docker exec -i wildbox-ollama ollama create my-security-model < Modelfile
```

### Use in Wildbox

Update `.env`:

```bash
OLLAMA_MODEL=my-security-model
```

---

## API Reference

### Ollama Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tags` | GET | List installed models |
| `/api/generate` | POST | Generate text completion |
| `/api/chat` | POST | Chat completion (multi-turn) |
| `/api/pull` | POST | Download a model |
| `/api/delete` | DELETE | Remove a model |

### OpenAI-Compatible Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/models` | GET | List available models |
| `/v1/chat/completions` | POST | Chat completion (OpenAI format) |
| `/v1/completions` | POST | Text completion (OpenAI format) |

---

## Cost Comparison

| Solution | Cost | Privacy | Latency |
|----------|------|---------|---------|
| **Ollama (Local)** | $0 (hardware only) | 100% private | Low (local) |
| **OpenAI GPT-4** | ~$30/1M tokens | Sent to OpenAI | Medium (API call) |
| **OpenAI GPT-3.5** | ~$1/1M tokens | Sent to OpenAI | Medium (API call) |

For security-sensitive data, **local Ollama is the recommended choice**.

---

## Support & Resources

- **Ollama Documentation**: https://ollama.ai/docs
- **Model Library**: https://ollama.ai/library
- **GitHub**: https://github.com/ollama/ollama
- **Wildbox Issues**: https://github.com/fabriziosalmi/wildbox/issues

---

**Last Updated**: November 16, 2025
**Status**: Production Ready
**Recommended Model**: llama2:7b or llama2:13b for security analysis
