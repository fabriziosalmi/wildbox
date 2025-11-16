# Local LLM Setup Guide

This guide explains how to run the Wildbox AI Agents with a containerized local LLM using vLLM and Qwen2.5-0.5B-Instruct.

## Overview

The agents service now includes a **vLLM-powered OpenAI-compatible API** running **Qwen2.5-0.5B-Instruct** from Hugging Face. This eliminates the need for external LLM services like LM Studio or OpenAI API.

### Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│ Agents Service  │────▶│  vLLM API    │────▶│ Qwen2.5-0.5B│
│   (FastAPI)     │     │ (Port 8000)  │     │   Model     │
└─────────────────┘     └──────────────┘     └─────────────┘
        │
        │ OpenAI-compatible API
        │ http://llm:8000/v1/chat/completions
        │
        ▼
    LangChain Agent
```

## Hardware Requirements

### GPU Configuration (Recommended)

- **GPU:** NVIDIA GPU with 4GB+ VRAM (RTX 2060 or better)
- **RAM:** 8GB system RAM
- **Disk:** 5GB for model cache
- **CUDA:** 11.8+ with nvidia-docker support

**Performance:** 15-20 tokens/second

### CPU-Only Configuration (Fallback)

- **CPU:** 4+ cores recommended
- **RAM:** 8GB minimum, 16GB recommended
- **Disk:** 5GB for model cache

**Performance:** 2-5 tokens/second (5-10x slower than GPU)

## Quick Start

### GPU Setup (Default)

```bash
# Start all services including LLM
docker-compose up -d

# Verify LLM is running
curl http://localhost:8080/health

# Test inference
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer wildbox-local-llm" \
  -d '{
    "model": "qwen3-0.6b",
    "messages": [{"role": "user", "content": "Analyze IP 8.8.8.8"}],
    "max_tokens": 256
  }'
```

### CPU-Only Setup

```bash
# Use CPU-only override configuration
docker-compose -f docker-compose.yml -f docker-compose.cpu.yml up -d

# Monitor startup (first run downloads ~1GB model)
docker-compose logs -f llm
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_BASE_URL` | `http://llm:8000/v1` | vLLM API endpoint |
| `OPENAI_API_KEY` | `wildbox-local-llm` | API key for local LLM |
| `OPENAI_MODEL` | `qwen3-0.6b` | Model name for inference |

### Model Configuration

Edit `docker-compose.yml` to change models:

```yaml
llm:
  command: >
    --model Qwen/Qwen2.5-0.5B-Instruct  # Change this
    --served-model-name qwen3-0.6b      # And this
    --max-model-len 4096
```

**Supported models:**
- `Qwen/Qwen2.5-0.5B-Instruct` (500MB, fastest)
- `Qwen/Qwen2.5-1.5B-Instruct` (1.5GB, balanced)
- `Qwen/Qwen2.5-3B-Instruct` (3GB, best quality)
- `meta-llama/Llama-3.2-1B-Instruct` (1GB, alternative)

## Switching to OpenAI API

To use OpenAI GPT-4o instead of local LLM:

```yaml
# docker-compose.yml
agents:
  environment:
    - OPENAI_API_KEY=sk-your-real-openai-key-here
    - OPENAI_BASE_URL=  # Remove or leave empty
    - OPENAI_MODEL=gpt-4o
  depends_on:
    - wildbox-redis
    - api
    # - llm  # Remove dependency
```

Or set environment variables:

```bash
export OPENAI_API_KEY="sk-your-real-key"
export OPENAI_BASE_URL=""
export OPENAI_MODEL="gpt-4o"
docker-compose up -d agents
```

## Troubleshooting

### LLM container fails to start

**Symptom:** `llm` container exits immediately

**Solution 1: GPU not detected**
```bash
# Check GPU availability
docker run --rm --gpus all nvidia/cuda:11.8.0-base-ubuntu22.04 nvidia-smi

# If fails, install nvidia-docker2
sudo apt-get install nvidia-docker2
sudo systemctl restart docker
```

**Solution 2: Use CPU-only mode**
```bash
docker-compose -f docker-compose.yml -f docker-compose.cpu.yml up -d
```

### Model download fails

**Symptom:** "Repository not found" or "Connection timeout"

**Solution: Set Hugging Face token (for gated models)**
```yaml
llm:
  environment:
    - HF_TOKEN=hf_your_token_here
```

**Solution: Use proxy for China/restricted regions**
```yaml
llm:
  environment:
    - HF_ENDPOINT=https://hf-mirror.com
```

### Out of memory errors

**Symptom:** "CUDA out of memory" or container restarts

**Solution 1: Reduce max model length**
```yaml
llm:
  command: >
    --max-model-len 2048  # Reduce from 4096
    --gpu-memory-utilization 0.7  # Reduce from 0.9
```

**Solution 2: Use smaller model**
```yaml
llm:
  command: >
    --model Qwen/Qwen2.5-0.5B-Instruct  # Instead of 1.5B/3B
```

**Solution 3: Use CPU mode**
```bash
docker-compose -f docker-compose.yml -f docker-compose.cpu.yml up -d
```

### Slow inference (CPU mode)

**Expected:** 2-5 tokens/second on CPU

**Optimization:**
```yaml
llm:
  deploy:
    resources:
      limits:
        cpus: '8'  # Increase CPU cores
        memory: 16G  # Increase RAM
```

**Alternative:** Use external API (OpenAI, Anthropic) for production

### Agent analysis fails

**Check LLM health:**
```bash
curl http://localhost:8080/health
```

**Check agent logs:**
```bash
docker-compose logs agents | grep -i llm
```

**Test LLM directly:**
```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer wildbox-local-llm" \
  -d '{"model":"qwen3-0.6b","messages":[{"role":"user","content":"test"}]}'
```

## Performance Benchmarks

### Qwen2.5-0.5B-Instruct

| Hardware | Tokens/sec | Analysis Time | Cost |
|----------|------------|---------------|------|
| RTX 3090 (24GB) | 50-80 | 10-15s | Free |
| RTX 2060 (6GB) | 15-20 | 20-30s | Free |
| CPU (8 cores) | 2-5 | 60-120s | Free |
| OpenAI GPT-4o | 100-150 | 3-5s | $0.01-0.05 |

### Quality Comparison

| Model | Verdict Accuracy | Report Quality | Reasoning Depth |
|-------|------------------|----------------|-----------------|
| Qwen2.5-0.5B | ⭐⭐⭐ Good | ⭐⭐⭐ Good | ⭐⭐ Basic |
| Qwen2.5-3B | ⭐⭐⭐⭐ Very Good | ⭐⭐⭐⭐ Very Good | ⭐⭐⭐ Moderate |
| GPT-4o | ⭐⭐⭐⭐⭐ Excellent | ⭐⭐⭐⭐⭐ Excellent | ⭐⭐⭐⭐⭐ Deep |

## Cost Analysis

### Local LLM (vLLM)

- **Initial Setup:** Free (model download ~1GB)
- **Per Analysis:** $0.00 (electricity only)
- **Monthly Cost:** $0-10 (GPU electricity)
- **Scalability:** Limited by GPU/CPU capacity

### OpenAI GPT-4o

- **Initial Setup:** Free (API key required)
- **Per Analysis:** $0.01-0.05 (varies by length)
- **Monthly Cost:** $50-500 (1000-10000 analyses)
- **Scalability:** Unlimited (API handles scale)

## Recommended Deployment

### Development/Testing
```yaml
# Local LLM (CPU or GPU)
OPENAI_BASE_URL=http://llm:8000/v1
OPENAI_MODEL=qwen3-0.6b
```

### Low-Volume Production (<100/day)
```yaml
# Local LLM (GPU required)
OPENAI_BASE_URL=http://llm:8000/v1
OPENAI_MODEL=qwen3-0.6b
```

### High-Volume Production (>100/day)
```yaml
# OpenAI API (best quality + speed)
OPENAI_BASE_URL=
OPENAI_MODEL=gpt-4o
OPENAI_API_KEY=sk-real-key
```

### Hybrid Deployment
```python
# Route based on priority
if priority == "high":
    use_openai_gpt4o()
else:
    use_local_llm()
```

## Advanced Configuration

### Multi-GPU Setup

```yaml
llm:
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: 2  # Use 2 GPUs
            capabilities: [gpu]
  command: >
    --tensor-parallel-size 2  # Distribute across GPUs
```

### Quantization (Reduce memory)

```yaml
llm:
  command: >
    --quantization awq  # 4-bit quantization
    --dtype auto
```

### Custom System Prompt

Edit `app/agents/threat_enrichment_agent.py`:

```python
system_prompt = """You are a cybersecurity expert specializing in 
threat intelligence. Analyze IOCs with extreme attention to detail..."""
```

## Migration from LM Studio

If you were using LM Studio:

1. **Stop LM Studio** (port 1234 no longer needed)
2. **Remove old configuration:**
   ```bash
   unset OPENAI_BASE_URL
   # Or delete from .env: OPENAI_BASE_URL=http://192.168.100.12:1234/v1
   ```
3. **Start new stack:**
   ```bash
   docker-compose down
   docker-compose up -d
   ```

## Support

For issues or questions:
- GitHub Issues: https://github.com/fabriziosalmi/wildbox/issues
- Documentation: https://wildbox.security/docs
- Security: security@wildbox.security
