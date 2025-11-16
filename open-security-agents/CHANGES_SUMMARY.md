# Summary: LM Studio to vLLM Migration

## ✅ Completed Changes

### 1. **Added vLLM Service** 
- **Container:** `wildbox-llm`
- **Image:** `vllm/vllm-openai:latest`
- **Model:** Qwen/Qwen2.5-0.5B-Instruct from Hugging Face
- **API:** OpenAI-compatible at `http://llm:8000/v1`
- **Port:** 8080 (external), 8000 (internal)

### 2. **Updated Agents Configuration**
- Removed LM Studio dependency (`host.docker.internal:1234`)
- Added container-based LLM dependency
- Updated environment variables for vLLM

### 3. **Fixed Rate Limiting**
- Increased API service rate limit: 100 → 500 requests/min
- Added retry logic with exponential backoff in agents client
- Better handling of concurrent tool calls

### 4. **Created Documentation**
- `LLM_SETUP.md` - Comprehensive setup guide
- `docker-compose.cpu.yml` - CPU-only configuration
- `test_llm_setup.sh` - Automated testing script
- `MIGRATION_LM_STUDIO_TO_VLLM.md` - Migration documentation
- Updated `README.md` with new quick start

### 5. **Updated Code**
- `app/config.py` - Comment update
- `app/agents/threat_enrichment_agent.py` - Comment update
- `app/tools/wildbox_client.py` - Added retry logic

---

## 🚀 Quick Start

### GPU Setup (Recommended)
```bash
# Start all services
docker-compose up -d

# Monitor LLM startup (downloads ~1GB model on first run)
docker-compose logs -f llm

# Test the setup
./open-security-agents/test_llm_setup.sh
```

### CPU-Only Setup (No GPU)
```bash
# Use CPU override configuration
docker-compose -f docker-compose.yml -f open-security-agents/docker-compose.cpu.yml up -d
```

---

## 📊 Key Improvements

| Aspect | Before (LM Studio) | After (vLLM) |
|--------|-------------------|--------------|
| **Setup** | Manual installation | `docker-compose up` |
| **Portability** | macOS only (MLX) | Linux/macOS/Windows |
| **Networking** | Host-based | Container network |
| **GPU** | Apple Silicon | NVIDIA CUDA + CPU fallback |
| **Model Size** | 3B params | 0.5B params (faster) |
| **Dependencies** | External app | Self-contained |
| **First Run** | Pre-configured | Auto-download model |

---

## 📁 Files Modified

### Main Repository
- ✏️ `docker-compose.yml` - Added LLM service, updated agents config
- ✏️ `open-security-agents/app/config.py`
- ✏️ `open-security-agents/app/agents/threat_enrichment_agent.py`
- ✏️ `open-security-agents/app/tools/wildbox_client.py`

### Agents Service
- ✏️ `docker-compose.yml` - Added LLM service for standalone mode
- ✏️ `README.md` - Updated with local LLM info
- ➕ `LLM_SETUP.md` - New comprehensive guide
- ➕ `docker-compose.cpu.yml` - New CPU configuration
- ➕ `test_llm_setup.sh` - New test script
- ➕ `MIGRATION_LM_STUDIO_TO_VLLM.md` - New migration doc

---

## 🧪 Testing

Run the automated test:
```bash
cd /Users/fab/GitHub/wildbox/open-security-agents
./test_llm_setup.sh
```

Manual test:
```bash
# Test LLM directly
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer wildbox-local-llm" \
  -d '{"model":"qwen3-0.6b","messages":[{"role":"user","content":"test"}]}'

# Submit IOC analysis
curl -X POST http://localhost:8006/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "ipv4", "value": "8.8.8.8"}}'
```

---

## 🎯 Next Steps

1. **Start the services:**
   ```bash
   docker-compose down
   docker-compose up -d
   ```

2. **Verify LLM startup:**
   ```bash
   docker-compose logs -f llm
   # Wait for: "Application startup complete"
   ```

3. **Run tests:**
   ```bash
   ./open-security-agents/test_llm_setup.sh
   ```

4. **Submit first analysis:**
   ```bash
   curl -X POST http://localhost:8006/v1/analyze \
     -H "Content-Type: application/json" \
     -d '{"ioc": {"type": "ipv4", "value": "1.1.1.1"}, "priority": "high"}'
   ```

---

## 💡 Tips

- **First run takes longer** (~60-90s) while downloading the 1GB model
- **GPU recommended** for best performance (15-20 tokens/sec vs 2-5 on CPU)
- **Model cached** in Docker volume `llm_cache` - persists across restarts
- **CPU mode works** but expect 5-10x slower inference
- **Switch to OpenAI API** anytime by setting `OPENAI_BASE_URL=` (empty)

---

## 📚 Documentation

- **Setup Guide:** `open-security-agents/LLM_SETUP.md`
- **Migration Guide:** `open-security-agents/MIGRATION_LM_STUDIO_TO_VLLM.md`
- **Test Script:** `open-security-agents/test_llm_setup.sh`
- **CPU Config:** `open-security-agents/docker-compose.cpu.yml`

---

## 🔧 Troubleshooting

**LLM container won't start:**
```bash
# Check if GPU available
docker run --rm --gpus all nvidia/cuda:11.8.0-base-ubuntu22.04 nvidia-smi

# If no GPU, use CPU mode
docker-compose -f docker-compose.yml -f open-security-agents/docker-compose.cpu.yml up -d
```

**Model download fails:**
```bash
# Check logs
docker-compose logs llm

# May need Hugging Face token for some models
# Add to docker-compose.yml:
#   environment:
#     - HF_TOKEN=hf_your_token_here
```

**Out of memory:**
```bash
# Use smaller max_model_len
# Edit docker-compose.yml:
#   --max-model-len 2048  # instead of 4096
```

---

**Migration Status:** ✅ Complete  
**Ready for Testing:** ✅ Yes  
**Production Ready:** ⚠️ Requires GPU testing
