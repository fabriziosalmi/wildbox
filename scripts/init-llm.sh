#!/bin/bash
# Initialize Ollama with Qwen2.5:0.5b model

set -e

echo "🤖 Initializing Ollama LLM..."

# Wait for Ollama to be ready
echo "Waiting for Ollama service..."
for i in {1..30}; do
    if curl -sf http://localhost:11434/ > /dev/null 2>&1; then
        echo "✓ Ollama is ready"
        break
    fi
    sleep 2
done

# Pull the model (only ~300MB!)
echo "Pulling qwen2.5:0.5b model (~300MB)..."
docker-compose exec llm ollama pull qwen2.5:0.5b

echo "✓ Model ready!"
echo ""
echo "Test the LLM:"
echo "  curl http://localhost:8080/v1/chat/completions \\"
echo "    -H 'Authorization: Bearer ollama' \\"
echo "    -d '{\"model\":\"qwen2.5:0.5b\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'"
