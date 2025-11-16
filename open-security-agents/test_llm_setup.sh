#!/bin/bash
# Test script for Local LLM setup

set -e

echo "🧪 Testing Wildbox Local LLM Setup..."
echo "========================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Check if LLM container is running
echo -e "\n${YELLOW}Test 1: LLM Container Status${NC}"
if docker-compose ps llm | grep -q "Up"; then
    echo -e "${GREEN}✓ LLM container is running${NC}"
else
    echo -e "${RED}✗ LLM container is not running${NC}"
    echo "  Start with: docker-compose up -d llm"
    exit 1
fi

# Test 2: Check LLM health endpoint
echo -e "\n${YELLOW}Test 2: LLM Health Check${NC}"
if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ LLM health endpoint responding${NC}"
else
    echo -e "${RED}✗ LLM health endpoint not responding${NC}"
    echo "  Check logs: docker-compose logs llm"
    exit 1
fi

# Test 3: Test LLM inference
echo -e "\n${YELLOW}Test 3: LLM Inference Test${NC}"
RESPONSE=$(curl -s http://localhost:8080/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer wildbox-local-llm" \
    -d '{
        "model": "qwen3-0.6b",
        "messages": [{"role": "user", "content": "Say hello in 3 words"}],
        "max_tokens": 50
    }')

if echo "$RESPONSE" | grep -q "choices"; then
    echo -e "${GREEN}✓ LLM inference working${NC}"
    echo "  Response: $(echo "$RESPONSE" | jq -r '.choices[0].message.content' 2>/dev/null || echo 'OK')"
else
    echo -e "${RED}✗ LLM inference failed${NC}"
    echo "  Response: $RESPONSE"
    exit 1
fi

# Test 4: Check agents service
echo -e "\n${YELLOW}Test 4: Agents Service Status${NC}"
if docker-compose ps agents | grep -q "Up"; then
    echo -e "${GREEN}✓ Agents container is running${NC}"
else
    echo -e "${RED}✗ Agents container is not running${NC}"
    echo "  Start with: docker-compose up -d agents"
    exit 1
fi

# Test 5: Check agents health
echo -e "\n${YELLOW}Test 5: Agents Health Check${NC}"
if curl -sf http://localhost:8006/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Agents health endpoint responding${NC}"
else
    echo -e "${RED}✗ Agents health endpoint not responding${NC}"
    echo "  Check logs: docker-compose logs agents"
    exit 1
fi

# Test 6: Submit test analysis
echo -e "\n${YELLOW}Test 6: IOC Analysis Test${NC}"
TASK_RESPONSE=$(curl -s -X POST http://localhost:8006/v1/analyze \
    -H "Content-Type: application/json" \
    -d '{
        "ioc": {"type": "ipv4", "value": "8.8.8.8"},
        "priority": "normal"
    }')

TASK_ID=$(echo "$TASK_RESPONSE" | jq -r '.task_id' 2>/dev/null)

if [ -n "$TASK_ID" ] && [ "$TASK_ID" != "null" ]; then
    echo -e "${GREEN}✓ Analysis task submitted${NC}"
    echo "  Task ID: $TASK_ID"
    
    # Wait for completion (max 60 seconds)
    echo -e "\n${YELLOW}Waiting for analysis to complete...${NC}"
    for i in {1..12}; do
        sleep 5
        STATUS=$(curl -s http://localhost:8006/v1/analyze/$TASK_ID | jq -r '.status' 2>/dev/null)
        echo "  Status: $STATUS ($((i*5))s)"
        
        if [ "$STATUS" = "completed" ]; then
            echo -e "${GREEN}✓ Analysis completed successfully${NC}"
            
            # Show verdict
            VERDICT=$(curl -s http://localhost:8006/v1/analyze/$TASK_ID | jq -r '.verdict' 2>/dev/null)
            echo "  Verdict: $VERDICT"
            break
        elif [ "$STATUS" = "failed" ]; then
            echo -e "${RED}✗ Analysis failed${NC}"
            break
        fi
    done
else
    echo -e "${RED}✗ Failed to submit analysis task${NC}"
    echo "  Response: $TASK_RESPONSE"
fi

# Summary
echo -e "\n========================================"
echo -e "${GREEN}🎉 Local LLM Setup Tests Complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. View LLM logs: docker-compose logs -f llm"
echo "  2. View agents logs: docker-compose logs -f agents"
echo "  3. Submit analysis: curl -X POST http://localhost:8006/v1/analyze ..."
echo "  4. See LLM_SETUP.md for advanced configuration"
