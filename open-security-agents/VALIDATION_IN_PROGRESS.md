# open-security-agents - Validation Report

**Service:** AI-Powered Threat Intelligence Analysis  
**Version:** 0.1.5  
**Validation Date:** 16 November 2025  
**Status:** 🔬 IN PROGRESS

---

## Executive Summary

**Current Assessment:** ⏳ UNDER VALIDATION

Open-security-agents implements an AI-powered threat intelligence enrichment service using GPT-4o and LangChain. This is the "cognitive layer" of Wildbox, designed to autonomously investigate IOCs and generate comprehensive threat analysis reports.

---

## Validation Methodology

### Testing Approach
- **Architecture analysis** (AI agent design, LangChain integration)
- **API functionality testing** (IOC submission, task status, results)
- **AI capabilities validation** (tool selection, reasoning, report generation)
- **Integration testing** (responder playbooks, tools service, data service)
- **Performance & concurrency** (async task handling via Celery)

### Test Environment
```bash
Service: agents (port 8006)
Queue: Redis DB 6 (Celery broker)
Framework: FastAPI + Celery + LangChain
AI Model: GPT-4o (configurable)
Tools Available: TBD (via Wildbox Tool Belt)
```

---

## Investigation Questions

### Q1: Come viene definito un "agente"? È configurabile?

**Initial Findings:**

**Agent Architecture** (`app/agents/threat_enrichment_agent.py`):
```python
class ThreatEnrichmentAgent:
    """
    AI-powered threat enrichment agent using GPT-4o and LangChain
    """
    def __init__(self):
        self.llm = ChatOpenAI(
            model=settings.openai_model,        # GPT-4o by default
            temperature=settings.openai_temperature,  # Configurable
            openai_api_key=settings.openai_api_key
        )
        self.tools = ALL_TOOLS  # Security tools from Wildbox
        self.agent_executor = AgentExecutor(
            agent=agent,
            tools=self.tools,
            max_iterations=15,  # Prevents infinite loops
            max_execution_time=settings.max_analysis_time_minutes * 60
        )
```

**System Prompt** (defines agent behavior):
```
You are 'Wildbox AI Analyst', a world-class cybersecurity threat 
intelligence analyst with decades of experience.

INVESTIGATION METHODOLOGY:
1. Identify IOC type and select appropriate tools
2. Use tools in logical progression
3. Correlate findings across multiple tools
4. Base conclusions on actual tool outputs
5. Be thorough but efficient

ANALYSIS GUIDELINES:
- For IPs: reputation, geolocation, port scans, WHOIS, threat intel
- For domains: reputation, DNS, WHOIS, historical data
- For URLs: URL analysis, reputation, domain examination
- For hashes: reputation, malware databases
- For emails: domain analysis, reputation

Final assessment: Malicious, Suspicious, Benign, or Informational
```

**Configurability:**
- ✅ **AI Model**: `OPENAI_MODEL` env var (default: gpt-4o)
- ✅ **Temperature**: `OPENAI_TEMPERATURE` (controls creativity vs determinism)
- ✅ **Max Iterations**: 15 (hardcoded, prevents runaway agents)
- ✅ **Timeout**: `MAX_ANALYSIS_TIME_MINUTES` env var
- ✅ **System Prompt**: Defined in code (requires code change to modify)
- ❓ **Tool Selection**: Uses ALL_TOOLS (no runtime filtering yet)

**Assessment:** ✅ **Well-Designed** - Agent follows industry-standard LangChain patterns with reasonable constraints.

---

### Q2: Come viene invocato? Tramite un'API REST standard?

**API Endpoint Discovery:**

#### Health Check
```bash
GET /health
Response: {
  "status": "healthy",
  "services": {
    "redis": "healthy",
    "celery": "healthy",
    "openai": "configured"
  }
}
✅ Service operational
```

#### Submit Analysis Task
```bash
POST /v1/analyze
Body: {
  "ioc": {
    "type": "ipv4",  # ipv4, ipv6, domain, url, md5, sha1, sha256, email
    "value": "8.8.8.8"
  },
  "priority": "high"  # low, normal, high
}

Expected Response: {
  "task_id": "abc-123-def",
  "status": "pending",
  "created_at": "2025-11-16T...",
  "result_url": "/v1/analyze/abc-123-def"
}
```

#### Check Task Status
```bash
GET /v1/analyze/{task_id}

Response (pending): {
  "task_id": "abc-123",
  "status": "running",
  "progress": "Performing WHOIS lookup..."
}

Response (completed): {
  "task_id": "abc-123",
  "status": "completed",
  "result": {
    "verdict": "Suspicious",
    "confidence": 75,
    "evidence": [...],
    "markdown_report": "# Threat Analysis Report\n..."
  }
}
```

**Architecture:**
```
Browser/API → FastAPI (port 8006) → Celery Task Queue
                                          ↓
                                    Redis (DB 6)
                                          ↓
                                    Celery Worker
                                          ↓
                                    ThreatEnrichmentAgent
                                          ↓
                                    GPT-4o + Tools
```

**Assessment:** ⏳ **TO BE TESTED** - Standard async REST pattern. Need to verify actual behavior.

---

### Q3: Come gestisce l'input e restituisce l'output?

**Input Schema** (`app/schemas.py`):
```python
class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"

class IOCInput(BaseModel):
    type: IOCType
    value: str  # The IOC to analyze
```

**Output Schema** (expected):
```python
class AnalysisResult(BaseModel):
    task_id: str
    ioc: IOCInput
    verdict: ThreatVerdict  # Malicious, Suspicious, Benign, Informational
    confidence: int  # 0-100
    evidence: List[AnalysisEvidence]
    tools_used: List[str]
    markdown_report: str
    analysis_duration: float
    completed_at: datetime
```

**Processing Flow:**
1. **Input Validation**: Pydantic models ensure type safety
2. **Task Creation**: Celery task queued with unique ID
3. **Agent Execution**: LangChain agent runs with LLM + tools
4. **Intermediate Steps**: Each tool call logged
5. **Report Generation**: Second LLM call structures findings
6. **Result Storage**: Stored in Redis with TTL

**Assessment:** ⏳ **TO BE VERIFIED** - Need to test actual output structure.

---

### Q4: Come si integra con i playbook di responder?

**Expected Integration** (from responder playbooks):

```yaml
# In open-security-responder/playbooks/triage_ip.yml
- name: "ai_analysis"
  action: "wildbox.execute_agent"
  input:
    ioc_type: "ipv4"
    ioc_value: "{{ trigger.ip }}"
```

**Connector Implementation** (expected in responder):
```python
# open-security-responder/app/connectors/wildbox.py
async def execute_agent(self, ioc_type: str, ioc_value: str):
    """Call agents service for AI analysis"""
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"http://agents:8006/v1/analyze",
            json={"ioc": {"type": ioc_type, "value": ioc_value}}
        ) as resp:
            task = await resp.json()
            
        # Poll for completion
        while True:
            async with session.get(
                f"http://agents:8006/v1/analyze/{task['task_id']}"
            ) as resp:
                status = await resp.json()
                if status['status'] in ['completed', 'failed']:
                    return status
            await asyncio.sleep(5)
```

**Integration Points:**
1. **Playbook Step**: Calls agents via wildbox connector
2. **Async Handling**: Responder waits for completion
3. **Result Usage**: AI analysis enriches playbook context
4. **Decision Making**: Verdict influences next steps

**Assessment:** ⏳ **TO BE TESTED** - Need to verify connector exists and integration works.

---

### Q5: Quali sono i modelli AI sottostanti?

**LLM Configuration:**
```python
# Default model
OPENAI_MODEL = "gpt-4o"  # GPT-4 Optimized

# Alternative models supported by LangChain:
# - "gpt-4-turbo"
# - "gpt-3.5-turbo"
# - Local models via Ollama (requires code changes)
```

**LangChain Framework:**
```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_openai_tools_agent, AgentExecutor

# Two-stage AI process:
1. Main Analysis: Agent uses GPT-4o to reason and select tools
2. Report Generation: Second LLM call to structure findings
```

**Tool Integration:**
- **LangChain Tools**: Wraps security tools as LangChain-compatible functions
- **Tool Descriptions**: LLM reads descriptions to decide which tools to use
- **Chain-of-Thought**: Agent explains reasoning before each tool call

**Assessment:** ✅ **STATE-OF-THE-ART** - Uses GPT-4o with LangChain agent framework.

---

## Test Plan

### Phase 1: Basic Functionality
- [ ] Submit IP analysis task
- [ ] Check task status polling
- [ ] Verify completion and result structure
- [ ] Test error handling (invalid IOC)

### Phase 2: AI Capabilities  
- [ ] Verify tool selection logic
- [ ] Analyze agent reasoning quality
- [ ] Test report markdown formatting
- [ ] Validate verdict accuracy

### Phase 3: Integration
- [ ] Test responder playbook integration
- [ ] Verify tools service calls
- [ ] Check data service queries
- [ ] Validate concurrent tasks

### Phase 4: Performance
- [ ] Measure analysis duration
- [ ] Test concurrent task handling
- [ ] Verify Redis result caching
- [ ] Check Celery worker scaling

---

## Next Steps

1. **List available tools** - Discover what security tools the agent can use
2. **Submit test analysis** - Run IP/domain/hash analysis
3. **Analyze agent reasoning** - Review verbose logs and tool selection
4. **Test responder integration** - Verify playbook connector works
5. **Performance testing** - Concurrent task handling

---

**Status:** 🚀 READY TO BEGIN TESTING  
**Next Command:** List available tools and submit first analysis

