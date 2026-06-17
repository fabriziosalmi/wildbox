"""
Threat Enrichment Agent using LangChain

This is the core AI agent that conducts intelligent threat analysis of IOCs.
It uses a combination of LLM reasoning and security tools to generate comprehensive reports.
"""

import json
import logging
import re
import sys
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Literal

from langchain_anthropic import ChatAnthropic
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.schema.messages import SystemMessage
from pydantic import BaseModel, Field

from ..config import settings
from ..tools.langchain_tools import ALL_TOOLS


class _ReportEvidence(BaseModel):
    """A single evidence item the model must ground in a tool output."""
    source: str = Field(description="The tool the finding came from (e.g. whois_lookup)")
    finding: str = Field(description="A specific, factual finding taken from that tool's output")
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="Severity of this individual finding"
    )


class _StructuredReport(BaseModel):
    """Schema Claude fills via structured output — the real threat report."""
    verdict: Literal["Malicious", "Suspicious", "Benign", "Informational"] = Field(
        description="Overall threat assessment of the indicator"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="How conclusive the evidence is, 0.0-1.0. Low when tools failed "
                    "or findings were inconclusive; high only when corroborated.",
    )
    executive_summary: str = Field(
        description="2-4 sentences: what was found and why it leads to the verdict"
    )
    evidence: List[_ReportEvidence] = Field(
        default_factory=list,
        description="Concrete findings from the tool outputs that justify the verdict",
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Concrete next steps for a SOC analyst, derived from the findings",
    )

# Circuit breaker for Anthropic API resilience
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'open-security-shared'))
try:
    from circuit_breaker import CircuitBreaker, CircuitBreakerError
    LLM_BREAKER = CircuitBreaker(
        name="anthropic_agent",
        failure_threshold=3,
        timeout=120,
        recovery_timeout=60,
    )
except ImportError:
    LLM_BREAKER = None
    CircuitBreakerError = Exception

logger = logging.getLogger(__name__)


class ThreatEnrichmentAgent:
    """
    AI-powered threat enrichment agent
    
    This agent uses Claude and security tools to analyze IOCs and generate
    comprehensive threat intelligence reports.
    """

    def __init__(self):
        self.llm = self._initialize_llm()
        self.tools = ALL_TOOLS
        self.agent_executor = self._create_agent()

    def _initialize_llm(self) -> ChatAnthropic:
        """Initialize the Claude (Anthropic) LLM"""
        return ChatAnthropic(
            model=settings.anthropic_model,
            temperature=settings.anthropic_temperature,
            max_tokens=settings.anthropic_max_tokens,
            anthropic_api_key=settings.anthropic_api_key,
            streaming=False,
        )
    
    def _create_agent(self) -> AgentExecutor:
        """Create the LangChain agent with tools and prompt"""
        
        # Main system prompt for the agent
        system_prompt = """You are 'Wildbox AI Analyst', a world-class cybersecurity threat intelligence analyst with decades of experience. Your mission is to conduct comprehensive investigations of Indicators of Compromise (IOCs) using available security tools.

INVESTIGATION METHODOLOGY:
1. Always start by identifying the IOC type and selecting appropriate initial tools
2. Use tools in a logical progression - start with basic lookups, then deeper analysis
3. Correlate findings across multiple tools to form a complete picture
4. Never make assumptions - base all conclusions on actual tool outputs
5. Be thorough but efficient - use only tools that provide valuable insights

ANALYSIS GUIDELINES:
- For IP addresses: Check reputation, geolocation, port scans, WHOIS, and threat intel
- For domains: Check reputation, DNS records, WHOIS, and historical data
- For URLs: Analyze the URL, check reputation, and examine the domain
- For hashes: Check reputation and malware databases
- For emails: Analyze the domain portion and check reputation

IMPORTANT RULES:
- State facts, not opinions
- Cite specific tool outputs as evidence
- If a tool fails, acknowledge it and continue with other tools
- Look for patterns and correlations in the data
- Consider both positive and negative findings (absence of malicious indicators is also valuable)

Your final assessment should be one of: Malicious, Suspicious, Benign, or Informational.

CURRENT INVESTIGATION TARGET: {input}

Begin your investigation by thinking through your approach, then systematically use the available tools."""

        # Create the prompt template
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=system_prompt),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad")
        ])
        
        # Create the agent (provider-agnostic tool-calling agent — works with Claude)
        agent = create_tool_calling_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=prompt
        )
        
        # Create agent executor with configuration
        return AgentExecutor(
            agent=agent,
            tools=self.tools,
            verbose=False,
            handle_parsing_errors=True,
            max_iterations=15,  # Prevent infinite loops
            max_execution_time=settings.max_analysis_time_minutes * 60,
            return_intermediate_steps=True
        )
    
    async def analyze_ioc(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze an IOC and return comprehensive results
        
        Args:
            ioc: Dictionary containing 'type' and 'value' keys
            
        Returns:
            Dictionary containing analysis results
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            # Sanitize IOC value to prevent prompt injection
            import re
            ioc_type = re.sub(r'[^a-zA-Z0-9_-]', '', str(ioc['type']))[:50]
            ioc_value = re.sub(r'[^\w.:\-/@\[\]%]', '', str(ioc['value']))[:500]
            logger.info(f"Starting analysis of {ioc_type} IOC: {ioc_value}")

            # Prepare input for the agent
            input_text = f"Please investigate this {ioc_type} IOC: {ioc_value}"
            
            # Execute the agent (protected by circuit breaker)
            if LLM_BREAKER is not None:
                result = await LLM_BREAKER.call(
                    self.agent_executor.ainvoke, {"input": input_text}
                )
            else:
                result = await self.agent_executor.ainvoke({"input": input_text})
            
            # Extract the agent's analysis
            agent_output = result.get("output", "")
            intermediate_steps = result.get("intermediate_steps", [])
            
            # Calculate analysis duration
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            # Extract tools used
            tools_used = []
            raw_tool_data = {}
            
            for step in intermediate_steps:
                if len(step) >= 2:
                    action = step[0]
                    tool_result = step[1]
                    
                    if hasattr(action, 'tool'):
                        tool_name = action.tool
                        tools_used.append(tool_name)
                        raw_tool_data[tool_name] = tool_result
            
            # Generate structured report using a second LLM call
            structured_result = await self._generate_structured_report(
                ioc, agent_output, raw_tool_data, tools_used, duration
            )
            
            logger.info(f"Completed analysis of {ioc['value']} in {duration:.1f}s")
            return structured_result
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error analyzing IOC {ioc['value']}: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return {
                "task_id": None,  # Will be set by caller
                "ioc": ioc,
                "verdict": "Informational",
                "confidence": 0.0,
                "executive_summary": "Analysis could not be completed. Please retry or contact support.",
                "evidence": [],
                "recommended_actions": ["Retry analysis"],
                "full_report": "# Analysis Error\n\nThe analysis could not be completed. Please retry or contact support.",
                "analysis_duration": duration,
                "tools_used": []
            }
    
    async def _generate_structured_report(
        self, 
        ioc: Dict[str, Any], 
        raw_analysis: str, 
        tool_data: Dict[str, Any],
        tools_used: List[str],
        duration: float
    ) -> Dict[str, Any]:
        """
        Turn the agent's investigation into a structured threat report.

        Uses Claude structured output so the verdict, confidence, evidence and
        recommended actions are derived from the actual tool findings — not
        hardcoded. (Previously these were stubbed for a tiny local model.)
        """
        tool_findings = self._summarize_tool_outputs(tool_data)

        report_prompt = (
            f"Indicator under investigation: {ioc.get('type')} = {ioc.get('value')}\n\n"
            f"Investigation notes from the analyst agent:\n{raw_analysis[:4000]}\n\n"
            f"Raw tool outputs:\n{tool_findings}\n\n"
            "Produce the structured threat report. Base the verdict, confidence and "
            "every piece of evidence ONLY on the investigation notes and tool outputs "
            "above — never invent findings. Confidence must reflect how conclusive the "
            "evidence is (low when tools failed or were inconclusive, high only when "
            "multiple sources corroborate). Each evidence item must name the specific "
            "tool (source) and state the concrete finding. Recommended actions must be "
            "concrete next steps for a SOC analyst."
        )

        try:
            structured_llm = self.llm.with_structured_output(_StructuredReport)
            report: _StructuredReport = await structured_llm.ainvoke([
                SystemMessage(content=(
                    "You are a senior cybersecurity threat intelligence analyst. "
                    "Produce precise, evidence-grounded threat reports."
                )),
                ("human", report_prompt),
            ])

            evidence = [e.model_dump() for e in report.evidence]
            return {
                "task_id": None,  # Will be set by caller
                "ioc": ioc,
                "verdict": report.verdict,
                "confidence": float(report.confidence),
                "executive_summary": report.executive_summary,
                "evidence": evidence,
                "recommended_actions": report.recommended_actions,
                "full_report": self._render_markdown(
                    ioc, report.verdict, report.confidence, report.executive_summary,
                    evidence, report.recommended_actions, tools_used, raw_analysis,
                ),
                "raw_data": tool_data,
                "analysis_duration": duration,
                "tools_used": tools_used,
            }

        except Exception as e:
            # Structured output is best-effort; on failure fall back to a verdict
            # parsed from the agent's own narrative rather than a fixed value.
            logger.error(f"Structured report generation failed, using fallback: {e}")
            verdict = self._verdict_from_text(raw_analysis)
            return {
                "task_id": None,
                "ioc": ioc,
                "verdict": verdict,
                "confidence": 0.3,  # low — structured analysis did not complete
                "executive_summary": (
                    f"Investigation ran {len(tools_used)} tool(s); structured report "
                    f"generation failed, verdict inferred from the analyst narrative."
                ),
                "evidence": [
                    {"source": t, "finding": "Tool was executed during the investigation.",
                     "severity": "low"}
                    for t in tools_used
                ],
                "recommended_actions": ["Re-run the analysis", "Review the raw investigation notes"],
                "full_report": (
                    f"# Threat Analysis Report\n\n## Executive Summary\n"
                    f"Analysis ran with {len(tools_used)} tool(s) (structured report failed).\n\n"
                    f"## Raw Analysis\n{raw_analysis}"
                ),
                "raw_data": tool_data,
                "analysis_duration": duration,
                "tools_used": tools_used,
            }

    @staticmethod
    def _summarize_tool_outputs(tool_data: Dict[str, Any], per_tool_limit: int = 1500) -> str:
        """Render the raw tool outputs into a compact, bounded text block for the model."""
        if not tool_data:
            return "(no tools produced output)"
        parts = []
        for tool_name, tool_result in tool_data.items():
            text = tool_result if isinstance(tool_result, str) else json.dumps(tool_result, default=str)
            parts.append(f"### {tool_name}\n{text[:per_tool_limit]}")
        return "\n\n".join(parts)

    @staticmethod
    def _verdict_from_text(text: str) -> str:
        """Best-effort verdict extraction from free text (fallback only)."""
        m = re.search(r'\b(Malicious|Suspicious|Benign|Informational)\b', text or "", re.IGNORECASE)
        return m.group(1).capitalize() if m else "Informational"

    @staticmethod
    def _render_markdown(ioc, verdict, confidence, summary, evidence, actions, tools_used, raw_analysis) -> str:
        """Render the structured report as a human-readable markdown document."""
        lines = [
            f"# Threat Analysis Report",
            f"\n**Indicator:** `{ioc.get('value')}` ({ioc.get('type')})",
            f"**Verdict:** {verdict}  •  **Confidence:** {confidence:.0%}",
            f"\n## Executive Summary\n{summary}",
        ]
        if evidence:
            lines.append("\n## Evidence")
            for e in evidence:
                lines.append(f"- **[{e['severity']}] {e['source']}** — {e['finding']}")
        if actions:
            lines.append("\n## Recommended Actions")
            lines.extend(f"- {a}" for a in actions)
        lines.append(f"\n## Tools Used\n{', '.join(tools_used) if tools_used else 'none'}")
        lines.append(f"\n## Analyst Notes\n{raw_analysis}")
        return "\n".join(lines)


# Lazily-built agent instance: constructing it builds the LLM + agent graph
# (which needs ANTHROPIC_API_KEY), so defer until first use. This lets the worker
# import without the key set instead of crash-looping at import.
_agent_instance = None


def get_threat_enrichment_agent() -> ThreatEnrichmentAgent:
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = ThreatEnrichmentAgent()
    return _agent_instance
