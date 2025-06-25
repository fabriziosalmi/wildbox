"""
Threat Enrichment Agent using LangChain

This is the core AI agent that conducts intelligent threat analysis of IOCs.
It uses a combination of LLM reasoning and security tools to generate comprehensive reports.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from langchain_openai import ChatOpenAI
from langchain.agents import create_openai_tools_agent, AgentExecutor
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.schema.messages import SystemMessage

from ..config import settings
from ..tools.langchain_tools import ALL_TOOLS

logger = logging.getLogger(__name__)


class ThreatEnrichmentAgent:
    """
    AI-powered threat enrichment agent
    
    This agent uses GPT-4o and security tools to analyze IOCs and generate
    comprehensive threat intelligence reports.
    """
    
    def __init__(self):
        self.llm = self._initialize_llm()
        self.tools = ALL_TOOLS
        self.agent_executor = self._create_agent()
    
    def _initialize_llm(self) -> ChatOpenAI:
        """Initialize the OpenAI LLM"""
        return ChatOpenAI(
            model=settings.openai_model,
            temperature=settings.openai_temperature,
            openai_api_key=settings.openai_api_key,
            streaming=False
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
        
        # Create the agent
        agent = create_openai_tools_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=prompt
        )
        
        # Create agent executor with configuration
        return AgentExecutor(
            agent=agent,
            tools=self.tools,
            verbose=True,
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
            logger.info(f"Starting analysis of {ioc['type']} IOC: {ioc['value']}")
            
            # Prepare input for the agent
            input_text = f"Please investigate this {ioc['type']} IOC: {ioc['value']}"
            
            # Execute the agent
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
            
        except Exception as e:
            logger.error(f"Error analyzing IOC {ioc['value']}: {e}")
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return {
                "task_id": None,  # Will be set by caller
                "ioc": ioc,
                "verdict": "Informational",
                "confidence": 0.0,
                "executive_summary": f"Analysis failed due to error: {str(e)}",
                "evidence": [],
                "recommended_actions": ["Retry analysis", "Check system logs"],
                "full_report": f"# Analysis Error\n\nThe analysis could not be completed due to an error:\n\n```\n{str(e)}\n```",
                "raw_data": {},
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
        Generate a structured report from the raw agent analysis
        
        This uses a second LLM call to create a properly formatted report.
        """
        
        # Prompt for structured report generation
        report_prompt = f"""Based on the following threat intelligence investigation, create a structured analysis report.

ORIGINAL IOC: {ioc['type']} - {ioc['value']}
TOOLS USED: {', '.join(tools_used)}
ANALYSIS DURATION: {duration:.1f} seconds

RAW INVESTIGATION OUTPUT:
{raw_analysis}

Create a JSON response with the following structure:
{{
    "verdict": "Malicious|Suspicious|Benign|Informational",
    "confidence": 0.0-1.0,
    "executive_summary": "2-3 sentence summary",
    "evidence": [
        {{
            "source": "tool_name",
            "finding": "specific finding",
            "severity": "low|medium|high|critical"
        }}
    ],
    "recommended_actions": ["action1", "action2"],
    "full_report_markdown": "Complete markdown report with sections"
}}

GUIDELINES:
- Base verdict on actual findings, not speculation
- Confidence should reflect certainty of assessment
- Evidence should cite specific tool outputs
- Recommended actions should be practical and specific
- Full report should be professional and comprehensive in Markdown format

Respond ONLY with valid JSON."""

        try:
            # Use a simpler LLM call for report generation
            response = await self.llm.ainvoke([
                SystemMessage(content="You are a cybersecurity analyst creating structured threat reports. Respond only with valid JSON."),
                ("human", report_prompt)
            ])
            
            # Parse the JSON response
            import json
            structured_data = json.loads(response.content)
            
            # Build final result
            result = {
                "task_id": None,  # Will be set by caller
                "ioc": ioc,
                "verdict": structured_data.get("verdict", "Informational"),
                "confidence": float(structured_data.get("confidence", 0.5)),
                "executive_summary": structured_data.get("executive_summary", "Analysis completed"),
                "evidence": structured_data.get("evidence", []),
                "recommended_actions": structured_data.get("recommended_actions", []),
                "full_report": structured_data.get("full_report_markdown", raw_analysis),
                "raw_data": tool_data,
                "analysis_duration": duration,
                "tools_used": tools_used
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error generating structured report: {e}")
            
            # Fallback to basic structured result
            return {
                "task_id": None,
                "ioc": ioc,
                "verdict": "Informational",
                "confidence": 0.5,
                "executive_summary": "Analysis completed but report generation failed",
                "evidence": [
                    {
                        "source": "agent_analysis",
                        "finding": "Raw analysis completed successfully",
                        "severity": "low"
                    }
                ],
                "recommended_actions": ["Review raw analysis output"],
                "full_report": f"# Threat Analysis Report\n\n## Executive Summary\nAnalysis completed with {len(tools_used)} tools.\n\n## Raw Analysis\n{raw_analysis}",
                "raw_data": tool_data,
                "analysis_duration": duration,
                "tools_used": tools_used
            }


# Global agent instance
threat_enrichment_agent = ThreatEnrichmentAgent()
