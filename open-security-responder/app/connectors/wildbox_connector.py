"""
Wildbox connector for Open Security Responder

Provides integration with other Wildbox microservices.
"""

import httpx
import asyncio
from typing import Dict, Any
from datetime import datetime

from .base import BaseConnector, ConnectorError
from ..config import settings


class WildboxConnector(BaseConnector):
    """Connector for integrating with Wildbox microservices"""
    
    def __init__(self):
        super().__init__("wildbox", {
            "api_url": settings.wildbox_api_url,
            "data_url": settings.wildbox_data_url,
            "guardian_url": settings.wildbox_guardian_url,
            "sensor_url": settings.wildbox_sensor_url,
            "agents_url": settings.wildbox_agents_url
        })
        
        # Initialize HTTP client
        self.client = httpx.Client(timeout=30.0)
        self.logger.info(f"Initialized Wildbox connector with services: {list(self.config.keys())}")
    
    def get_available_actions(self) -> Dict[str, str]:
        """Get available actions for the Wildbox connector"""
        return {
            "run_tool": "Execute a security tool via Open Security API",
            "add_to_blacklist": "Add an IOC to the blacklist via Open Security Data",
            "query_threat_intel": "Query threat intelligence data",
            "isolate_endpoint": "Isolate an endpoint via Open Security Sensor",
            "get_vulnerabilities": "Get vulnerability data from Guardian",
            "create_ticket": "Create a security ticket in Guardian",
            "create_vulnerability": "Create a vulnerability in Guardian",
            "analyze_ioc": "Analyze an IOC using AI-powered Agents service",
            "get_asset_info": "Get asset information from Data service"
        }
    
    def run_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a security tool via Open Security API
        
        Args:
            tool_name: Name of the tool to execute
            params: Parameters for the tool
            
        Returns:
            Tool execution results
        """
        try:
            url = f"{self.config['api_url']}/api/v1/tools/{tool_name}"
            payload = {
                "params": params,
                "async": False,  # Synchronous execution for now
                "source": "responder"
            }
            
            self.logger.info(f"Executing tool '{tool_name}' with params: {params}")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Tool '{tool_name}' completed successfully")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error executing tool '{tool_name}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to execute tool '{tool_name}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def add_to_blacklist(self, ioc: str, ioc_type: str, reason: str, confidence: str = "medium") -> Dict[str, Any]:
        """
        Add an IOC to the blacklist via Open Security Data
        
        Args:
            ioc: The indicator of compromise
            ioc_type: Type of IOC (ip, domain, url, hash, etc.)
            reason: Reason for blacklisting
            confidence: Confidence level (low, medium, high)
            
        Returns:
            Blacklist addition result
        """
        try:
            url = f"{self.config['data_url']}/api/v1/blacklist"
            payload = {
                "ioc": ioc,
                "type": ioc_type,
                "reason": reason,
                "confidence": confidence,
                "source": "responder",
                "created_at": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Adding {ioc_type} '{ioc}' to blacklist")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Successfully added '{ioc}' to blacklist")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error adding '{ioc}' to blacklist: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to add '{ioc}' to blacklist: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def query_threat_intel(self, query: str, source: str = "all") -> Dict[str, Any]:
        """
        Query threat intelligence data
        
        Args:
            query: The query string (IP, domain, hash, etc.)
            source: Specific source to query or "all"
            
        Returns:
            Threat intelligence results
        """
        try:
            url = f"{self.config['data_url']}/api/v1/threat-intel/query"
            params = {
                "q": query,
                "source": source,
                "format": "json"
            }
            
            self.logger.info(f"Querying threat intel for '{query}'")
            response = self.client.get(url, params=params)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Threat intel query for '{query}' completed")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error querying threat intel for '{query}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to query threat intel for '{query}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def isolate_endpoint(self, agent_id: str, reason: str = "Security incident") -> Dict[str, Any]:
        """
        Isolate an endpoint via Open Security Sensor
        
        Args:
            agent_id: ID of the agent/endpoint to isolate
            reason: Reason for isolation
            
        Returns:
            Isolation command result
        """
        try:
            url = f"{self.config['sensor_url']}/api/v1/agents/{agent_id}/actions"
            payload = {
                "action": "isolate",
                "reason": reason,
                "source": "responder",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Isolating endpoint '{agent_id}'")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Endpoint '{agent_id}' isolation initiated")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error isolating endpoint '{agent_id}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to isolate endpoint '{agent_id}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def get_vulnerabilities(self, asset_id: str = None, severity: str = None) -> Dict[str, Any]:
        """
        Get vulnerability data from Guardian
        
        Args:
            asset_id: Specific asset ID to query
            severity: Filter by severity (critical, high, medium, low)
            
        Returns:
            Vulnerability data
        """
        try:
            url = f"{self.config['guardian_url']}/api/v1/vulnerabilities"
            params = {}
            
            if asset_id:
                params["asset_id"] = asset_id
            if severity:
                params["severity"] = severity
            
            self.logger.info(f"Querying vulnerabilities with params: {params}")
            response = self.client.get(url, params=params)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Retrieved {len(result.get('vulnerabilities', []))} vulnerabilities")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error querying vulnerabilities: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to query vulnerabilities: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def create_ticket(self, title: str, description: str, severity: str = "medium") -> Dict[str, Any]:
        """
        Create a security ticket in Guardian
        
        Args:
            title: Ticket title
            description: Ticket description
            severity: Ticket severity
            
        Returns:
            Created ticket information
        """
        try:
            url = f"{self.config['guardian_url']}/api/v1/tickets"
            payload = {
                "title": title,
                "description": description,
                "severity": severity,
                "source": "responder",
                "created_at": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Creating ticket: {title}")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Created ticket with ID: {result.get('id')}")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error creating ticket: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to create ticket: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def get_asset_info(self, asset_id: str) -> Dict[str, Any]:
        """
        Get asset information from Data service
        
        Args:
            asset_id: Asset identifier
            
        Returns:
            Asset information
        """
        try:
            url = f"{self.config['data_url']}/api/v1/assets/{asset_id}"
            
            self.logger.info(f"Getting asset info for '{asset_id}'")
            response = self.client.get(url)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Retrieved asset info for '{asset_id}'")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error getting asset info for '{asset_id}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to get asset info for '{asset_id}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def analyze_ioc(self, ioc_type: str, ioc_value: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze an IOC using AI-powered Agents service
        
        Args:
            ioc_type: Type of IOC (ip, domain, url, hash, email)
            ioc_value: The IOC value to analyze
            context: Additional context for the analysis
            
        Returns:
            AI analysis results with verdict, confidence, and report
        """
        try:
            url = f"{self.config['agents_url']}/v1/analyze"
            payload = {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "context": context or {},
                "source": "responder"
            }
            
            self.logger.info(f"Requesting AI analysis for {ioc_type}: {ioc_value}")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"AI analysis completed with task_id: {result.get('task_id')}")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error requesting AI analysis for '{ioc_value}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to request AI analysis for '{ioc_value}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def create_vulnerability(self, title: str, description: str, severity: str, 
                           asset_name: str = None, cve_id: str = None) -> Dict[str, Any]:
        """
        Create a vulnerability in Guardian service
        
        Args:
            title: Vulnerability title
            description: Detailed description
            severity: Severity level (critical, high, medium, low)
            asset_name: Affected asset name
            cve_id: CVE identifier if applicable
            
        Returns:
            Created vulnerability information
        """
        try:
            url = f"{self.config['guardian_url']}/api/v1/vulnerabilities/"
            payload = {
                "title": title,
                "description": description,
                "severity": severity,
                "asset_name": asset_name or "unknown",
                "asset_type": "server",
                "status": "open",
                "priority": "p1" if severity in ["critical", "high"] else "p2",
                "source": "responder"
            }
            
            if cve_id:
                payload["cve_id"] = cve_id
            
            self.logger.info(f"Creating vulnerability in Guardian: {title}")
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Created vulnerability with ID: {result.get('id')}")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error creating vulnerability: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except Exception as e:
            error_msg = f"Failed to create vulnerability: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def __del__(self):
        """Cleanup HTTP client"""
        if hasattr(self, 'client'):
            self.client.close()
