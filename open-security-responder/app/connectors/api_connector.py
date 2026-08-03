"""
API connector for Open Security Responder

Provides integration with the Open Security API service for tool execution.
"""

import httpx
from typing import Dict, Any
from datetime import datetime

from .base import BaseConnector, ConnectorError
from ..config import settings


class ApiConnector(BaseConnector):
    """Connector for Open Security API service operations"""
    
    def __init__(self):
        super().__init__("api", {"api_url": settings.wildbox_api_url})
        self.client = httpx.Client(timeout=60.0)  # Longer timeout for tool execution
        self.logger.info("Initialized API connector")
    
    def get_available_actions(self) -> Dict[str, str]:
        """Get available actions for the API connector"""
        return {
            "run_tool": "Execute a security tool",
            "list_tools": "List available security tools",
            "get_tool_info": "Get information about a specific tool",
            "cancel_execution": "Cancel a running tool execution",
            "get_execution_status": "Get status of a tool execution"
        }
    
    def run_tool(self, tool_name: str, params: Dict[str, Any], async_execution: bool = False) -> Dict[str, Any]:
        """
        Execute a security tool
        
        Args:
            tool_name: Name of the tool to execute
            params: Parameters for the tool
            async_execution: Whether to execute asynchronously
            
        Returns:
            Tool execution results
        """
        try:
            url = f"{self.config['api_url']}/api/v1/tools/{tool_name}/execute"
            payload = {
                "params": params,
                "async": async_execution,
                "source": "responder",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Executing tool '{tool_name}'")
            response = self.client.post(url, json=payload)
            
            # Handle different response codes
            if response.status_code == 202:  # Accepted for async execution
                result = response.json()
                self.logger.info(f"Tool '{tool_name}' execution started asynchronously")
                return result
            elif response.status_code == 200:  # Completed synchronously
                result = response.json()
                self.logger.info(f"Tool '{tool_name}' completed successfully")
                return result
            else:
                response.raise_for_status()
                
        except httpx.HTTPError as e:
            error_msg = f"HTTP error executing tool '{tool_name}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            error_msg = f"Failed to execute tool '{tool_name}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def list_tools(self) -> Dict[str, Any]:
        """
        List available security tools
        
        Returns:
            List of available tools
        """
        try:
            url = f"{self.config['api_url']}/api/v1/tools"
            
            self.logger.info("Listing available tools")
            response = self.client.get(url)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Found {len(result.get('tools', []))} available tools")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error listing tools: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            error_msg = f"Failed to list tools: {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def get_tool_info(self, tool_name: str) -> Dict[str, Any]:
        """
        Get information about a specific tool
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool information
        """
        try:
            url = f"{self.config['api_url']}/api/v1/tools/{tool_name}"
            
            self.logger.info(f"Getting info for tool '{tool_name}'")
            response = self.client.get(url)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Retrieved info for tool '{tool_name}'")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error getting tool info for '{tool_name}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            error_msg = f"Failed to get tool info for '{tool_name}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def cancel_execution(self, execution_id: str) -> Dict[str, Any]:
        """
        Cancel a running tool execution
        
        Args:
            execution_id: ID of the execution to cancel
            
        Returns:
            Cancellation result
        """
        try:
            url = f"{self.config['api_url']}/api/v1/executions/{execution_id}/cancel"
            
            self.logger.info(f"Cancelling execution '{execution_id}'")
            response = self.client.post(url)
            response.raise_for_status()
            
            result = response.json()
            self.logger.info(f"Execution '{execution_id}' cancelled")
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error cancelling execution '{execution_id}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            error_msg = f"Failed to cancel execution '{execution_id}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def get_execution_status(self, execution_id: str) -> Dict[str, Any]:
        """
        Get status of a tool execution
        
        Args:
            execution_id: ID of the execution
            
        Returns:
            Execution status
        """
        try:
            url = f"{self.config['api_url']}/api/v1/executions/{execution_id}"
            
            self.logger.info(f"Getting status for execution '{execution_id}'")
            response = self.client.get(url)
            response.raise_for_status()
            
            result = response.json()
            return result
            
        except httpx.HTTPError as e:
            error_msg = f"HTTP error getting execution status for '{execution_id}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            error_msg = f"Failed to get execution status for '{execution_id}': {str(e)}"
            self.logger.error(error_msg)
            raise ConnectorError(error_msg)
    
    def __del__(self):
        """Cleanup HTTP client"""
        if hasattr(self, 'client'):
            self.client.close()
