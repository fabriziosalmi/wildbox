"""
Wildbox API Client for accessing other microservices

Provides authenticated access to the Wildbox security toolkit.
"""

import logging
from typing import Dict, Any, Optional
import httpx

from ..config import settings

logger = logging.getLogger(__name__)


class WildboxAPIClient:
    """Client for interacting with Wildbox microservices"""
    
    # Mapping of internal tool names to actual API endpoints
    # Format: "internal_name": ("api_endpoint", {"param_mapping": "actual_param"})
    TOOL_ENDPOINT_MAP = {
        "whois_lookup": ("whois_lookup", {"target": "domain"}),
        "dns_lookup": ("dns_enumerator", {"domain": "domain"}),
        "geolocation_lookup": ("ip_geolocation", {"ip": "ip_address"}),
        "network_port_scanner": ("network_port_scanner", {"target": "target"}),
        "reputation_check": ("threat_intelligence_aggregator", {"ioc": "ioc_value"}),
        "hash_lookup": ("malware_hash_checker", {"hash": "hash"}),
        "url_analyzer": ("url_analyzer", {"url": "url"}),
    }
    
    def __init__(self):
        self.api_url = settings.wildbox_api_url
        self.data_url = settings.wildbox_data_url
        self.guardian_url = settings.wildbox_guardian_url
        self.responder_url = settings.wildbox_responder_url
        self.api_key = settings.internal_api_key
        
        # HTTP client configuration
        self.timeout = httpx.Timeout(30.0, connect=10.0)
        self.headers = {
            "User-Agent": "Open-Security-Agents/1.0",
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
    
    async def run_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a security tool via Open Security API
        
        Args:
            tool_name: Name of the tool to run (internal name)
            params: Parameters for the tool (using internal param names)
            
        Returns:
            Tool execution results
        """
        try:
            # Get endpoint mapping
            if tool_name not in self.TOOL_ENDPOINT_MAP:
                logger.warning(f"No endpoint mapping for tool '{tool_name}', using default")
                endpoint_name = tool_name
                param_mapping = {}
            else:
                endpoint_name, param_mapping = self.TOOL_ENDPOINT_MAP[tool_name]
            
            # Transform parameters according to mapping
            transformed_params = {}
            for internal_param, value in params.items():
                # Use mapped parameter name if available, otherwise keep original
                actual_param = param_mapping.get(internal_param, internal_param)
                transformed_params[actual_param] = value
            
            # Construct correct API URL (no /run suffix, /api/tools/ base path)
            url = f"{self.api_url}/api/tools/{endpoint_name}"
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                logger.debug(f"Running tool '{endpoint_name}' at {url} with params: {transformed_params}")
                
                response = await client.post(
                    url,
                    json=transformed_params,  # Send params directly, not wrapped
                    headers=self.headers
                )
                response.raise_for_status()
                
                result = response.json()
                logger.debug(f"Tool '{endpoint_name}' completed successfully")
                return result
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error running tool '{tool_name}': {e}")
            return {"error": f"HTTP error: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Error running tool '{tool_name}': {e}")
            return {"error": str(e), "success": False}
    
    async def query_data_lake(self, ioc_value: str, ioc_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Query threat intelligence data lake
        
        Args:
            ioc_value: The IOC value to search for
            ioc_type: Optional IOC type filter
            
        Returns:
            Query results from data lake
        """
        try:
            url = f"{self.data_url}/api/v1/threat-intel/query"
            params = {
                "q": ioc_value,
                "format": "json"
            }
            
            if ioc_type:
                params["type"] = ioc_type
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                logger.debug(f"Querying data lake for IOC: {ioc_value}")
                
                response = await client.get(
                    url,
                    params=params,
                    headers=self.headers
                )
                response.raise_for_status()
                
                result = response.json()
                logger.debug(f"Data lake query for '{ioc_value}' completed")
                return result
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error querying data lake for '{ioc_value}': {e}")
            return {"error": f"HTTP error: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Error querying data lake for '{ioc_value}': {e}")
            return {"error": str(e), "success": False}
    
    async def get_reputation(self, ioc_value: str, sources: Optional[list] = None) -> Dict[str, Any]:
        """
        Get reputation information for an IOC
        
        Args:
            ioc_value: The IOC value to check
            sources: Optional list of specific sources to query
            
        Returns:
            Reputation data
        """
        try:
            params = {
                "ioc": ioc_value,
                "sources": sources or ["virustotal", "abuseipdb", "urlvoid"]
            }
            
            return await self.run_tool("reputation_check", params)
            
        except Exception as e:
            logger.error(f"Error getting reputation for '{ioc_value}': {e}")
            return {"error": str(e), "success": False}
    
    async def port_scan(self, ip_address: str, ports: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform port scan on an IP address
        
        Args:
            ip_address: Target IP address
            ports: Port range to scan (e.g., "1-1000")
            
        Returns:
            Port scan results
        """
        try:
            params = {
                "target": ip_address,
                "ports": ports or "1-1000",
                "scan_type": "tcp"
            }
            
            return await self.run_tool("network_port_scanner", params)
            
        except Exception as e:
            logger.error(f"Error port scanning '{ip_address}': {e}")
            return {"error": str(e), "success": False}
    
    async def whois_lookup(self, target: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup
        
        Args:
            target: Domain or IP address
            
        Returns:
            WHOIS data
        """
        try:
            params = {"target": target}
            return await self.run_tool("whois_lookup", params)
            
        except Exception as e:
            logger.error(f"Error doing WHOIS lookup for '{target}': {e}")
            return {"error": str(e), "success": False}
    
    async def dns_lookup(self, domain: str, record_type: str = "A") -> Dict[str, Any]:
        """
        Perform DNS lookup
        
        Args:
            domain: Domain to lookup
            record_type: DNS record type (A, AAAA, MX, TXT, etc.)
            
        Returns:
            DNS lookup results
        """
        try:
            params = {
                "domain": domain,
                "record_type": record_type
            }
            
            return await self.run_tool("dns_lookup", params)
            
        except Exception as e:
            logger.error(f"Error doing DNS lookup for '{domain}': {e}")
            return {"error": str(e), "success": False}
    
    async def url_analysis(self, url: str, take_screenshot: bool = True) -> Dict[str, Any]:
        """
        Analyze a URL
        
        Args:
            url: URL to analyze
            take_screenshot: Whether to take a screenshot
            
        Returns:
            URL analysis results
        """
        try:
            params = {
                "url": url,
                "screenshot": take_screenshot,
                "check_redirects": True
            }
            
            return await self.run_tool("url_analyzer", params)
            
        except Exception as e:
            logger.error(f"Error analyzing URL '{url}': {e}")
            return {"error": str(e), "success": False}
    
    async def hash_lookup(self, hash_value: str) -> Dict[str, Any]:
        """
        Lookup file hash reputation
        
        Args:
            hash_value: File hash (MD5, SHA1, or SHA256)
            
        Returns:
            Hash reputation data
        """
        try:
            params = {"hash": hash_value}
            return await self.run_tool("hash_lookup", params)
            
        except Exception as e:
            logger.error(f"Error looking up hash '{hash_value}': {e}")
            return {"error": str(e), "success": False}
    
    async def geolocation_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Get geolocation information for an IP
        
        Args:
            ip_address: IP address to locate
            
        Returns:
            Geolocation data
        """
        try:
            params = {"ip": ip_address}
            return await self.run_tool("geolocation_lookup", params)
            
        except Exception as e:
            logger.error(f"Error getting geolocation for '{ip_address}': {e}")
            return {"error": str(e), "success": False}
    
    async def check_vulnerability_db(self, query: str) -> Dict[str, Any]:
        """
        Check vulnerability databases
        
        Args:
            query: Search query (CVE, product name, etc.)
            
        Returns:
            Vulnerability data
        """
        try:
            url = f"{self.guardian_url}/api/v1/vulnerabilities/search"
            params = {"q": query}
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    url,
                    params=params,
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
                
        except Exception as e:
            logger.error(f"Error checking vulnerability DB for '{query}': {e}")
            return {"error": str(e), "success": False}
    
    async def health_check(self) -> Dict[str, str]:
        """
        Check health of all Wildbox services
        
        Returns:
            Health status of each service
        """
        services = {
            "api": self.api_url,
            "data": self.data_url,
            "guardian": self.guardian_url,
            "responder": self.responder_url
        }
        
        health_status = {}
        
        for service_name, service_url in services.items():
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                    response = await client.get(
                        f"{service_url}/health",
                        headers={"X-API-Key": self.api_key}
                    )
                    if response.status_code == 200:
                        health_status[service_name] = "healthy"
                    else:
                        health_status[service_name] = f"unhealthy ({response.status_code})"
                        
            except Exception as e:
                health_status[service_name] = f"error ({str(e)})"
        
        return health_status


# Global client instance
wildbox_client = WildboxAPIClient()
