"""
Wildbox API Client for accessing other microservices

Provides authenticated access to the Wildbox security toolkit.
"""

import asyncio
import logging
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Dict, Iterator, Mapping, Optional
import httpx
from open_security_shared.scopes import AUTH_TYPE_HEADER, AUTH_TYPE_SERVICE

from ..config import settings

logger = logging.getLogger(__name__)

# Identity of the user on whose behalf internal tool calls are made (#175).
#
# A ContextVar, so it follows the task's own context: asyncio tasks (the
# agent's concurrent tool calls go through asyncio.gather) and LangChain's
# run_in_executor (which runs a sync tool under copy_context()) both see the
# value of the context they were started from. That same property is why it
# must be scoped: a Celery worker runs one task after another in the same
# thread, hence the same context, so a value set and never reset is still
# there for the next task (#594). Set it through caller_identity(), which
# validates the caller first and restores the previous value on exit.
_caller_identity: ContextVar[Optional[Dict[str, str]]] = ContextVar(
    "wildbox_caller_identity", default=None
)


class CallerIdentityUnavailable(RuntimeError):
    """An internal call has no caller identity or no gateway secret to send.

    The services the client calls accept gateway-authenticated requests only:
    the caller's X-Wildbox-* identity with the GATEWAY_INTERNAL_SECRET proof
    of origin. There is nothing else to send. The client used to fall back to
    the static INTERNAL_API_KEY as X-API-Key, which the tools service has not
    accepted since #566 (it answers 401), so the fallback only turned a
    configuration error into an unexplained authentication failure (#567).

    Also raised when a task is handed a caller that is missing, or lacks a
    user or team id: such a task must not start, let alone call a tool (#594).
    """


def require_caller_identity(caller: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """Return the identity to forward for ``caller``, or refuse it.

    A complete caller has a non-blank ``user_id`` and ``team_id``; ``role``
    defaults to ``member``. Anything less cannot be forwarded, and is refused
    rather than completed from somewhere else.

    Raises:
        CallerIdentityUnavailable: ``caller`` is missing or incomplete.
    """
    if not isinstance(caller, Mapping):
        raise CallerIdentityUnavailable("the task has no caller identity")
    user_id = str(caller.get("user_id") or "").strip()
    team_id = str(caller.get("team_id") or "").strip()
    missing = [
        name
        for name, value in (("user_id", user_id), ("team_id", team_id))
        if not value
    ]
    if missing:
        raise CallerIdentityUnavailable(
            "the task's caller identity is incomplete: no " + " and no ".join(missing)
        )
    role = str(caller.get("role") or "").strip() or "member"
    return {"user_id": user_id, "team_id": team_id, "role": role}


def set_caller_identity(user_id: str, team_id: str, role: str = "member") -> Token:
    """Make this identity the one internal calls forward, in this context.

    Returns the ContextVar token, to pass to reset_caller_identity() in a
    ``finally``. Prefer caller_identity(), which does both.

    Raises:
        CallerIdentityUnavailable: ``user_id`` or ``team_id`` is blank.
    """
    identity = require_caller_identity(
        {"user_id": user_id, "team_id": team_id, "role": role}
    )
    return _caller_identity.set(identity)


def reset_caller_identity(token: Token) -> None:
    """Restore the identity that was current before set_caller_identity()."""
    _caller_identity.reset(token)


@contextmanager
def caller_identity(caller: Optional[Mapping[str, Any]]) -> Iterator[Dict[str, str]]:
    """Run a block with ``caller`` as the identity its internal calls send.

    The caller is validated before anything is set, so a missing or partial
    caller raises CallerIdentityUnavailable before the block runs. On exit,
    normal or not, the previous identity is restored, so nothing set here is
    visible to whatever runs next in the same context (#594).
    """
    identity = require_caller_identity(caller)
    token = _caller_identity.set(identity)
    try:
        yield identity
    finally:
        _caller_identity.reset(token)


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
        self.gateway_secret = settings.gateway_internal_secret
        if not self.gateway_secret:
            logger.error(
                "GATEWAY_INTERNAL_SECRET is not set: every internal tool call "
                "will fail, because the services accept gateway-authenticated "
                "requests only."
            )

        # HTTP client configuration
        self.timeout = httpx.Timeout(30.0, connect=10.0)

    def _request_headers(self) -> Dict[str, str]:
        """Build auth headers per call.

        Forwards the caller's gateway identity (X-Wildbox-*) with the
        proof-of-origin secret (#175), so downstream services apply the user's
        real team scope and role. Without both there is no way to authenticate,
        and the call fails here, saying which is missing, instead of reaching
        the service and coming back 401.

        Raises:
            CallerIdentityUnavailable: no caller identity was set for this
                task, or GATEWAY_INTERNAL_SECRET is not configured.
        """
        caller = _caller_identity.get()
        missing = []
        if not caller or not caller.get("user_id") or not caller.get("team_id"):
            missing.append("no caller identity was set for this task (set_caller_identity)")
        if not self.gateway_secret:
            missing.append("GATEWAY_INTERNAL_SECRET is not set")
        if missing:
            message = "Cannot authenticate an internal call: " + "; ".join(missing)
            logger.error(message)
            raise CallerIdentityUnavailable(message)
        return {
            "User-Agent": "Open-Security-Agents/1.0",
            "Content-Type": "application/json",
            "X-Wildbox-User-ID": caller["user_id"],
            "X-Wildbox-Team-ID": caller["team_id"],
            "X-Wildbox-Role": caller["role"],
            # What this call is (#637): a Wildbox service acting for the
            # caller, whose own credential the gateway checked on the route
            # that started the analysis. The services refuse a request that
            # needs a scope and does not say what its credential is.
            AUTH_TYPE_HEADER: AUTH_TYPE_SERVICE,
            "X-Gateway-Secret": self.gateway_secret,
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
            # SSRF protection: only call explicitly-allowlisted tool endpoints.
            # An LLM-chosen (or prompt-injected) tool_name must never become a
            # raw URL path component — f"{api_url}/api/tools/{tool_name}" would
            # otherwise let a crafted IOC steer the agent to arbitrary internal
            # paths. Reject anything not in the fixed endpoint map.
            mapping = self.TOOL_ENDPOINT_MAP.get(tool_name)
            if mapping is None:
                logger.warning(f"Rejected unmapped tool '{tool_name}' (not in allowlist)")
                return {"error": f"Unknown tool: {tool_name}", "success": False}
            endpoint_name, param_mapping = mapping
            
            # Transform parameters according to mapping
            transformed_params = {}
            for internal_param, value in params.items():
                # Use mapped parameter name if available, otherwise keep original
                actual_param = param_mapping.get(internal_param, internal_param)
                transformed_params[actual_param] = value
            
            # Construct correct API URL (no /run suffix, /api/tools/ base path)
            url = f"{self.api_url}/api/tools/{endpoint_name}"
            
            # Retry logic with exponential backoff for rate limits
            max_retries = 3
            retry_delay = 1.0  # Start with 1 second
            
            for attempt in range(max_retries + 1):
                try:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        logger.debug(f"Running tool '{endpoint_name}' at {url} (attempt {attempt + 1}/{max_retries + 1})")
                        
                        response = await client.post(
                            url,
                            json=transformed_params,  # Send params directly, not wrapped
                            headers=self._request_headers()
                        )
                        
                        # Handle rate limiting with exponential backoff
                        if response.status_code == 429 and attempt < max_retries:
                            logger.warning(f"Rate limited on tool '{endpoint_name}', retrying in {retry_delay}s")
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 2  # Exponential backoff
                            continue
                        
                        response.raise_for_status()
                        
                        result = response.json()
                        logger.debug(f"Tool '{endpoint_name}' completed successfully")
                        return result
                        
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429 and attempt < max_retries:
                        continue
                    raise
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error running tool '{tool_name}': {e}")
            return {"error": f"HTTP error: {str(e)}", "success": False}
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
                    headers=self._request_headers()
                )
                response.raise_for_status()
                
                result = response.json()
                logger.debug(f"Data lake query for '{ioc_value}' completed")
                return result
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error querying data lake for '{ioc_value}': {e}")
            return {"error": f"HTTP error: {str(e)}", "success": False}
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
                    headers=self._request_headers()
                )
                response.raise_for_status()
                return response.json()
                
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
                    # /health is public on every service, and a health check
                    # runs outside any user's task, so it sends no identity.
                    response = await client.get(
                        f"{service_url}/health",
                        headers={"User-Agent": "Open-Security-Agents/1.0"},
                    )
                    if response.status_code == 200:
                        health_status[service_name] = "healthy"
                    else:
                        health_status[service_name] = f"unhealthy ({response.status_code})"
                        
            except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                health_status[service_name] = f"error ({str(e)})"
        
        return health_status


# Global client instance
wildbox_client = WildboxAPIClient()
