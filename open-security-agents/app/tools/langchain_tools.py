"""
LangChain tools for the Threat Enrichment Agent

These tools provide the AI agent with access to security analysis capabilities.
Each tool has a clear description that helps the AI understand when and how to use it.
"""

import json
import logging
from typing import Any, Dict
from langchain.tools import tool

from .wildbox_client import wildbox_client

logger = logging.getLogger(__name__)


@tool
async def port_scan_tool(ip_address: str) -> str:
    """
    Runs a network port scan against the provided IP address to identify open ports and running services.
    Use this to understand the attack surface of a host and identify potentially vulnerable services.
    
    Args:
        ip_address: The IP address to scan (e.g., "192.168.1.1")
    
    Returns:
        JSON string containing open ports, services, and service versions
    """
    try:
        result = await wildbox_client.port_scan(ip_address)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Port scan tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def whois_lookup_tool(target: str) -> str:
    """
    Performs a WHOIS lookup on a domain or IP address to find registration details,
    such as the owner, creation date, expiration date, and registrar information.
    Useful for assessing the legitimacy and age of a domain or identifying the owner of an IP block.
    
    Args:
        target: Domain name or IP address (e.g., "example.com" or "8.8.8.8")
    
    Returns:
        JSON string containing WHOIS registration data
    """
    try:
        result = await wildbox_client.whois_lookup(target)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"WHOIS lookup tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def reputation_check_tool(ioc_value: str, sources: str = "virustotal,abuseipdb,urlvoid") -> str:
    """
    Checks the reputation of an IOC (IP, domain, URL, or hash) across multiple threat intelligence sources.
    This is essential for determining if an indicator is known to be malicious.
    
    Args:
        ioc_value: The indicator to check (IP, domain, URL, or file hash)
        sources: Comma-separated list of sources to check (default: "virustotal,abuseipdb,urlvoid")
    
    Returns:
        JSON string containing reputation scores and detections from each source
    """
    try:
        source_list = [s.strip() for s in sources.split(",")]
        result = await wildbox_client.get_reputation(ioc_value, source_list)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Reputation check tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def dns_lookup_tool(domain: str, record_type: str = "A") -> str:
    """
    Performs DNS lookups to resolve domain names and analyze DNS records.
    Use this to find IP addresses, mail servers, text records, and other DNS information.
    
    Args:
        domain: Domain name to lookup (e.g., "example.com")
        record_type: DNS record type to query (A, AAAA, MX, TXT, NS, CNAME, etc.)
    
    Returns:
        JSON string containing DNS resolution results
    """
    try:
        result = await wildbox_client.dns_lookup(domain, record_type)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"DNS lookup tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def url_analysis_tool(url: str, take_screenshot: str = "true") -> str:
    """
    Analyzes a URL by visiting it and checking for malicious content, redirects, and suspicious behavior.
    Can also take screenshots to identify phishing pages or malicious content.
    
    Args:
        url: The URL to analyze (must include protocol, e.g., "https://example.com")
        take_screenshot: Whether to take a screenshot ("true" or "false")
    
    Returns:
        JSON string containing URL analysis results, redirects, and screenshot data
    """
    try:
        screenshot = take_screenshot.lower() == "true"
        result = await wildbox_client.url_analysis(url, screenshot)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"URL analysis tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def hash_lookup_tool(hash_value: str) -> str:
    """
    Looks up file hash reputation in threat intelligence databases to determine if a file is malicious.
    Supports MD5, SHA1, and SHA256 hashes.
    
    Args:
        hash_value: File hash to lookup (MD5, SHA1, or SHA256)
    
    Returns:
        JSON string containing hash reputation and malware family information
    """
    try:
        result = await wildbox_client.hash_lookup(hash_value)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Hash lookup tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def geolocation_lookup_tool(ip_address: str) -> str:
    """
    Gets geolocation information for an IP address, including country, city, ISP, and organization.
    Useful for understanding the origin of network traffic and identifying suspicious locations.
    
    Args:
        ip_address: IP address to geolocate (e.g., "8.8.8.8")
    
    Returns:
        JSON string containing geolocation data including country, city, ISP, and coordinates
    """
    try:
        result = await wildbox_client.geolocation_lookup(ip_address)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Geolocation lookup tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def threat_intel_query_tool(ioc_value: str, ioc_type: str = "") -> str:
    """
    Queries the internal threat intelligence data lake for historical data about an IOC.
    This can reveal past incidents, related indicators, and context from previous investigations.
    
    Args:
        ioc_value: The indicator to search for
        ioc_type: Optional IOC type filter (ip, domain, url, hash, email)
    
    Returns:
        JSON string containing historical threat intelligence data
    """
    try:
        result = await wildbox_client.query_data_lake(ioc_value, ioc_type if ioc_type else None)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Threat intel query tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def vulnerability_search_tool(query: str) -> str:
    """
    Searches vulnerability databases for CVEs, security advisories, and exploit information.
    Use this when analyzing services or software versions found during reconnaissance.
    
    Args:
        query: Search query (CVE ID, software name, version, etc.)
    
    Returns:
        JSON string containing vulnerability information and severity scores
    """
    try:
        result = await wildbox_client.check_vulnerability_db(query)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Vulnerability search tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


# Export all tools for the agent
ALL_TOOLS = [
    port_scan_tool,
    whois_lookup_tool,
    reputation_check_tool,
    dns_lookup_tool,
    url_analysis_tool,
    hash_lookup_tool,
    geolocation_lookup_tool,
    threat_intel_query_tool,
    vulnerability_search_tool
]
