"""
LangChain tools for the Threat Enrichment Agent

These tools provide the AI agent with access to security analysis capabilities.
Each tool has a clear description that helps the AI understand when and how to use it.

A description is the only thing the model knows about a tool, so each one
says what the service behind it really does, and nothing more. The model was
offered tools that could only fail: the threat-intelligence and vulnerability
tools called routes that do not exist, at an address inside the agents'
own container, and four tools sent the tools service fields it refuses
(#652). Every tool here calls a route that exists with the input it
validates (tests/unit/test_tool_contracts.py), as the user who submitted
the analysis. A tool that cannot be made to do that is taken out of
ALL_TOOLS, not left for the model to call.
"""

import json
import logging
from typing import Any, Dict, Iterable, List
from langchain_core.tools import tool

from .wildbox_client import wildbox_client

logger = logging.getLogger(__name__)


@tool
async def port_scan_tool(ip_address: str) -> str:
    """
    Runs a TCP port scan (ports 1-1000) against an IP address or hostname to identify open ports and services.
    Use this to understand the attack surface of a host. Internal and private addresses are refused.

    Args:
        ip_address: The IP address or hostname to scan (e.g., "203.0.113.10")

    Returns:
        JSON string containing open ports and detected services, or an error
    """
    try:
        result = await wildbox_client.port_scan(ip_address)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Port scan tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def whois_lookup_tool(target: str) -> str:
    """
    Performs a WHOIS lookup on a domain name to find registration details,
    such as the registrant, creation date, expiration date, and registrar.
    Useful for assessing the age and legitimacy of a domain.

    Args:
        target: Domain name (e.g., "example.com")

    Returns:
        JSON string containing WHOIS registration data, or an error
    """
    try:
        result = await wildbox_client.whois_lookup(target)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"WHOIS lookup tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def reputation_check_tool(ioc_value: str, ioc_type: str) -> str:
    """
    Checks an IOC against the threat intelligence sources the tools service aggregates.
    Use this to find out whether an indicator is known to be malicious.

    Args:
        ioc_value: The indicator to check (IP, domain, URL, file hash or email)
        ioc_type: The indicator's type: "ip", "domain", "url", "hash" or "email"

    Returns:
        JSON string containing the aggregated threat score and what each source reported, or an error
    """
    try:
        result = await wildbox_client.get_reputation(ioc_value, ioc_type)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Reputation check tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def dns_lookup_tool(domain: str, record_type: str = "A") -> str:
    """
    Resolves the DNS records of one type for a domain name.
    Use this to find IP addresses, mail servers, name servers and text records.

    Args:
        domain: Domain name to look up (e.g., "example.com")
        record_type: One DNS record type: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR or SRV

    Returns:
        JSON string containing the DNS records found, or an error
    """
    try:
        result = await wildbox_client.dns_lookup(domain, record_type)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"DNS lookup tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def url_analysis_tool(url: str) -> str:
    """
    Follows a URL's redirect chain and reports each hop, the final destination and
    the phishing or malware indicators found along it. It does not render the page
    and takes no screenshot. Internal and private addresses are refused.

    Args:
        url: The URL to analyze (must include the scheme, e.g., "https://example.com/path")

    Returns:
        JSON string containing the redirect chain, the final URL and the security analysis, or an error
    """
    try:
        result = await wildbox_client.url_analysis(url)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"URL analysis tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def hash_lookup_tool(hash_value: str) -> str:
    """
    Looks a file hash up in the malware hash sources of the tools service to determine if a file is known malware.
    Supports MD5, SHA1, SHA256 and SHA512 hashes.

    Args:
        hash_value: File hash to look up

    Returns:
        JSON string containing what each source reported about the hash, or an error
    """
    try:
        result = await wildbox_client.hash_lookup(hash_value)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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
        JSON string containing geolocation data including country, city, ISP, and coordinates, or an error
    """
    try:
        result = await wildbox_client.geolocation_lookup(ip_address)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Geolocation lookup tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def threat_intel_query_tool(ioc_value: str, ioc_type: str = "") -> str:
    """
    Searches the threat indicators Wildbox has collected: the organization's own indicators
    and the threat feeds it ingests. The search matches the text anywhere in an indicator's
    value or description, so results can include related indicators (for example URLs on a
    domain); each result says whether it is an exact match. No result means only that
    Wildbox holds no indicator matching the text, not that the IOC is safe.

    Args:
        ioc_value: The indicator, or part of one, to search for
        ioc_type: Optional type to restrict the search to: "ip", "domain", "url", "hash" or "email"

    Returns:
        JSON string with the total number of matches and up to 25 indicators
        (type, value, threat types, confidence, severity 1-10, first and last seen), or an error
    """
    try:
        result = await wildbox_client.search_threat_intel(ioc_value, ioc_type if ioc_type else None)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Threat intel query tool error: {e}")
        return json.dumps({"error": str(e), "success": False})


@tool
async def vulnerability_search_tool(query: str) -> str:
    """
    Searches the vulnerabilities the organization tracks in Guardian, its vulnerability
    management service: findings recorded against the organization's own assets. The text is
    matched against a finding's title, description, CVE ID and asset name. Use it to check
    whether a host or a CVE under investigation is already a known finding. It is not a
    public CVE or exploit database: no result means only that nothing matching is recorded.

    Args:
        query: Text to search for: a CVE ID, a product name or an asset name

    Returns:
        JSON string with the total number of matches and up to 25 findings
        (title, CVE ID, severity, status, risk score, asset), or an error
    """
    try:
        result = await wildbox_client.search_vulnerabilities(query)
        return json.dumps(result, indent=2)
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
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

# The tools that return data Wildbox holds for the caller's team, as opposed
# to what a lookup of the IOC finds outside. What they return goes to the
# model provider like every tool output, and is in the model's context for
# the rest of the analysis, next to text it read from the internet.
INTERNAL_DATA_TOOLS = ("threat_intel_query_tool", "vulnerability_search_tool")


def enabled_tools(disabled: Iterable[str] = ()) -> List[Any]:
    """The tools the agent offers its model: ALL_TOOLS but ``disabled``.

    ``disabled`` is the operator's AGENT_DISABLED_TOOLS. A tool that is left
    out is not bound to the model, so the model cannot call it.

    Raises:
        ValueError: a name in ``disabled`` is not a tool. Withholding a tool
            is a decision about what the model may read; a typo must not
            leave it offered.
    """
    names = [tool.name for tool in ALL_TOOLS]
    unknown = sorted(set(disabled) - set(names))
    if unknown:
        raise ValueError(
            f"AGENT_DISABLED_TOOLS names no tool of the agent: {', '.join(unknown)}. "
            f"The tools are: {', '.join(names)}"
        )
    return [tool for tool in ALL_TOOLS if tool.name not in set(disabled)]
