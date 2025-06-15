"""Subdomain Scanner Tool - Discovers subdomains for a given domain."""

import socket
import asyncio
from datetime import datetime
from typing import List
try:
    from .schemas import SubdomainScannerInput, SubdomainScannerOutput, SubdomainResult
except ImportError:
    from schemas import SubdomainScannerInput, SubdomainScannerOutput, SubdomainResult

# Wordlists for subdomain discovery
SMALL_WORDLIST = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "www1", "email", "img", "www3", "help", "shop", "sql", "secure", "beta", "john", "robert", "www4", "ftp2", "mssql", "ftpd", "www5", "www6", "www7", "www8", "www9", "www10"]

MEDIUM_WORDLIST = SMALL_WORDLIST + ["staging", "api", "cdn", "assets", "static", "images", "videos", "docs", "support", "portal", "dashboard", "app", "mobile", "web", "store", "download", "upload", "media", "content", "files", "data", "backup", "archive", "log", "logs", "monitoring", "stats", "analytics", "reports", "crm", "erp", "intranet", "extranet", "vpn", "remote", "access", "gateway", "proxy", "cache", "load", "balance", "cluster", "node", "server", "host", "service", "micro", "edge", "cloud", "saas", "paas", "iaas"]

LARGE_WORDLIST = MEDIUM_WORDLIST + ["dev", "test", "stage", "prod", "production", "development", "testing", "demo", "preview", "pre", "post", "pre-prod", "uat", "qa", "qc", "integration", "int", "sit", "pit", "performance", "load", "stress", "security", "sec", "pentest", "audit", "compliance", "risk", "governance", "policy", "procedure", "incident", "emergency", "disaster", "recovery", "backup", "restore", "sync", "replica", "mirror", "shadow", "clone", "copy"]

def get_wordlist(size: str) -> List[str]:
    """Get wordlist based on size preference."""
    if size == "small":
        return SMALL_WORDLIST
    elif size == "large":
        return LARGE_WORDLIST
    else:
        return MEDIUM_WORDLIST

async def check_subdomain(subdomain: str, domain: str, timeout: int) -> SubdomainResult:
    """Check if a subdomain exists and get its IP addresses."""
    full_domain = f"{subdomain}.{domain}"
    try:
        # Use asyncio to make DNS resolution non-blocking
        loop = asyncio.get_event_loop()
        ip_addresses = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname_ex, full_domain),
            timeout=timeout
        )
        return SubdomainResult(
            subdomain=full_domain,
            ip_addresses=list(set(ip_addresses[2])),  # Remove duplicates
            status="active"
        )
    except (socket.gaierror, asyncio.TimeoutError):
        return None

async def execute_tool(input_data: SubdomainScannerInput) -> SubdomainScannerOutput:
    """Execute the subdomain scanner tool."""
    start_time = datetime.now()
    
    wordlist = get_wordlist(input_data.wordlist_size)
    found_subdomains = []
    
    # Create tasks for concurrent subdomain checking
    tasks = []
    for subdomain in wordlist:
        task = check_subdomain(subdomain, input_data.domain, input_data.timeout)
        tasks.append(task)
    
    # Run all tasks concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out None results and exceptions
    for result in results:
        if isinstance(result, SubdomainResult):
            found_subdomains.append(result)
    
    duration = (datetime.now() - start_time).total_seconds()
    
    return SubdomainScannerOutput(
        domain=input_data.domain,
        timestamp=start_time,
        duration=duration,
        total_found=len(found_subdomains),
        subdomains=found_subdomains
    )

# Tool metadata
TOOL_INFO = {
    "name": "subdomain_scanner",
    "display_name": "Subdomain Scanner",
    "description": "Discovers subdomains for a target domain using DNS enumeration",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "network_reconnaissance"
}
