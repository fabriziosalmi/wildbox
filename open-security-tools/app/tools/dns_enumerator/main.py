"""DNS enumeration tool implementation."""

import asyncio
import socket
import dns.resolver
import dns.zone
import dns.query
from datetime import datetime
from typing import Dict, Any, List
import logging

try:
    from schemas import (
        DNSEnumeratorInput, DNSEnumeratorOutput, DNSRecord, SubdomainInfo,
        ZoneTransferResult, RecordType, EnumerationMode
    )
except ImportError:
    from schemas import (
        DNSEnumeratorInput, DNSEnumeratorOutput, DNSRecord, SubdomainInfo,
        ZoneTransferResult, RecordType, EnumerationMode
    )


# Tool metadata
TOOL_INFO = {
    "name": "dns_enumerator",
    "display_name": "DNS Enumeration Tool",
    "description": "Advanced DNS reconnaissance tool for domain enumeration, subdomain discovery, and DNS security analysis",
    "version": "1.5.0",
    "author": "Wildbox Security",
    "category": "reconnaissance"
}


# Common subdomains for brute forcing
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "www2", "ns1", "ns2", "smtp", "pop", "imap",
    "api", "admin", "cpanel", "blog", "dev", "test", "staging", "demo", "beta",
    "secure", "vpn", "remote", "portal", "app", "mobile", "m", "cdn", "static",
    "media", "images", "assets", "files", "docs", "support", "help", "kb",
    "login", "secure", "ssl", "www3", "ftp2", "email", "exchange", "mail2",
    "autodiscover", "autoconfig", "secure", "intranet", "extranet", "gateway"
]

# Extended subdomain list for comprehensive scans
EXTENDED_SUBDOMAINS = COMMON_SUBDOMAINS + [
    "access", "accounting", "accounts", "ad", "adm", "admin1", "admin2", "administration",
    "administrator", "ads", "affiliate", "affiliates", "alpha", "alumni", "analytics",
    "android", "apache", "api1", "api2", "apiv1", "apiv2", "app1", "app2", "apps",
    "archive", "assets1", "assets2", "auth", "backup", "beta1", "beta2", "billing",
    "blog1", "blog2", "board", "books", "business", "calendar", "cdn1", "cdn2",
    "chat", "checkout", "client", "clients", "cloud", "cms", "code", "community",
    "conference", "connect", "console", "contact", "content", "control", "corporate",
    "crm", "customers", "data", "database", "db", "demo1", "demo2", "design",
    "dev1", "dev2", "developer", "developers", "direct", "directory", "dl",
    "download", "downloads", "e", "ecommerce", "edit", "education", "email1",
    "email2", "en", "enterprise", "erp", "event", "events", "external", "finance",
    "forum", "forums", "ftp1", "gallery", "game", "games", "git", "global",
    "groups", "help1", "help2", "home", "host", "hosting", "hr", "hub", "i",
    "id", "image", "img", "info", "internal", "intranet1", "intranet2", "investor",
    "investors", "invoice", "invoices", "ios", "it", "jobs", "js", "lab", "labs",
    "learn", "learning", "legal", "live", "local", "log", "logs", "m1", "m2",
    "manage", "management", "manager", "marketing", "marketplace", "media1", "media2",
    "member", "members", "mobile1", "mobile2", "monitor", "monitoring", "mx1", "mx2",
    "my", "network", "new", "news", "newsletter", "old", "online", "order", "orders",
    "panel", "partner", "partners", "payment", "payments", "photo", "photos", "pilot",
    "pop3", "portal1", "portal2", "preview", "private", "prod", "production", "products",
    "project", "projects", "promo", "public", "qa", "redirect", "register", "registration",
    "repo", "repository", "research", "resource", "resources", "review", "reviews",
    "sales", "sandbox", "search", "secure1", "secure2", "security", "server", "servers",
    "service", "services", "shop", "site", "sites", "social", "software", "staff",
    "stage", "staging1", "staging2", "start", "stat", "static1", "static2", "stats",
    "status", "store", "stream", "streaming", "support1", "support2", "sync", "system",
    "team", "temp", "test1", "test2", "testing", "tools", "track", "tracking", "training",
    "trial", "update", "updates", "upload", "uploads", "user", "users", "v", "v1", "v2",
    "vendor", "vendors", "video", "videos", "virtual", "vm", "voice", "voip", "vpn1",
    "vpn2", "w", "w3", "web", "web1", "web2", "webdisk", "webmail1", "webmail2",
    "website", "webstats", "wiki", "win", "windows", "work", "workspace", "xml", "zone"
]


async def query_dns_records(domain: str, record_types: List[RecordType], dns_servers: List[str], timeout: int) -> List[DNSRecord]:
    """Query DNS records for a domain."""
    records = []
    
    # Configure DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = dns_servers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type.value)
            for answer in answers:
                record = DNSRecord(
                    name=domain,
                    type=record_type.value,
                    value=str(answer),
                    ttl=answers.rrset.ttl
                )
                records.append(record)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            # Domain doesn't exist, no records of this type, or timeout
            continue
    
    return records


async def enumerate_subdomains(domain: str, mode: EnumerationMode, max_subdomains: int, dns_servers: List[str], timeout: int) -> List[SubdomainInfo]:
    """Enumerate subdomains for a domain."""
    
    # Choose subdomain list based on mode
    if mode == EnumerationMode.BASIC:
        subdomain_list = COMMON_SUBDOMAINS[:20]
    elif mode == EnumerationMode.COMPREHENSIVE:
        subdomain_list = COMMON_SUBDOMAINS
    else:  # SUBDOMAIN_BRUTE
        subdomain_list = EXTENDED_SUBDOMAINS[:max_subdomains]
    
    subdomains = []
    
    # Configure DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = dns_servers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    # Create semaphore to limit concurrent requests
    semaphore = asyncio.Semaphore(50)  # Limit to 50 concurrent requests
    
    async def check_subdomain(subdomain_name: str) -> SubdomainInfo:
        async with semaphore:
            full_subdomain = f"{subdomain_name}.{domain}"
            ip_addresses = []
            cname = None
            
            try:
                # Check for A records
                try:
                    answers = resolver.resolve(full_subdomain, 'A')
                    ip_addresses = [str(answer) for answer in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                
                # Check for AAAA records
                try:
                    answers = resolver.resolve(full_subdomain, 'AAAA')
                    ip_addresses.extend([str(answer) for answer in answers])
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                
                # Check for CNAME records
                try:
                    answers = resolver.resolve(full_subdomain, 'CNAME')
                    cname = str(answers[0])
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                
                status = "active" if ip_addresses or cname else "inactive"
                
                return SubdomainInfo(
                    subdomain=full_subdomain,
                    ip_addresses=ip_addresses,
                    cname=cname,
                    status=status
                )
                
            except Exception:
                return SubdomainInfo(
                    subdomain=full_subdomain,
                    ip_addresses=[],
                    cname=None,
                    status="error"
                )
    
    # Run subdomain checks concurrently
    tasks = [check_subdomain(sub) for sub in subdomain_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out exceptions and inactive subdomains
    for result in results:
        if isinstance(result, SubdomainInfo) and result.status in ["active", "inactive"]:
            subdomains.append(result)
    
    return subdomains


async def attempt_zone_transfer(domain: str, name_servers: List[str], timeout: int) -> List[ZoneTransferResult]:
    """Attempt zone transfer (AXFR) from name servers."""
    results = []
    
    for ns in name_servers[:5]:  # Test up to 5 name servers
        try:
            # Attempt zone transfer
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=timeout))
            
            # Zone transfer successful - extract records
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        record = DNSRecord(
                            name=str(name) + "." + domain if str(name) != "@" else domain,
                            type=dns.rdatatype.to_text(rdataset.rdtype),
                            value=str(rdata),
                            ttl=rdataset.ttl
                        )
                        records.append(record)
            
            result = ZoneTransferResult(
                server=ns,
                successful=True,
                records=records,
                error=None
            )
            
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            result = ZoneTransferResult(
                server=ns,
                successful=False,
                records=[],
                error=str(e)
            )
        
        results.append(result)
    
    return results


async def execute_tool(input_data: DNSEnumeratorInput) -> DNSEnumeratorOutput:
    """Execute the DNS enumeration tool."""
    start_time = datetime.now()
    
    try:
        # Validate domain
        domain = input_data.target_domain.lower().strip()
        if not domain or '.' not in domain:
            raise ValueError("Invalid domain format")
        
        # Perform DNS enumeration tasks
        tasks = []
        
        # Basic DNS record queries
        tasks.append(query_dns_records(domain, input_data.record_types, input_data.dns_servers, input_data.timeout))
        
        # Subdomain enumeration
        tasks.append(enumerate_subdomains(domain, input_data.enumeration_mode, input_data.max_subdomains, input_data.dns_servers, input_data.timeout))
        
        # Zone transfer attempts (if enabled)
        zone_transfer_task = None
        if input_data.check_zone_transfer:
            # First get name servers
            ns_records = await query_dns_records(domain, [RecordType.NS], input_data.dns_servers, input_data.timeout)
            name_servers = [record.value for record in ns_records if record.type == "NS"]
            
            if name_servers:
                tasks.append(attempt_zone_transfer(domain, name_servers, input_data.timeout))
            else:
                tasks.append(asyncio.create_task(asyncio.sleep(0)))  # Dummy task
        
        # Execute all tasks
        results = await asyncio.gather(*tasks)
        
        dns_records = results[0]
        subdomains = results[1]
        zone_transfers = results[2] if input_data.check_zone_transfer and len(results) > 2 else []
        
        # Extract name servers and mail servers from DNS records
        name_servers = [r.value for r in dns_records if r.type == "NS"]
        mail_servers = [r.value for r in dns_records if r.type == "MX"]
        
        # Generate security findings
        security_findings = []
        
        # Check for zone transfer vulnerabilities
        successful_transfers = [zt for zt in zone_transfers if isinstance(zt, ZoneTransferResult) and zt.successful]
        if successful_transfers:
            security_findings.append(f"Zone transfer vulnerability detected on {len(successful_transfers)} name server(s)")
        
        # Check for wildcard DNS
        active_subdomains = [s for s in subdomains if s.status == "active"]
        if len(active_subdomains) > 50:
            security_findings.append("Possible wildcard DNS configuration detected")
        
        # Check for suspicious subdomains
        suspicious_keywords = ['admin', 'test', 'dev', 'staging', 'internal', 'backup', 'temp']
        suspicious_subs = [s for s in active_subdomains if any(word in s.subdomain.lower() for word in suspicious_keywords)]
        if suspicious_subs:
            security_findings.append(f"Found {len(suspicious_subs)} potentially sensitive subdomain(s)")
        
        # Generate statistics
        statistics = {
            "total_dns_records": len(dns_records),
            "active_subdomains": len(active_subdomains),
            "total_subdomains": len(subdomains),
            "name_servers_found": len(name_servers),
            "mail_servers_found": len(mail_servers)
        }
        
        # Generate recommendations
        recommendations = []
        if successful_transfers:
            recommendations.append("Disable zone transfers on authoritative name servers")
        if not mail_servers:
            recommendations.append("Consider implementing SPF, DKIM, and DMARC records")
        if suspicious_subs:
            recommendations.append("Review and secure sensitive subdomains")
        if len(security_findings) == 0:
            recommendations.append("DNS configuration appears secure")
        else:
            recommendations.append("Address identified DNS security issues")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return DNSEnumeratorOutput(
            target_domain=domain,
            enumeration_mode=input_data.enumeration_mode.value,
            timestamp=start_time,
            duration=duration,
            status="completed",
            dns_records=dns_records,
            subdomains=subdomains,
            zone_transfers=zone_transfers if isinstance(zone_transfers, list) else [],
            name_servers=name_servers,
            mail_servers=mail_servers,
            security_findings=security_findings,
            statistics=statistics,
            recommendations=recommendations
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return DNSEnumeratorOutput(
            target_domain=input_data.target_domain,
            enumeration_mode=input_data.enumeration_mode.value,
            timestamp=start_time,
            duration=duration,
            status=f"failed: {str(e)}",
            dns_records=[],
            subdomains=[],
            zone_transfers=[],
            name_servers=[],
            mail_servers=[],
            security_findings=[],
            statistics={},
            recommendations=["Fix enumeration errors and retry"]
        )


# Alias for the main execution function
run = execute_tool
