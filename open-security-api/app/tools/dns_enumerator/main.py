"""DNS enumeration tool implementation."""

import asyncio
import random
from datetime import datetime
from typing import Dict, Any, List

try:
    from .schemas import (
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
    "author": "Wildbox Security Team",
    "category": "reconnaissance"
}


# Common subdomains for brute forcing
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "www2", "ns1", "ns2", "smtp", "pop", "imap",
    "api", "admin", "cpanel", "blog", "dev", "test", "staging", "demo", "beta",
    "secure", "vpn", "remote", "portal", "app", "mobile", "m", "cdn", "static",
    "media", "images", "assets", "files", "docs", "support", "help", "kb"
]


async def query_dns_records(domain: str, record_types: List[RecordType]) -> List[DNSRecord]:
    """Simulate DNS record queries."""
    await asyncio.sleep(random.uniform(0.5, 2.0))
    
    records = []
    
    # Sample record templates
    record_templates = {
        RecordType.A: [
            "192.168.1.10", "203.0.113.5", "198.51.100.2", "10.0.0.5"
        ],
        RecordType.AAAA: [
            "2001:db8::1", "2001:db8:85a3::8a2e:370:7334", "fe80::1"
        ],
        RecordType.MX: [
            "10 mail.example.com", "20 mail2.example.com", "30 backup-mail.example.com"
        ],
        RecordType.NS: [
            "ns1.example.com", "ns2.example.com", "ns3.example.com"
        ],
        RecordType.TXT: [
            "v=spf1 include:_spf.google.com ~all",
            "google-site-verification=abc123",
            "MS=ms123456789"
        ],
        RecordType.CNAME: [
            "www.example.com", "cdn.cloudflare.com"
        ]
    }
    
    for record_type in record_types:
        if record_type in record_templates and random.random() < 0.7:  # 70% chance record exists
            values = record_templates[record_type]
            num_records = random.randint(1, min(3, len(values)))
            
            for i in range(num_records):
                value = random.choice(values)
                record = DNSRecord(
                    name=domain if record_type != RecordType.CNAME else f"www.{domain}",
                    type=record_type.value,
                    value=value,
                    ttl=random.randint(300, 86400)
                )
                records.append(record)
    
    return records


async def enumerate_subdomains(domain: str, mode: EnumerationMode, max_subdomains: int) -> List[SubdomainInfo]:
    """Simulate subdomain enumeration."""
    
    # Simulate enumeration time based on mode
    enum_time = {
        EnumerationMode.BASIC: random.uniform(1, 3),
        EnumerationMode.COMPREHENSIVE: random.uniform(5, 10),
        EnumerationMode.SUBDOMAIN_BRUTE: random.uniform(8, 15)
    }
    await asyncio.sleep(enum_time[mode])
    
    subdomains = []
    
    # Determine number of subdomains to find based on mode
    num_subdomains = {
        EnumerationMode.BASIC: random.randint(2, 5),
        EnumerationMode.COMPREHENSIVE: random.randint(5, 15),
        EnumerationMode.SUBDOMAIN_BRUTE: random.randint(10, min(max_subdomains, 25))
    }
    
    subdomain_count = num_subdomains[mode]
    found_subdomains = random.sample(COMMON_SUBDOMAINS, min(subdomain_count, len(COMMON_SUBDOMAINS)))
    
    for subdomain in found_subdomains:
        full_subdomain = f"{subdomain}.{domain}"
        
        # Generate realistic IP addresses
        ip_addresses = []
        if random.random() < 0.8:  # 80% chance subdomain has IP
            num_ips = random.randint(1, 3)
            for _ in range(num_ips):
                ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                ip_addresses.append(ip)
        
        # Sometimes add CNAME
        cname = None
        if random.random() < 0.3:  # 30% chance of CNAME
            cname = f"cdn.{domain}"
        
        subdomain_info = SubdomainInfo(
            subdomain=full_subdomain,
            ip_addresses=ip_addresses,
            cname=cname,
            status="active" if ip_addresses else "inactive"
        )
        subdomains.append(subdomain_info)
    
    return subdomains


async def attempt_zone_transfer(domain: str, name_servers: List[str]) -> List[ZoneTransferResult]:
    """Simulate zone transfer attempts."""
    await asyncio.sleep(random.uniform(1, 3))
    
    results = []
    
    for ns in name_servers[:3]:  # Test up to 3 name servers
        # Most zone transfers should fail (security best practice)
        successful = random.random() < 0.1  # 10% chance of success (misconfigured server)
        
        if successful:
            # Generate some fake zone records
            zone_records = [
                DNSRecord(name=f"internal.{domain}", type="A", value="10.0.0.100", ttl=3600),
                DNSRecord(name=f"backup.{domain}", type="A", value="10.0.0.200", ttl=3600),
                DNSRecord(name=f"db.{domain}", type="A", value="10.0.0.50", ttl=3600),
            ]
            result = ZoneTransferResult(
                server=ns,
                successful=True,
                records=zone_records,
                error=None
            )
        else:
            result = ZoneTransferResult(
                server=ns,
                successful=False,
                records=[],
                error="Transfer failed: refused by server"
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
        tasks.append(query_dns_records(domain, input_data.record_types))
        
        # Subdomain enumeration
        tasks.append(enumerate_subdomains(domain, input_data.enumeration_mode, input_data.max_subdomains))
        
        # Zone transfer attempts (if enabled)
        zone_transfer_task = None
        if input_data.check_zone_transfer:
            # Use some example name servers
            example_ns = [f"ns1.{domain}", f"ns2.{domain}"]
            zone_transfer_task = attempt_zone_transfer(domain, example_ns)
            tasks.append(zone_transfer_task)
        
        # Execute all tasks
        results = await asyncio.gather(*tasks)
        
        dns_records = results[0]
        subdomains = results[1]
        zone_transfers = results[2] if input_data.check_zone_transfer else []
        
        # Extract name servers and mail servers from DNS records
        name_servers = [r.value for r in dns_records if r.type == "NS"]
        mail_servers = [r.value for r in dns_records if r.type == "MX"]
        
        # Generate security findings
        security_findings = []
        
        # Check for zone transfer vulnerabilities
        if any(zt.successful for zt in zone_transfers):
            security_findings.append("Zone transfer (AXFR) allowed - potential information disclosure")
        
        # Check for wildcard DNS
        if len(subdomains) > 20:
            security_findings.append("Large number of subdomains discovered - check for wildcard DNS")
        
        # Check for suspicious subdomains
        suspicious_subs = [s for s in subdomains if any(word in s.subdomain.lower() 
                          for word in ['admin', 'test', 'dev', 'staging', 'internal'])]
        if suspicious_subs:
            security_findings.append(f"Potentially sensitive subdomains discovered: {len(suspicious_subs)} found")
        
        # Generate statistics
        statistics = {
            "total_dns_records": len(dns_records),
            "active_subdomains": len([s for s in subdomains if s.status == "active"]),
            "total_subdomains": len(subdomains),
            "name_servers_found": len(name_servers),
            "mail_servers_found": len(mail_servers)
        }
        
        # Generate recommendations
        recommendations = []
        if any(zt.successful for zt in zone_transfers):
            recommendations.append("Disable zone transfers (AXFR) for external queries")
        if not mail_servers:
            recommendations.append("Consider implementing SPF, DKIM, and DMARC records")
        if len(security_findings) == 0:
            recommendations.append("DNS configuration appears secure - maintain current practices")
        else:
            recommendations.append("Review and secure DNS configuration based on findings")
        
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
            zone_transfers=zone_transfers,
            name_servers=name_servers,
            mail_servers=mail_servers,
            security_findings=security_findings,
            statistics=statistics,
            recommendations=recommendations
        )
        
    except Exception as e:
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
