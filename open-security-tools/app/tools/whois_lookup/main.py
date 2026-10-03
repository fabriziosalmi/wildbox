"""WHOIS Lookup Tool - Retrieves domain registration information."""

import ipaddress
import socket
import re
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict
from ...tool_errors import RUN_ERRORS, ToolRunError
from ...input_validation import InputSanitizer
from ...url_guard import is_local_hostname, parse_target_url
from .schemas import WHOISLookupInput, WHOISLookupOutput, WHOISResult, WHOISContact
# Configure logging
logger = logging.getLogger(__name__)

# WHOIS servers for different TLDs
WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'biz': 'whois.neulevel.biz',
    'us': 'whois.nic.us',
    'uk': 'whois.nic.uk',
    'ca': 'whois.cira.ca',
    'au': 'whois.aunic.net',
    'de': 'whois.denic.de',
    'fr': 'whois.nic.fr',
    'it': 'whois.nic.it',
    'nl': 'whois.domain-registry.nl',
    'be': 'whois.dns.be',
    'ch': 'whois.nic.ch',
    'se': 'whois.iis.se',
    'no': 'whois.norid.no',
    'dk': 'whois.dk-hostmaster.dk',
    'fi': 'whois.ficora.fi',
    'pl': 'whois.dns.pl',
    'ru': 'whois.tcinet.ru',
    'cn': 'whois.cnnic.net.cn',
    'jp': 'whois.jprs.jp',
    'kr': 'whois.nida.or.kr',
    'tw': 'whois.twnic.net.tw',
    'in': 'whois.ncst.ernet.in',
    'mx': 'whois.mx',
    'br': 'whois.registro.br',
    'ar': 'whois.nic.ar'
}

def get_whois_server(domain: str) -> str:
    """Get the appropriate WHOIS server for a domain."""
    tld = domain.split('.')[-1].lower()
    return WHOIS_SERVERS.get(tld, 'whois.iana.org')


WHOIS_PORT = 43


def resolve_referral_server(server: str) -> tuple:
    """Check a referral WHOIS server and return the address to connect to.

    The "Whois Server:" line comes from a WHOIS response, so the remote side
    picks the host this tool connects to next. It gets the same treatment as
    a URL a caller supplies (#610): a canonical host name or IP literal with
    no port, path or user info; not a local or metadata name; and every
    address it resolves to public. A name that does not resolve is refused.

    Returns ``(family, sockaddr)`` of the first address. The caller connects
    to that address rather than resolving the name again, so the checked
    address is the one dialed. Raises ValueError if the server is refused.
    """
    server = server.strip()
    if not server or any(ch in server for ch in "/@?#:[]\\"):
        raise ValueError(f"Referral WHOIS server {server!r} is not a bare host name")
    target = parse_target_url(f"whois://{server}", allowed_schemes=("whois",))
    if is_local_hostname(target.host) or target.host in InputSanitizer.BLOCKED_HOSTNAMES:
        raise ValueError(f"Referral WHOIS server {target.host!r} is blocked (SSRF protection)")
    try:
        infos = socket.getaddrinfo(target.host, WHOIS_PORT, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Referral WHOIS server {target.host!r} could not be resolved") from exc
    if not infos:
        raise ValueError(f"Referral WHOIS server {target.host!r} could not be resolved")
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = ipaddress.ip_address(sockaddr[0])
        if InputSanitizer._is_blocked_ip(addr):
            raise ValueError(
                f"Referral WHOIS server {target.host!r} resolves to blocked address {addr} (SSRF protection)"
            )
    family, _type, _proto, _canon, sockaddr = infos[0]
    return family, sockaddr


def query_whois_server(domain: str, server: str, timeout: int, address: Optional[tuple] = None) -> str:
    """Query a WHOIS server for domain information.

    ``address`` is a ``(family, sockaddr)`` pair from
    :func:`resolve_referral_server`; when given, the connection goes to that
    checked address instead of resolving ``server`` again.
    """
    try:
        if address is not None:
            family, sockaddr = address
        else:
            family, sockaddr = socket.AF_INET, (server, WHOIS_PORT)
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        sock.send(f"{domain}\r\n".encode())

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()
        return response.decode('utf-8', errors='ignore')

    except RUN_ERRORS as e:
        raise ToolRunError(f"Failed to query WHOIS server {server}: {str(e)}")

def parse_date(date_str: str) -> Optional[datetime]:
    """Parse various date formats found in WHOIS data."""
    if not date_str:
        return None
    
    # Common date formats in WHOIS
    date_formats = [
        '%Y-%m-%d',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%d-%b-%Y',
        '%d/%m/%Y',
        '%m/%d/%Y',
        '%Y.%m.%d',
        '%d.%m.%Y',
        '%Y-%m-%d %H:%M:%S',
        '%d-%m-%Y %H:%M:%S'
    ]
    
    # Clean the date string
    date_str = date_str.strip()
    
    for fmt in date_formats:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    
    return None

def extract_contact_info(whois_data: str, contact_type: str) -> Optional[WHOISContact]:
    """Extract contact information for a specific type (registrant, admin, tech)."""
    contact_patterns = {
        'registrant': [
            r'Registrant.*?Name:\s*(.+)',
            r'Registrant.*?Organization:\s*(.+)',
            r'Registrant.*?Email:\s*(.+)',
            r'Registrant.*?Phone:\s*(.+)'
        ],
        'admin': [
            r'Admin.*?Name:\s*(.+)',
            r'Admin.*?Organization:\s*(.+)', 
            r'Admin.*?Email:\s*(.+)',
            r'Admin.*?Phone:\s*(.+)'
        ],
        'tech': [
            r'Tech.*?Name:\s*(.+)',
            r'Tech.*?Organization:\s*(.+)',
            r'Tech.*?Email:\s*(.+)',
            r'Tech.*?Phone:\s*(.+)'
        ]
    }
    
    if contact_type not in contact_patterns:
        return None
    
    patterns = contact_patterns[contact_type]
    contact = WHOISContact()
    
    for i, pattern in enumerate(patterns):
        match = re.search(pattern, whois_data, re.IGNORECASE | re.MULTILINE)
        if match:
            value = match.group(1).strip()
            if i == 0:  # Name
                contact.name = value
            elif i == 1:  # Organization
                contact.organization = value
            elif i == 2:  # Email
                contact.email = value
            elif i == 3:  # Phone
                contact.phone = value
    
    # Return None if no contact info found
    if not any([contact.name, contact.organization, contact.email, contact.phone]):
        return None
    
    return contact

def parse_whois_data(whois_raw: str, domain: str) -> WHOISResult:
    """Parse raw WHOIS data into structured format."""
    
    # Extract registrar
    registrar_match = re.search(r'Registrar:\s*(.+)', whois_raw, re.IGNORECASE)
    registrar = registrar_match.group(1).strip() if registrar_match else None
    
    # Extract dates
    creation_patterns = [
        r'Creation Date:\s*(.+)',
        r'Created:\s*(.+)',
        r'Domain Registration Date:\s*(.+)',
        r'created:\s*(.+)'
    ]
    
    expiration_patterns = [
        r'Registry Expiry Date:\s*(.+)',
        r'Expiry Date:\s*(.+)',
        r'Expiration Date:\s*(.+)',
        r'expire:\s*(.+)'
    ]
    
    updated_patterns = [
        r'Updated Date:\s*(.+)',
        r'Last Updated:\s*(.+)',
        r'changed:\s*(.+)'
    ]
    
    registration_date = None
    for pattern in creation_patterns:
        match = re.search(pattern, whois_raw, re.IGNORECASE)
        if match:
            registration_date = parse_date(match.group(1))
            break
    
    expiration_date = None
    for pattern in expiration_patterns:
        match = re.search(pattern, whois_raw, re.IGNORECASE)
        if match:
            expiration_date = parse_date(match.group(1))
            break
    
    last_updated = None
    for pattern in updated_patterns:
        match = re.search(pattern, whois_raw, re.IGNORECASE)
        if match:
            last_updated = parse_date(match.group(1))
            break
    
    # Extract name servers
    ns_patterns = [
        r'Name Server:\s*(.+)',
        r'nserver:\s*(.+)',
        r'Nameserver:\s*(.+)'
    ]
    
    name_servers = []
    for pattern in ns_patterns:
        matches = re.findall(pattern, whois_raw, re.IGNORECASE)
        name_servers.extend([ns.strip().lower() for ns in matches])
    
    name_servers = list(set(name_servers))  # Remove duplicates
    
    # Extract domain status
    status_matches = re.findall(r'Domain Status:\s*(.+)', whois_raw, re.IGNORECASE)
    status = [s.strip() for s in status_matches]
    
    # Extract DNSSEC
    dnssec_match = re.search(r'DNSSEC:\s*(.+)', whois_raw, re.IGNORECASE)
    dnssec = dnssec_match.group(1).strip() if dnssec_match else None
    
    # Extract contact information
    registrant = extract_contact_info(whois_raw, 'registrant')
    admin_contact = extract_contact_info(whois_raw, 'admin')
    tech_contact = extract_contact_info(whois_raw, 'tech')
    
    return WHOISResult(
        domain=domain,
        registrar=registrar,
        registration_date=registration_date,
        expiration_date=expiration_date,
        last_updated=last_updated,
        name_servers=name_servers,
        status=status,
        registrant=registrant,
        admin_contact=admin_contact,
        tech_contact=tech_contact,
        dnssec=dnssec
    )

def execute_tool(input_data: WHOISLookupInput) -> WHOISLookupOutput:
    """Execute the WHOIS lookup tool."""
    timestamp = datetime.now()
    domain = input_data.domain.lower().strip()
    
    try:
        # Get appropriate WHOIS server
        whois_server = get_whois_server(domain)
        
        # Query WHOIS server
        raw_data = query_whois_server(domain, whois_server, input_data.timeout)
        
        # Check if we need to query a different server (some registrars redirect)
        redirect_match = re.search(r'Whois Server:\s*(.+)', raw_data, re.IGNORECASE)
        if redirect_match:
            redirect_server = redirect_match.group(1).strip()
            if redirect_server != whois_server:
                try:
                    # The referral comes from the response: check it with the
                    # SSRF rules and connect to the checked address.
                    address = resolve_referral_server(redirect_server)
                    raw_data = query_whois_server(
                        domain, redirect_server, input_data.timeout, address=address
                    )
                except (socket.error, socket.timeout, Exception) as e:
                    logger.error(f"Error querying redirect WHOIS server {redirect_server}: {e}")
                    pass  # Use original data if redirect fails
        
        # Parse the WHOIS data
        parsed_result = parse_whois_data(raw_data, domain)
        
        # Calculate days until expiry
        days_until_expiry = None
        if parsed_result.expiration_date:
            delta = parsed_result.expiration_date - datetime.now(timezone.utc)
            days_until_expiry = delta.days
        
        return WHOISLookupOutput(
            timestamp=timestamp,
            domain=domain,
            success=True,
            result=parsed_result,
            raw_data=raw_data if input_data.include_raw else None,
            error_message=None,
            days_until_expiry=days_until_expiry
        )
        
    except RUN_ERRORS as e:
        return WHOISLookupOutput(
            timestamp=timestamp,
            domain=domain,
            success=False,
            result=None,
            raw_data=None,
            error_message=str(e),
            days_until_expiry=None
        )

# Tool metadata
TOOL_INFO = {
    "name": "whois_lookup",
    "display_name": "WHOIS Lookup",
    "description": "Retrieves domain registration and ownership information",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "osint"
}
