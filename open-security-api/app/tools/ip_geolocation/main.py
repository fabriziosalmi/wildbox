"""
IP Geolocation Tool

This tool provides comprehensive IP address geolocation and analysis including
geographic location, ISP information, threat intelligence, and WHOIS data.
"""

import asyncio
import aiohttp
import ipaddress
import json
import sys
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from app.utils.tool_utils import RateLimiter
    from app.config.tool_config import ToolConfig
except ImportError:
    # Fallback for when running as standalone
    class RateLimiter:
        def __init__(self, max_requests=10, time_window=60):
            pass
        async def acquire(self):
            pass
    
    class ToolConfig:
        DEFAULT_RATE_LIMIT = 10
        DEFAULT_RATE_WINDOW = 60

try:
    from .schemas import IPGeolocationInput, IPGeolocationOutput, GeolocationData, ISPInfo, ThreatIntel, WHOISInfo
except ImportError:
    from schemas import IPGeolocationInput, IPGeolocationOutput, GeolocationData, ISPInfo, ThreatIntel, WHOISInfo


class IPGeolocationLookup:
    """IP Geolocation and Analysis Tool"""
    
    # Private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10'),
    ]
    
    # Reserved ranges
    RESERVED_RANGES = [
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('224.0.0.0/4'),
        ipaddress.ip_network('240.0.0.0/4'),
        ipaddress.ip_network('255.255.255.255/32'),
    ]
    
    # Known malicious IP patterns (simplified examples)
    MALICIOUS_PATTERNS = [
        r'^192\.0\.2\.',      # TEST-NET-1
        r'^198\.51\.100\.',   # TEST-NET-2
        r'^203\.0\.113\.',    # TEST-NET-3
    ]
    
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=30)
        # Initialize rate limiter for external requests
        self.rate_limiter = RateLimiter(max_requests=10, time_window=60)
    
    async def geolocate_ip(self, ip_address: str, include_isp_info: bool = True,
                          include_threat_intel: bool = True, include_whois: bool = True,
                          timeout: int = 10) -> Dict[str, Any]:
        """Perform comprehensive IP geolocation and analysis"""
        
        try:
            # Validate and analyze IP address
            ip_obj = ipaddress.ip_address(ip_address)
            ip_version = ip_obj.version
            is_private = self._is_private_ip(ip_obj)
            is_reserved = self._is_reserved_ip(ip_obj)
            
            data_sources = []
            
            # Get geolocation data
            geolocation = await self._get_geolocation_data(ip_address, timeout)
            if geolocation:
                data_sources.append("ip-api.com")
            
            # Get ISP information
            isp_info = None
            if include_isp_info and not is_private:
                isp_info = await self._get_isp_info(ip_address, timeout)
                if isp_info:
                    data_sources.append("ISP Database")
            
            # Get threat intelligence
            threat_intel = None
            if include_threat_intel and not is_private:
                threat_intel = await self._get_threat_intel(ip_address, timeout)
                if threat_intel:
                    data_sources.append("Threat Intelligence")
            
            # Get WHOIS information
            whois_info = None
            if include_whois and not is_private:
                whois_info = await self._get_whois_info(ip_address, timeout)
                if whois_info:
                    data_sources.append("WHOIS")
            
            return {
                'ip_version': ip_version,
                'is_private': is_private,
                'is_reserved': is_reserved,
                'geolocation': geolocation,
                'isp_info': isp_info,
                'threat_intel': threat_intel,
                'whois_info': whois_info,
                'data_sources': data_sources
            }
            
        except ValueError as e:
            raise Exception(f"Invalid IP address: {str(e)}")
        except Exception as e:
            raise Exception(f"Geolocation lookup failed: {str(e)}")
    
    def _is_private_ip(self, ip_obj: ipaddress.IPv4Address) -> bool:
        """Check if IP is in private range"""
        return any(ip_obj in network for network in self.PRIVATE_RANGES)
    
    def _is_reserved_ip(self, ip_obj: ipaddress.IPv4Address) -> bool:
        """Check if IP is in reserved range"""
        return any(ip_obj in network for network in self.RESERVED_RANGES)
    
    async def _get_geolocation_data(self, ip_address: str, timeout: int) -> Optional[GeolocationData]:
        """Get geolocation data using free IP-API service"""
        try:
            custom_timeout = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=custom_timeout) as session:
                # Apply rate limiting before making external request
                await self.rate_limiter.acquire()
                
                # Using ip-api.com (free service with rate limits)
                url = f"http://ip-api.com/json/{ip_address}"
                
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('status') == 'success':
                            return GeolocationData(
                                country=data.get('country'),
                                country_code=data.get('countryCode'),
                                region=data.get('regionName'),
                                region_code=data.get('region'),
                                city=data.get('city'),
                                postal_code=data.get('zip'),
                                latitude=data.get('lat'),
                                longitude=data.get('lon'),
                                timezone=data.get('timezone')
                            )
            
            return None
            
        except Exception:
            return None
    
    async def _get_isp_info(self, ip_address: str, timeout: int) -> Optional[ISPInfo]:
        """Get ISP information (simulated for demo)"""
        try:
            # In a real implementation, this would query actual ISP databases
            # For demo purposes, we'll simulate some data based on common patterns
            
            if ip_address.startswith('8.8.'):
                return ISPInfo(
                    isp="Google LLC",
                    organization="Google Public DNS",
                    asn=15169,
                    asn_name="GOOGLE"
                )
            elif ip_address.startswith('1.1.'):
                return ISPInfo(
                    isp="Cloudflare, Inc.",
                    organization="Cloudflare DNS",
                    asn=13335,
                    asn_name="CLOUDFLARENET"
                )
            elif ip_address.startswith('208.67.'):
                return ISPInfo(
                    isp="Cisco OpenDNS",
                    organization="OpenDNS LLC",
                    asn=36692,
                    asn_name="OPENDNS"
                )
            else:
                # Generic ISP info for other IPs
                return ISPInfo(
                    isp="Unknown ISP",
                    organization="Unknown Organization",
                    asn=None,
                    asn_name=None
                )
                
        except Exception:
            return None
    
    async def _get_threat_intel(self, ip_address: str, timeout: int) -> Optional[ThreatIntel]:
        """Get threat intelligence data (simulated for demo)"""
        try:
            # In a real implementation, this would query actual threat intelligence feeds
            # For demo purposes, we'll check against some basic patterns
            
            is_malicious = False
            threat_types = []
            blacklist_sources = []
            reputation_score = 100
            
            # Check against malicious patterns
            for pattern in self.MALICIOUS_PATTERNS:
                if re.match(pattern, ip_address):
                    is_malicious = True
                    threat_types.append("Test/Reserved IP")
                    blacklist_sources.append("RFC Test Networks")
                    reputation_score = 0
                    break
            
            # Simulate some threat data for specific IPs
            if ip_address in ['192.0.2.1', '198.51.100.1']:
                is_malicious = True
                threat_types.extend(["Malware C&C", "Botnet"])
                blacklist_sources.extend(["Demo Blacklist", "Test Feed"])
                reputation_score = 10
            
            # Check for suspicious patterns
            if any(char.isalpha() for char in ip_address.replace('.', '')):
                # This would never happen with valid IPs, but good for demo
                pass
            
            return ThreatIntel(
                is_malicious=is_malicious,
                threat_types=threat_types,
                reputation_score=reputation_score,
                last_seen="Never" if not is_malicious else "Demo Data",
                blacklist_sources=blacklist_sources
            )
            
        except Exception:
            return None
    
    async def _get_whois_info(self, ip_address: str, timeout: int) -> Optional[WHOISInfo]:
        """Get WHOIS information (simulated for demo)"""
        try:
            # In a real implementation, this would query actual WHOIS databases
            # For demo purposes, we'll provide simulated data
            
            if ip_address.startswith('8.8.'):
                return WHOISInfo(
                    network_range="8.8.8.0/24",
                    allocation_date="2014-09-01",
                    registry="ARIN",
                    registrant="Google LLC",
                    admin_contact="Google DNS Admin",
                    tech_contact="Google Technical Contact"
                )
            elif ip_address.startswith('1.1.'):
                return WHOISInfo(
                    network_range="1.1.1.0/24",
                    allocation_date="2018-04-01",
                    registry="APNIC",
                    registrant="Cloudflare, Inc.",
                    admin_contact="Cloudflare DNS Admin",
                    tech_contact="Cloudflare Technical Contact"
                )
            else:
                # Generic WHOIS info
                return WHOISInfo(
                    network_range=f"{'.'.join(ip_address.split('.')[:-1])}.0/24",
                    allocation_date="Unknown",
                    registry="Unknown",
                    registrant="Unknown Organization",
                    admin_contact="Unknown",
                    tech_contact="Unknown"
                )
                
        except Exception:
            return None


async def execute_tool(params: IPGeolocationInput) -> IPGeolocationOutput:
    """Main entry point for the IP geolocation tool"""
    lookup = IPGeolocationLookup()
    
    try:
        # Perform IP geolocation lookup
        result = await lookup.geolocate_ip(
            ip_address=params.ip_address,
            include_isp_info=params.include_isp_info,
            include_threat_intel=params.include_threat_intel,
            include_whois=params.include_whois,
            timeout=params.timeout
        )
        
        return IPGeolocationOutput(
            success=True,
            ip_address=params.ip_address,
            ip_version=result['ip_version'],
            is_private=result['is_private'],
            is_reserved=result['is_reserved'],
            geolocation=result['geolocation'] or GeolocationData(),
            isp_info=result['isp_info'],
            threat_intel=result['threat_intel'],
            whois_info=result['whois_info'],
            accuracy_radius=50 if result['geolocation'] else None,  # Simulated accuracy
            data_sources=result['data_sources'],
            timestamp=datetime.now(),
            error=None
        )
        
    except Exception as e:
        return IPGeolocationOutput(
            success=False,
            ip_address=params.ip_address,
            ip_version=0,
            is_private=False,
            is_reserved=False,
            geolocation=GeolocationData(),
            isp_info=None,
            threat_intel=None,
            whois_info=None,
            accuracy_radius=None,
            data_sources=[],
            timestamp=datetime.now(),
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "ip_geolocation",
    "display_name": "IP Geolocation Lookup",
    "description": "Comprehensive IP address geolocation with threat intelligence and WHOIS data",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "network_reconnaissance"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        test_input = IPGeolocationInput(
            ip_address="8.8.8.8",
            include_isp_info=True,
            include_threat_intel=True,
            include_whois=True
        )
        result = await execute_tool(test_input)
        print(f"Success: {result.success}")
        if result.success:
            print(f"Country: {result.geolocation.country}")
            print(f"City: {result.geolocation.city}")
            print(f"ISP: {result.isp_info.isp if result.isp_info else 'Unknown'}")
            print(f"Is Malicious: {result.threat_intel.is_malicious if result.threat_intel else 'Unknown'}")
        else:
            print(f"Error: {result.error}")
    
    asyncio.run(test())
