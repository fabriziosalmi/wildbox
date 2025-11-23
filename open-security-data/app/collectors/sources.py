"""
Specific collector implementations for popular threat intelligence sources
"""

import json
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from app.collectors import BaseCollector, HTTPCollector

logger = logging.getLogger(__name__)

class MalwareDomainListCollector(HTTPCollector):
    """Collector for Malware Domain List"""
    
    def __init__(self, source):
        super().__init__(source)
        if not source.url:
            source.url = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
    
    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse malware domain list item"""
        if 'raw_line' not in raw_item:
            return None
        
        line = raw_item['raw_line'].strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#') or line.startswith('localhost'):
            return None
        
        # Parse hosts file format: "127.0.0.1 malicious.domain.com"
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "127.0.0.1":
            domain = parts[1].strip()
            return {
                'indicator_type': 'domain',
                'value': domain,
                'threat_types': ['malware'],
                'confidence': 'high',
                'severity': 7,
                'description': f'Malicious domain from Malware Domain List',
                'tags': ['malware', 'domain-list'],
                'expires_at': datetime.now(timezone.utc) + timedelta(days=30)
            }
        
        return None

class AbuseIPDBCollector(HTTPCollector):
    """Collector for AbuseIPDB"""
    
    def __init__(self, source):
        super().__init__(source)
        if not source.url:
            source.url = "https://api.abuseipdb.com/api/v2/blacklist"
        
        # Requires API key
        api_key = self.config.get('api_key')
        if api_key:
            source.headers['Key'] = api_key
            source.headers['Accept'] = 'application/json'
    
    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse AbuseIPDB item"""
        if 'ipAddress' not in raw_item:
            return None
        
        ip_address = raw_item['ipAddress']
        confidence_percentage = raw_item.get('confidencePercentage', 0)
        
        # Convert confidence percentage to our scale
        if confidence_percentage >= 90:
            confidence = 'verified'
            severity = 9
        elif confidence_percentage >= 70:
            confidence = 'high'
            severity = 8
        elif confidence_percentage >= 50:
            confidence = 'medium'
            severity = 6
        else:
            confidence = 'low'
            severity = 4
        
        return {
            'indicator_type': 'ip_address',
            'value': ip_address,
            'threat_types': ['abuse', 'malicious'],
            'confidence': confidence,
            'severity': severity,
            'description': f'Abusive IP with {confidence_percentage}% confidence',
            'tags': ['abuse', 'blacklist'],
            'metadata': {
                'confidence_percentage': confidence_percentage,
                'usage_type': raw_item.get('usageType'),
                'isp': raw_item.get('isp'),
                'country_code': raw_item.get('countryCode'),
                'total_reports': raw_item.get('totalReports', 0)
            },
            'expires_at': datetime.now(timezone.utc) + timedelta(days=7)
        }

class URLVoidCollector(HTTPCollector):
    """Collector for URLVoid reputation checks"""
    
    def __init__(self, source):
        super().__init__(source)
        self.api_key = self.config.get('api_key')
        self.base_url = "http://api.urlvoid.com/1000/{}/host/{}"
    
    async def collect_data(self):
        """Collect data by checking specific domains"""
        domains_to_check = self.config.get('domains', [])
        
        for domain in domains_to_check:
            if self.api_key:
                url = self.base_url.format(self.api_key, domain)
                
                try:
                    async with self.session.get(url) as response:
                        response.raise_for_status()
                        data = await response.json()
                        yield {
                            'domain': domain,
                            'response': data
                        }
                except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
                    logger.error(f"Error checking domain {domain}: {e}")
                    continue
    
    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse URLVoid response"""
        domain = raw_item.get('domain')
        response = raw_item.get('response', {})
        
        if not domain or 'detections' not in response:
            return None
        
        detections = response['detections']
        engines = response.get('engines', {})
        
        detection_count = detections.get('count', 0)
        total_engines = engines.get('total', 1)
        
        if detection_count == 0:
            return None  # Clean domain, skip
        
        # Calculate confidence based on detection ratio
        detection_ratio = detection_count / total_engines
        if detection_ratio >= 0.5:
            confidence = 'high'
            severity = 8
        elif detection_ratio >= 0.25:
            confidence = 'medium'
            severity = 6
        else:
            confidence = 'low'
            severity = 4
        
        return {
            'indicator_type': 'domain',
            'value': domain,
            'threat_types': ['malicious', 'suspicious'],
            'confidence': confidence,
            'severity': severity,
            'description': f'Domain flagged by {detection_count}/{total_engines} engines',
            'tags': ['reputation', 'multi-engine'],
            'metadata': {
                'detection_count': detection_count,
                'total_engines': total_engines,
                'detection_ratio': detection_ratio,
                'engines': engines
            },
            'expires_at': datetime.now(timezone.utc) + timedelta(days=3)
        }

class PhishTankCollector(HTTPCollector):
    """Collector for PhishTank phishing URLs"""
    
    def __init__(self, source):
        super().__init__(source)
        if not source.url:
            source.url = "http://data.phishtank.com/data/online-valid.json"
    
    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse PhishTank item"""
        url = raw_item.get('url')
        phish_id = raw_item.get('phish_id')
        verified = raw_item.get('verified') == 'yes'
        
        if not url:
            return None
        
        return {
            'indicator_type': 'url',
            'value': url,
            'threat_types': ['phishing'],
            'confidence': 'verified' if verified else 'medium',
            'severity': 8 if verified else 6,
            'description': f'Phishing URL (PhishTank ID: {phish_id})',
            'tags': ['phishing', 'url'],
            'metadata': {
                'phish_id': phish_id,
                'verified': verified,
                'submission_time': raw_item.get('submission_time'),
                'verification_time': raw_item.get('verification_time'),
                'target': raw_item.get('target')
            },
            'expires_at': datetime.now(timezone.utc) + timedelta(days=30)
        }

class FeodoTrackerCollector(HTTPCollector):
    """Collector for Feodo Tracker botnet C&C servers"""
    
    def __init__(self, source):
        super().__init__(source)
        if not source.url:
            source.url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    
    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse Feodo Tracker item"""
        ip_address = raw_item.get('ip_address')
        port = raw_item.get('port')
        status = raw_item.get('status')
        malware = raw_item.get('malware')
        
        if not ip_address or status != 'online':
            return None
        
        return {
            'indicator_type': 'ip_address',
            'value': ip_address,
            'threat_types': ['botnet', 'malware'],
            'confidence': 'verified',
            'severity': 9,
            'description': f'{malware} C&C server on port {port}',
            'tags': ['botnet', 'c2', malware.lower() if malware else 'malware'],
            'metadata': {
                'port': port,
                'malware_family': malware,
                'status': status,
                'country': raw_item.get('country'),
                'as_name': raw_item.get('as_name'),
                'as_number': raw_item.get('as_number')
            },
            'expires_at': datetime.now(timezone.utc) + timedelta(days=7)
        }

class MalwareBazaarCollector(HTTPCollector):
    """Collector for MalwareBazaar malware samples"""
    
    def __init__(self, source):
        super().__init__(source)
        if not source.url:
            source.url = "https://mb-api.abuse.ch/api/v1/"
        
        # Get recent samples
        self.query_data = {
            "query": "get_recent",
            "selector": "time"
        }
    
    async def collect_data(self):
        """Collect recent malware samples"""
        try:
            async with self.session.post(
                self.source.url,
                data=self.query_data
            ) as response:
                response.raise_for_status()
                data = await response.json()
                
                if data.get('query_status') == 'ok':
                    for item in data.get('data', []):
                        yield item
                        
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error collecting from MalwareBazaar: {e}")
            raise
    
    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse MalwareBazaar sample"""
        sha256_hash = raw_item.get('sha256_hash')
        malware_bazaar_id = raw_item.get('sha256_hash')  # Using hash as ID
        
        if not sha256_hash:
            return None
        
        signature = raw_item.get('signature')
        file_type = raw_item.get('file_type')
        file_size = raw_item.get('file_size')
        
        return {
            'indicator_type': 'file_hash',
            'value': sha256_hash,
            'hash_type': 'sha256',
            'threat_types': ['malware'],
            'confidence': 'verified',
            'severity': 9,
            'description': f'Malware sample: {signature or "Unknown"}',
            'tags': ['malware', 'sample', signature.lower() if signature else 'unknown'],
            'metadata': {
                'signature': signature,
                'file_type': file_type,
                'file_size': file_size,
                'first_seen': raw_item.get('first_seen'),
                'last_seen': raw_item.get('last_seen'),
                'reporter': raw_item.get('reporter'),
                'intelligence': raw_item.get('intelligence', {})
            },
            'expires_at': datetime.now(timezone.utc) + timedelta(days=365)  # Hashes don't expire
        }

class ThreatFoxCollector(HTTPCollector):
    """Collector for ThreatFox IOCs"""
    
    def __init__(self, source):
        super().__init__(source)
        if not source.url:
            source.url = "https://threatfox-api.abuse.ch/api/v1/"
        
        # Get recent IOCs
        self.query_data = {
            "query": "get_iocs",
            "days": 1  # Last 24 hours
        }
    
    async def collect_data(self):
        """Collect recent IOCs"""
        try:
            async with self.session.post(
                self.source.url,
                json=self.query_data,
                headers={'Content-Type': 'application/json'}
            ) as response:
                response.raise_for_status()
                data = await response.json()
                
                if data.get('query_status') == 'ok':
                    for item in data.get('data', []):
                        yield item
                        
        except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
            logger.error(f"Error collecting from ThreatFox: {e}")
            raise
    
    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse ThreatFox IOC"""
        ioc_value = raw_item.get('ioc')
        ioc_type = raw_item.get('ioc_type')
        malware = raw_item.get('malware')
        confidence_level = raw_item.get('confidence_level')
        
        if not ioc_value or not ioc_type:
            return None
        
        # Map ThreatFox IOC types to our types
        type_mapping = {
            'ip:port': 'ip_address',
            'domain': 'domain',
            'url': 'url',
            'md5_hash': 'file_hash',
            'sha1_hash': 'file_hash',
            'sha256_hash': 'file_hash'
        }
        
        indicator_type = type_mapping.get(ioc_type.lower())
        if not indicator_type:
            return None
        
        # Extract IP from ip:port format
        if ioc_type.lower() == 'ip:port':
            ioc_value = ioc_value.split(':')[0]
        
        # Map confidence levels
        confidence_mapping = {
            'high': 'high',
            'medium': 'medium',
            'low': 'low'
        }
        confidence = confidence_mapping.get(confidence_level, 'medium')
        
        return {
            'indicator_type': indicator_type,
            'value': ioc_value,
            'hash_type': ioc_type.replace('_hash', '') if 'hash' in ioc_type else None,
            'threat_types': ['malware'],
            'confidence': confidence,
            'severity': 8 if confidence == 'high' else 6,
            'description': f'{malware} IOC from ThreatFox',
            'tags': ['malware', 'ioc', malware.lower() if malware else 'unknown'],
            'metadata': {
                'malware_family': malware,
                'threat_type': raw_item.get('threat_type'),
                'malware_alias': raw_item.get('malware_alias'),
                'malware_printable': raw_item.get('malware_printable'),
                'first_seen': raw_item.get('first_seen'),
                'last_seen': raw_item.get('last_seen'),
                'reporter': raw_item.get('reporter'),
                'reference': raw_item.get('reference')
            },
            'expires_at': datetime.now(timezone.utc) + timedelta(days=90)
        }


# Register all collectors
from app.collectors import CollectorRegistry

CollectorRegistry.register_collector('http', HTTPCollector)
CollectorRegistry.register_collector('malware_domain_list', MalwareDomainListCollector)
CollectorRegistry.register_collector('abuseipdb', AbuseIPDBCollector)
CollectorRegistry.register_collector('urlvoid', URLVoidCollector)
CollectorRegistry.register_collector('phishtank', PhishTankCollector)
CollectorRegistry.register_collector('feodo_tracker', FeodoTrackerCollector)
CollectorRegistry.register_collector('malwarebazaar', MalwareBazaarCollector)
CollectorRegistry.register_collector('threatfox', ThreatFoxCollector)
