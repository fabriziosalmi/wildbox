"""
Specific collector implementations for popular threat intelligence sources
"""

import csv
import io
import json
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

import aiohttp

from app.collectors import BaseCollector, HTTPCollector
from app.utils.log_safety import describe_error, host_of

logger = logging.getLogger(__name__)

class MalwareDomainListCollector(HTTPCollector):
    """Collector for Malware Domain List"""
    
    def __init__(self, source):
        super().__init__(source)
        if not source.url:
            source.url = "https://www.malwaredomainlist.com/hostslist/hosts.txt"
    
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
        self.base_url = "https://api.urlvoid.com/1000/{}/host/{}"
    
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
                    logger.error(
                        f"Error checking domain {domain}: {describe_error(e)}"
                    )
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
            logger.error(f"Error collecting from MalwareBazaar: {describe_error(e)}")
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
            logger.error(f"Error collecting from ThreatFox: {describe_error(e)}")
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

class NetAPIHoneypotCollector(HTTPCollector):
    """Collector for NetAPI's honeypot attacker IPs, an optional source.

    The feed is a CSV of the IPv4 addresses that attacked NetAPI's own
    honeypot sensors within the last 48 hours, rebuilt hourly, without a key,
    under CC BY 4.0 (https://netapi.com/compromised-ips/). Its header is
    ``ip,first_seen,last_seen,category,top_threat,threats,country,asn,as_name,sensors``.

    It is read with the csv module and not with HTTPCollector's line split:
    ``as_name`` is quoted and can hold a comma. A body without the columns
    the collector reads (an error page, a changed format) fails the run
    rather than collecting nothing and reporting success.
    """

    DEFAULT_URL = "https://netapi.com/api2/?method=compromised&dataset_type=ip&format=csv"
    REQUIRED_COLUMNS = ("ip", "category", "top_threat", "threats", "last_seen")
    # The feed's category of an address: its threat types, severity and tag.
    CATEGORIES = {
        "A": (["malware"], 8, "malware"),
        "B": (["suspicious"], 6, "password-guessing"),
        "C": (["exploit"], 7, "exploit"),
        "D": (["spam"], 4, "form-spam"),
    }
    # An address stays on the feed for 48 hours after its last attack.
    LISTED_FOR = timedelta(hours=48)
    TAG = re.compile(r'^[a-zA-Z0-9_-]+$')

    def __init__(self, source):
        super().__init__(source)
        if not source.url:
            source.url = self.DEFAULT_URL

    async def collect_data(self):
        url = self.source.url
        try:
            async with self.session.get(url) as response:
                response.raise_for_status()
                text = await response.text()
        except aiohttp.ClientError as e:
            logger.error(
                f"HTTP error collecting from {host_of(url)}: {describe_error(e)}"
            )
            raise

        reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
        missing = [c for c in self.REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(
                "The NetAPI feed answered without the columns " + ", ".join(missing)
            )
        rows = known = 0
        for row in reader:
            rows += 1
            if (row.get('category') or '').strip().upper() in self.CATEGORIES:
                known += 1
            yield row
        # A feed of attacks within 48 hours is never empty, and a row of no
        # category the collector knows is one it skips: a header alone, or
        # categories it does not know, is a changed feed, not a quiet day.
        if not rows:
            raise ValueError("The NetAPI feed answered with a header and no rows")
        if not known:
            raise ValueError("The NetAPI feed answered with no row of a known category")

    @staticmethod
    def _time(value: Optional[str]) -> Optional[datetime]:
        try:
            moment = datetime.fromisoformat((value or "").strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        # The feed's times are UTC; one without an offset is read as UTC, so
        # that expires_at compares with the service's aware clock.
        return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)

    @staticmethod
    def _int(value: Optional[str]) -> Optional[int]:
        try:
            return int((value or "").strip())
        except ValueError:
            return None

    def parse_item(self, raw_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse one row of the NetAPI feed"""
        ip_address = (raw_item.get('ip') or '').strip()
        category = (raw_item.get('category') or '').strip().upper()
        if not ip_address or category not in self.CATEGORIES:
            return None

        threat_types, severity, category_tag = self.CATEGORIES[category]
        top_threat = (raw_item.get('top_threat') or '').strip()
        threats = [t.strip() for t in (raw_item.get('threats') or '').split('|') if t.strip()]

        # A tag the validator would refuse would cost the whole indicator.
        tags = ['honeypot', 'netapi', category_tag]
        for threat in [top_threat] + threats:
            if threat and self.TAG.match(threat) and threat not in tags:
                tags.append(threat)

        # Without a readable time of the last attack the address is still on
        # the feed now, so it attacked within the last 48 hours: those count
        # from now.
        last_seen = self._time(raw_item.get('last_seen'))
        expires_from = last_seen or datetime.now(timezone.utc)

        return {
            'indicator_type': 'ip_address',
            'value': ip_address,
            'threat_types': list(threat_types),
            'confidence': 'high',
            'severity': severity,
            'description': f'Attacked NetAPI honeypot sensors: {top_threat or category_tag}',
            'tags': tags,
            'metadata': {
                'category': category,
                'top_threat': top_threat or None,
                'threats': threats,
                'first_seen': (raw_item.get('first_seen') or '').strip() or None,
                'last_seen': (raw_item.get('last_seen') or '').strip() or None,
                'country': (raw_item.get('country') or '').strip() or None,
                'asn': self._int(raw_item.get('asn')),
                'as_name': (raw_item.get('as_name') or '').strip() or None,
                'sensors': self._int(raw_item.get('sensors')),
            },
            'expires_at': expires_from + self.LISTED_FOR,
        }


# Register the collectors that can run. HTTPCollector itself is their base
# class: it has no parse_item and is not one of them.
from app.collectors import CollectorRegistry

CollectorRegistry.register_collector('malware_domain_list', MalwareDomainListCollector)
CollectorRegistry.register_collector('abuseipdb', AbuseIPDBCollector)
CollectorRegistry.register_collector('urlvoid', URLVoidCollector)
CollectorRegistry.register_collector('phishtank', PhishTankCollector)
CollectorRegistry.register_collector('feodo_tracker', FeodoTrackerCollector)
CollectorRegistry.register_collector('malwarebazaar', MalwareBazaarCollector)
CollectorRegistry.register_collector('threatfox', ThreatFoxCollector)
CollectorRegistry.register_collector('netapi_honeypot', NetAPIHoneypotCollector)
