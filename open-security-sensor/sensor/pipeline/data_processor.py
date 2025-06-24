"""
Data Processor

This module processes raw telemetry data from collectors, performing:
- Data validation and sanitization
- Enrichment with additional context
- Normalization to standard formats
- Filtering and noise reduction
"""

import asyncio
import json
import logging
import socket
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import hashlib
import platform

from sensor.core.config import SensorConfig
from sensor.utils.platform import get_platform_info

logger = logging.getLogger(__name__)

class DataProcessor:
    """Process and enrich telemetry data"""
    
    def __init__(self, config: SensorConfig, input_queue: asyncio.Queue, output_queue: asyncio.Queue):
        self.config = config
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.running = False
        
        # Processor statistics
        self.stats = {
            'events_processed': 0,
            'events_enriched': 0,
            'events_filtered': 0,
            'errors': 0
        }
        
        # Cache for enrichment data
        self.hostname = socket.gethostname()
        self.platform_info = get_platform_info()
        
        # Known process filters (to reduce noise)
        self.process_filters = [
            # System processes that are noisy but usually benign
            'kworker/',
            'ksoftirqd/',
            'rcu_',
            'watchdog/',
            'systemd',
            'dbus',
            '[',  # Kernel threads in brackets
        ]
    
    async def start(self):
        """Start data processing"""
        logger.info("Starting data processor")
        self.running = True
        
        # Start processing tasks
        for i in range(self.config.performance.worker_threads):
            asyncio.create_task(self._process_events())
        
        logger.info(f"Data processor started with {self.config.performance.worker_threads} workers")
    
    async def stop(self):
        """Stop data processing"""
        logger.info("Stopping data processor")
        self.running = False
    
    async def _process_events(self):
        """Main event processing loop"""
        while self.running:
            try:
                # Get event from input queue with timeout
                event = await asyncio.wait_for(self.input_queue.get(), timeout=1.0)
                
                # Process the event
                processed_event = await self._process_single_event(event)
                
                if processed_event:
                    # Forward to output queue
                    await self.output_queue.put(processed_event)
                    self.stats['events_processed'] += 1
                else:
                    self.stats['events_filtered'] += 1
                
            except asyncio.TimeoutError:
                # No events available, continue
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing event: {e}")
                self.stats['errors'] += 1
                await asyncio.sleep(0.1)
    
    async def _process_single_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single event"""
        try:
            # Apply filters first
            if self._should_filter_event(event):
                return None
            
            # Create base processed event
            processed_event = {
                'id': self._generate_event_id(event),
                'timestamp': event.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'source': event.get('source', 'unknown'),
                'type': event.get('type', 'unknown'),
                'data': event.get('data', {}),
                'metadata': event.get('metadata', {}),
                'host': {
                    'hostname': self.hostname,
                    'platform': self.platform_info['system'],
                    'architecture': self.platform_info['architecture'][0]
                }
            }
            
            # Apply enrichment based on event type
            processed_event = await self._enrich_event(processed_event)
            
            # Normalize data structures
            processed_event = self._normalize_event(processed_event)
            
            self.stats['events_enriched'] += 1
            return processed_event
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return None
    
    def _should_filter_event(self, event: Dict[str, Any]) -> bool:
        """Determine if event should be filtered out"""
        
        # Filter based on event type and content
        event_type = event.get('type', '')
        data = event.get('data', {})
        
        # Filter noisy process events
        if 'process' in event_type.lower():
            if isinstance(data, list):
                # Filter entire list if all processes are noisy
                filtered_data = []
                for item in data:
                    if not self._is_noisy_process(item):
                        filtered_data.append(item)
                
                if not filtered_data:
                    return True  # Filter out if no processes left
                
                # Update data with filtered list
                event['data'] = filtered_data
            
            elif isinstance(data, dict):
                if self._is_noisy_process(data):
                    return True
        
        # Filter empty events
        if not data:
            return True
        
        return False
    
    def _is_noisy_process(self, process_data: Dict[str, Any]) -> bool:
        """Check if process data represents a noisy/system process"""
        process_name = process_data.get('name', '')
        process_path = process_data.get('path', '')
        cmdline = process_data.get('cmdline', '')
        
        # Check against known noisy process patterns
        for filter_pattern in self.process_filters:
            if (filter_pattern in process_name or 
                filter_pattern in process_path or 
                filter_pattern in cmdline):
                return True
        
        return False
    
    async def _enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with additional context"""
        
        event_type = event.get('type', '')
        data = event.get('data', {})
        
        # Enrich network events
        if 'network' in event_type.lower() or 'socket' in event_type.lower():
            event = await self._enrich_network_event(event)
        
        # Enrich process events
        elif 'process' in event_type.lower():
            event = self._enrich_process_event(event)
        
        # Enrich file events
        elif 'file' in event_type.lower():
            event = self._enrich_file_event(event)
        
        # Add common enrichments
        event['metadata'].update({
            'processed_at': datetime.now(timezone.utc).isoformat(),
            'processor_version': '1.0.0',
            'enriched': True
        })
        
        return event
    
    async def _enrich_network_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich network-related events"""
        data = event.get('data', {})
        
        # Handle both single items and lists
        items_to_process = data if isinstance(data, list) else [data]
        
        for item in items_to_process:
            # Enrich IP addresses
            remote_address = item.get('remote_address')
            if remote_address and remote_address != '0.0.0.0':
                item['remote_address_info'] = await self._get_ip_info(remote_address)
            
            local_address = item.get('local_address')
            if local_address and local_address not in ['0.0.0.0', '127.0.0.1', '::1']:
                item['local_address_info'] = await self._get_ip_info(local_address)
            
            # Categorize connection
            item['connection_category'] = self._categorize_connection(item)
        
        return event
    
    def _enrich_process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich process-related events"""
        data = event.get('data', {})
        
        # Handle both single items and lists
        items_to_process = data if isinstance(data, list) else [data]
        
        for item in items_to_process:
            # Categorize process
            item['process_category'] = self._categorize_process(item)
            
            # Add security risk indicators
            item['risk_indicators'] = self._get_process_risk_indicators(item)
            
            # Parse command line arguments
            cmdline = item.get('cmdline', '')
            if cmdline:
                item['cmdline_parsed'] = self._parse_cmdline(cmdline)
        
        return event
    
    def _enrich_file_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich file-related events"""
        data = event.get('data', {})
        
        file_path = data.get('path', '')
        if file_path:
            data['file_category'] = self._categorize_file(file_path)
            data['risk_level'] = self._get_file_risk_level(file_path, data)
        
        return event
    
    async def _get_ip_info(self, ip_address: str) -> Dict[str, Any]:
        """Get information about an IP address"""
        info = {
            'ip': ip_address,
            'is_private': self._is_private_ip(ip_address),
            'is_localhost': ip_address in ['127.0.0.1', '::1'],
            'reverse_dns': None
        }
        
        # Attempt reverse DNS lookup (with timeout)
        try:
            reverse_dns = await asyncio.wait_for(
                self._reverse_dns_lookup(ip_address),
                timeout=2.0
            )
            info['reverse_dns'] = reverse_dns
        except:
            pass  # Ignore DNS lookup failures
        
        return info
    
    async def _reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            loop = asyncio.get_event_loop()
            hostname = await loop.run_in_executor(
                None, socket.gethostbyaddr, ip_address
            )
            return hostname[0] if hostname else None
        except:
            return None
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is private"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except:
            return False
    
    def _categorize_connection(self, connection_data: Dict[str, Any]) -> str:
        """Categorize network connection"""
        remote_address = connection_data.get('remote_address', '')
        remote_port = connection_data.get('remote_port', 0)
        protocol = connection_data.get('protocol', '')
        
        # Common port categorizations
        if remote_port in [80, 443, 8080, 8443]:
            return 'web'
        elif remote_port in [22, 23, 3389]:
            return 'remote_access'
        elif remote_port in [25, 110, 143, 587, 993, 995]:
            return 'email'
        elif remote_port in [53]:
            return 'dns'
        elif remote_port in [21, 22, 989, 990]:
            return 'file_transfer'
        elif self._is_private_ip(remote_address):
            return 'internal'
        else:
            return 'other'
    
    def _categorize_process(self, process_data: Dict[str, Any]) -> str:
        """Categorize process"""
        name = process_data.get('name', '').lower()
        path = process_data.get('path', '').lower()
        
        if any(browser in name for browser in ['chrome', 'firefox', 'safari', 'edge']):
            return 'browser'
        elif any(sys_proc in name for sys_proc in ['systemd', 'kernel', 'init']):
            return 'system'
        elif 'python' in name or 'java' in name or 'node' in name:
            return 'interpreter'
        elif '/usr/bin' in path or '/bin' in path:
            return 'system_binary'
        elif 'powershell' in name or 'cmd' in name or 'bash' in name:
            return 'shell'
        else:
            return 'application'
    
    def _get_process_risk_indicators(self, process_data: Dict[str, Any]) -> List[str]:
        """Get risk indicators for a process"""
        indicators = []
        
        name = process_data.get('name', '').lower()
        cmdline = process_data.get('cmdline', '').lower()
        path = process_data.get('path', '').lower()
        
        # Check for suspicious patterns
        if 'powershell' in name and any(flag in cmdline for flag in ['-enc', '-hidden', '-noprofile']):
            indicators.append('suspicious_powershell')
        
        if any(susp in cmdline for susp in ['download', 'invoke-expression', 'iex', 'base64']):
            indicators.append('download_execution')
        
        if '/tmp' in path or 'temp' in path:
            indicators.append('temp_execution')
        
        if not process_data.get('on_disk', True):
            indicators.append('fileless_execution')
        
        return indicators
    
    def _parse_cmdline(self, cmdline: str) -> Dict[str, Any]:
        """Parse command line arguments"""
        parts = cmdline.split()
        
        return {
            'executable': parts[0] if parts else '',
            'arguments': parts[1:] if len(parts) > 1 else [],
            'argument_count': len(parts) - 1 if parts else 0,
            'contains_urls': 'http' in cmdline.lower(),
            'contains_ips': self._contains_ip_addresses(cmdline)
        }
    
    def _contains_ip_addresses(self, text: str) -> bool:
        """Check if text contains IP addresses"""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, text))
    
    def _categorize_file(self, file_path: str) -> str:
        """Categorize file based on path"""
        path_lower = file_path.lower()
        
        if '/etc/' in path_lower or 'windows/system32' in path_lower:
            return 'system_config'
        elif '/bin/' in path_lower or '/sbin/' in path_lower:
            return 'system_binary'
        elif '/home/' in path_lower or '/users/' in path_lower:
            return 'user_data'
        elif '/var/log/' in path_lower:
            return 'log_file'
        elif '/tmp/' in path_lower or 'temp' in path_lower:
            return 'temporary'
        else:
            return 'other'
    
    def _get_file_risk_level(self, file_path: str, file_data: Dict[str, Any]) -> str:
        """Determine risk level for file operations"""
        path_lower = file_path.lower()
        changes = file_data.get('changes', [])
        
        # Critical system files
        if any(critical in path_lower for critical in ['/etc/passwd', '/etc/shadow', 'windows/system32']):
            return 'critical'
        
        # System configuration changes
        if '/etc/' in path_lower and 'content' in changes:
            return 'high'
        
        # Temporary file execution
        if '/tmp/' in path_lower or 'temp' in path_lower:
            return 'medium'
        
        return 'low'
    
    def _normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize event data structures"""
        
        # Ensure all timestamps are in ISO format
        if 'timestamp' in event:
            event['timestamp'] = self._normalize_timestamp(event['timestamp'])
        
        # Normalize data field
        data = event.get('data', {})
        if isinstance(data, list):
            event['data'] = [self._normalize_data_item(item) for item in data]
        elif isinstance(data, dict):
            event['data'] = self._normalize_data_item(data)
        
        return event
    
    def _normalize_timestamp(self, timestamp: Any) -> str:
        """Normalize timestamp to ISO format"""
        if isinstance(timestamp, str):
            try:
                # Try to parse and reformat
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.isoformat()
            except:
                return timestamp
        elif isinstance(timestamp, (int, float)):
            # Unix timestamp
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.isoformat()
        else:
            return datetime.now(timezone.utc).isoformat()
    
    def _normalize_data_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single data item"""
        
        # Convert numeric strings to integers where appropriate
        for key in ['pid', 'ppid', 'uid', 'gid', 'port']:
            if key in item and isinstance(item[key], str) and item[key].isdigit():
                item[key] = int(item[key])
        
        # Normalize boolean values
        for key in ['on_disk', 'active']:
            if key in item:
                if isinstance(item[key], str):
                    item[key] = item[key].lower() in ['true', '1', 'yes']
        
        return item
    
    def _generate_event_id(self, event: Dict[str, Any]) -> str:
        """Generate unique ID for event"""
        # Create hash based on event content
        content = json.dumps(event, sort_keys=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        
        hash_input = f"{content}:{timestamp}".encode('utf-8')
        return hashlib.sha256(hash_input).hexdigest()[:16]
    
    def get_status(self) -> Dict[str, Any]:
        """Get processor status"""
        return {
            'running': self.running,
            'stats': self.stats.copy(),
            'queue_sizes': {
                'input': self.input_queue.qsize(),
                'output': self.output_queue.qsize()
            }
        }
