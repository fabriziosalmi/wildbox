"""
Log Forwarder

This module forwards system and application logs to the central data lake.
It can monitor log files, Windows Event Logs, and system journals.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, AsyncGenerator
import tempfile

from sensor.core.config import SensorConfig
from sensor.utils.platform import is_windows, is_linux, is_macos

logger = logging.getLogger(__name__)

class LogForwarder:
    """Forward system and application logs to data lake"""
    
    def __init__(self, config: SensorConfig, event_queue: asyncio.Queue):
        self.config = config
        self.event_queue = event_queue
        self.running = False
        
        # Log sources configuration
        self.log_sources = self._initialize_log_sources()
        
        # File tracking for tail operations
        self.file_positions: Dict[str, int] = {}
        
    def _initialize_log_sources(self) -> List[Dict[str, Any]]:
        """Initialize log sources based on platform"""
        sources = []
        
        if is_linux():
            sources.extend([
                {
                    'name': 'syslog',
                    'type': 'file',
                    'path': '/var/log/syslog',
                    'format': 'syslog',
                    'enabled': True
                },
                {
                    'name': 'auth',
                    'type': 'file',
                    'path': '/var/log/auth.log',
                    'format': 'syslog',
                    'enabled': True
                },
                {
                    'name': 'journald',
                    'type': 'journald',
                    'format': 'json',
                    'enabled': True
                },
                {
                    'name': 'nginx_access',
                    'type': 'file',
                    'path': '/var/log/nginx/access.log',
                    'format': 'nginx',
                    'enabled': False  # Optional
                },
                {
                    'name': 'apache_access',
                    'type': 'file',
                    'path': '/var/log/apache2/access.log',
                    'format': 'apache',
                    'enabled': False  # Optional
                }
            ])
        
        elif is_windows():
            sources.extend([
                {
                    'name': 'security',
                    'type': 'windows_event',
                    'log_name': 'Security',
                    'format': 'windows_event',
                    'enabled': True
                },
                {
                    'name': 'system',
                    'type': 'windows_event',
                    'log_name': 'System',
                    'format': 'windows_event',
                    'enabled': True
                },
                {
                    'name': 'application',
                    'type': 'windows_event',
                    'log_name': 'Application',
                    'format': 'windows_event',
                    'enabled': True
                }
            ])
        
        elif is_macos():
            sources.extend([
                {
                    'name': 'system_log',
                    'type': 'file',
                    'path': '/var/log/system.log',
                    'format': 'syslog',
                    'enabled': True
                },
                {
                    'name': 'unified_log',
                    'type': 'unified_log',
                    'format': 'json',
                    'enabled': True
                }
            ])
        
        # Filter enabled sources
        return [source for source in sources if source.get('enabled', False)]
    
    async def start(self):
        """Start log forwarding"""
        if not self.config.collection.log_forwarding:
            logger.info("Log forwarding is disabled")
            return
        
        logger.info("Starting log forwarder")
        self.running = True
        
        try:
            # Start monitoring tasks for each log source
            tasks = []
            for source in self.log_sources:
                if source['type'] == 'file':
                    tasks.append(self._monitor_file(source))
                elif source['type'] == 'journald':
                    tasks.append(self._monitor_journald(source))
                elif source['type'] == 'windows_event':
                    tasks.append(self._monitor_windows_events(source))
                elif source['type'] == 'unified_log':
                    tasks.append(self._monitor_unified_log(source))
            
            # Start all monitoring tasks
            for task in tasks:
                asyncio.create_task(task)
            
            logger.info(f"Log forwarder started with {len(tasks)} sources")
            
        except Exception as e:
            logger.error(f"Failed to start log forwarder: {e}")
            await self.stop()
            raise
    
    async def stop(self):
        """Stop log forwarding"""
        logger.info("Stopping log forwarder")
        self.running = False
    
    async def _monitor_file(self, source: Dict[str, Any]):
        """Monitor a log file for new entries"""
        file_path = Path(source['path'])
        source_name = source['name']
        
        if not file_path.exists():
            logger.warning(f"Log file does not exist: {file_path}")
            return
        
        logger.info(f"Starting file monitoring: {file_path}")
        
        # Initialize file position
        try:
            # Start from end of file for new logs
            self.file_positions[str(file_path)] = file_path.stat().st_size
        except Exception as e:
            logger.error(f"Error initializing file position for {file_path}: {e}")
            return
        
        while self.running:
            try:
                await self._read_file_updates(file_path, source)
                await asyncio.sleep(1)  # Check every second
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error monitoring file {file_path}: {e}")
                await asyncio.sleep(5)
    
    async def _read_file_updates(self, file_path: Path, source: Dict[str, Any]):
        """Read new lines from a log file"""
        file_path_str = str(file_path)
        
        try:
            current_size = file_path.stat().st_size
            last_position = self.file_positions.get(file_path_str, 0)
            
            if current_size < last_position:
                # File was rotated or truncated
                logger.info(f"Log file rotated: {file_path}")
                self.file_positions[file_path_str] = 0
                last_position = 0
            
            if current_size > last_position:
                # New content available
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    self.file_positions[file_path_str] = f.tell()
                
                # Process new lines
                for line in new_lines:
                    line = line.strip()
                    if line:
                        await self._process_log_line(line, source)
        
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
    
    async def _monitor_journald(self, source: Dict[str, Any]):
        """Monitor systemd journal for new entries"""
        logger.info("Starting journald monitoring")
        
        try:
            # Use journalctl to follow logs
            cmd = ['journalctl', '-f', '--output=json', '--no-pager']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            while self.running:
                try:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    
                    line_str = line.decode('utf-8').strip()
                    if line_str:
                        await self._process_journal_entry(line_str, source)
                
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error reading journald: {e}")
                    break
            
            # Cleanup
            try:
                process.terminate()
                await process.wait()
            except:
                pass
                
        except Exception as e:
            logger.error(f"Error starting journald monitoring: {e}")
    
    async def _monitor_windows_events(self, source: Dict[str, Any]):
        """Monitor Windows Event Log"""
        if not is_windows():
            return
        
        log_name = source['log_name']
        logger.info(f"Starting Windows Event Log monitoring: {log_name}")
        
        # This would require Windows-specific implementation
        # For now, we'll use a placeholder
        while self.running:
            try:
                # PowerShell command to get latest events
                cmd = [
                    'powershell',
                    '-Command',
                    'Get-EventLog -LogName', log_name, '-Newest', '10', '|', 'ConvertTo-Json'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and result.stdout:
                    try:
                        events = json.loads(result.stdout)
                        if not isinstance(events, list):
                            events = [events]
                        
                        for event in events:
                            await self._process_windows_event(event, source)
                    
                    except json.JSONDecodeError:
                        pass
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error monitoring Windows events: {e}")
                await asyncio.sleep(30)
    
    async def _monitor_unified_log(self, source: Dict[str, Any]):
        """Monitor macOS Unified Log"""
        if not is_macos():
            return
        
        logger.info("Starting macOS Unified Log monitoring")
        
        try:
            # Use log command to stream logs
            cmd = ['log', 'stream', '--style', 'json']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            while self.running:
                try:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    
                    line_str = line.decode('utf-8').strip()
                    if line_str:
                        await self._process_unified_log_entry(line_str, source)
                
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error reading unified log: {e}")
                    break
            
            # Cleanup
            try:
                process.terminate()
                await process.wait()
            except:
                pass
                
        except Exception as e:
            logger.error(f"Error starting unified log monitoring: {e}")
    
    async def _process_log_line(self, line: str, source: Dict[str, Any]):
        """Process a single log line"""
        try:
            parsed_log = self._parse_log_line(line, source['format'])
            
            if parsed_log:
                event = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'source': 'log_forwarder',
                    'type': f"log.{source['name']}",
                    'data': parsed_log,
                    'metadata': {
                        'log_source': source['name'],
                        'log_file': source.get('path', ''),
                        'format': source['format']
                    }
                }
                
                await self.event_queue.put(event)
        
        except Exception as e:
            logger.debug(f"Error processing log line: {e}")
    
    async def _process_journal_entry(self, entry: str, source: Dict[str, Any]):
        """Process a journald entry"""
        try:
            journal_data = json.loads(entry)
            
            event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'log_forwarder',
                'type': 'log.journald',
                'data': journal_data,
                'metadata': {
                    'log_source': 'journald',
                    'format': 'json'
                }
            }
            
            await self.event_queue.put(event)
        
        except Exception as e:
            logger.debug(f"Error processing journal entry: {e}")
    
    async def _process_windows_event(self, event: Dict[str, Any], source: Dict[str, Any]):
        """Process a Windows event"""
        try:
            processed_event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'log_forwarder',
                'type': f"log.windows.{source['log_name'].lower()}",
                'data': event,
                'metadata': {
                    'log_source': source['log_name'],
                    'format': 'windows_event'
                }
            }
            
            await self.event_queue.put(processed_event)
        
        except Exception as e:
            logger.debug(f"Error processing Windows event: {e}")
    
    async def _process_unified_log_entry(self, entry: str, source: Dict[str, Any]):
        """Process a macOS unified log entry"""
        try:
            log_data = json.loads(entry)
            
            event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'log_forwarder',
                'type': 'log.unified',
                'data': log_data,
                'metadata': {
                    'log_source': 'unified_log',
                    'format': 'json'
                }
            }
            
            await self.event_queue.put(event)
        
        except Exception as e:
            logger.debug(f"Error processing unified log entry: {e}")
    
    def _parse_log_line(self, line: str, format_type: str) -> Optional[Dict[str, Any]]:
        """Parse a log line based on its format"""
        
        if format_type == 'syslog':
            return self._parse_syslog(line)
        elif format_type == 'nginx':
            return self._parse_nginx_log(line)
        elif format_type == 'apache':
            return self._parse_apache_log(line)
        else:
            # Generic parsing
            return {
                'raw_message': line,
                'parsed_timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _parse_syslog(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse syslog format"""
        # Basic syslog pattern: timestamp hostname process[pid]: message
        syslog_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s*(.*)$'
        
        match = re.match(syslog_pattern, line)
        if match:
            timestamp, hostname, process, pid, message = match.groups()
            return {
                'timestamp': timestamp,
                'hostname': hostname,
                'process': process,
                'pid': pid,
                'message': message,
                'raw_message': line
            }
        
        return {'raw_message': line}
    
    def _parse_nginx_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse nginx access log format"""
        # Common nginx log format
        nginx_pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'
        
        match = re.match(nginx_pattern, line)
        if match:
            ip, timestamp, request, status, size, referer, user_agent = match.groups()
            return {
                'client_ip': ip,
                'timestamp': timestamp,
                'request': request,
                'status_code': int(status),
                'response_size': int(size),
                'referer': referer,
                'user_agent': user_agent,
                'raw_message': line
            }
        
        return {'raw_message': line}
    
    def _parse_apache_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse Apache access log format"""
        # Similar to nginx but might have slight differences
        return self._parse_nginx_log(line)  # Simplified for now
    
    def get_status(self) -> Dict[str, Any]:
        """Get log forwarder status"""
        return {
            'running': self.running,
            'log_sources': [
                {
                    'name': source['name'],
                    'type': source['type'],
                    'enabled': source.get('enabled', False)
                }
                for source in self.log_sources
            ],
            'monitored_files': len(self.file_positions)
        }
