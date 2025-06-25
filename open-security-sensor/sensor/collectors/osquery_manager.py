"""
osquery Manager for system telemetry collection

This module manages osquery to collect comprehensive system telemetry including:
- Process events and ancestry
- Network connections
- User authentication events
- System inventory and configuration
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, AsyncGenerator
import yaml

from sensor.core.config import SensorConfig
from sensor.utils.platform import is_windows, is_linux, is_macos

logger = logging.getLogger(__name__)

class OsqueryManager:
    """Manages osquery daemon and query execution"""
    
    def __init__(self, config: SensorConfig, event_queue: asyncio.Queue):
        self.config = config
        self.event_queue = event_queue
        self.process = None
        self.running = False
        
        # Query packs based on enabled collection types
        self.query_packs = self._build_query_packs()
        
        # Osquery configuration
        self.osquery_config = self._build_osquery_config()
        
    def _build_query_packs(self) -> Dict[str, Dict[str, Any]]:
        """Build osquery query packs based on configuration"""
        packs = {}
        
        # Process events pack
        if self.config.collection.process_events:
            packs['process_events'] = {
                'queries': {
                    'process_events': {
                        'query': 'SELECT * FROM process_events;',
                        'interval': 5,
                        'description': 'Process creation and termination events'
                    },
                    'process_tree': {
                        'query': '''
                            SELECT p.pid, p.name, p.cmdline, p.parent, p.path, p.on_disk,
                                   p.resident_size, p.user_time, p.system_time, p.start_time,
                                   u.username, u.uid
                            FROM processes p
                            LEFT JOIN users u ON p.uid = u.uid;
                        ''',
                        'interval': 30,
                        'description': 'Current running processes with user context'
                    }
                }
            }
        
        # Network connections pack
        if self.config.collection.network_connections:
            packs['network'] = {
                'queries': {
                    'socket_events': {
                        'query': 'SELECT * FROM socket_events;',
                        'interval': 5,
                        'description': 'Network socket events'
                    },
                    'process_open_sockets': {
                        'query': '''
                            SELECT s.pid, s.fd, s.socket, s.family, s.protocol, s.local_address,
                                   s.local_port, s.remote_address, s.remote_port, s.state,
                                   p.name, p.cmdline, p.path
                            FROM process_open_sockets s
                            LEFT JOIN processes p ON s.pid = p.pid;
                        ''',
                        'interval': 15,
                        'description': 'Active network connections with process context'
                    }
                }
            }
        
        # User events pack
        if self.config.collection.user_events:
            user_queries = {
                'user_events': {
                    'query': 'SELECT * FROM user_events;',
                    'interval': 10,
                    'description': 'User login/logout events'
                },
                'logged_in_users': {
                    'query': 'SELECT * FROM logged_in_users;',
                    'interval': 60,
                    'description': 'Currently logged in users'
                }
            }
            
            # Platform-specific user queries
            if is_linux():
                user_queries['sudoers'] = {
                    'query': 'SELECT * FROM sudoers;',
                    'interval': 300,
                    'description': 'Sudo configuration'
                }
            elif is_windows():
                user_queries['logon_events'] = {
                    'query': '''
                        SELECT datetime, eventid, source, data
                        FROM windows_events
                        WHERE channel = 'Security' AND eventid IN (4624, 4625, 4634, 4647);
                    ''',
                    'interval': 30,
                    'description': 'Windows logon events'
                }
            
            packs['user_events'] = {'queries': user_queries}
        
        # System inventory pack
        if self.config.collection.system_inventory:
            inventory_queries = {
                'system_info': {
                    'query': 'SELECT * FROM system_info;',
                    'interval': 3600,
                    'description': 'Basic system information'
                },
                'os_version': {
                    'query': 'SELECT * FROM os_version;',
                    'interval': 3600,
                    'description': 'Operating system version'
                },
                'installed_applications': {
                    'query': 'SELECT * FROM programs;' if is_windows() else 'SELECT * FROM deb_packages UNION SELECT * FROM rpm_packages;',
                    'interval': 1800,
                    'description': 'Installed applications and packages'
                },
                'startup_items': {
                    'query': 'SELECT * FROM startup_items;',
                    'interval': 300,
                    'description': 'System startup items'
                },
                'services': {
                    'query': 'SELECT * FROM services;',
                    'interval': 300,
                    'description': 'System services'
                }
            }
            
            # Platform-specific inventory
            if is_linux():
                inventory_queries.update({
                    'kernel_info': {
                        'query': 'SELECT * FROM kernel_info;',
                        'interval': 3600,
                        'description': 'Kernel information'
                    },
                    'kernel_modules': {
                        'query': 'SELECT * FROM kernel_modules;',
                        'interval': 300,
                        'description': 'Loaded kernel modules'
                    }
                })
            
            packs['system_inventory'] = {'queries': inventory_queries}
        
        return packs
    
    def _build_osquery_config(self) -> Dict[str, Any]:
        """Build osquery daemon configuration"""
        config = {
            'options': {
                'config_plugin': 'filesystem',
                'logger_plugin': 'filesystem',
                'logger_path': tempfile.gettempdir(),
                'database_path': tempfile.gettempdir(),
                'utc': True,
                'verbose': False,
                'worker_threads': self.config.performance.worker_threads,
                'enable_monitor': True,
                'monitor_interval': 60
            },
            'schedule': {},
            'packs': {}
        }
        
        # Add query packs to schedule
        for pack_name, pack_config in self.query_packs.items():
            config['packs'][pack_name] = pack_config
        
        return config
    
    async def start(self):
        """Start osquery daemon"""
        logger.info("Starting osquery manager")
        self.running = True
        
        try:
            # Create osquery configuration file
            config_file = await self._create_config_file()
            
            # Start osquery daemon
            await self._start_osquery_daemon(config_file)
            
            # Start result collection
            asyncio.create_task(self._collect_results())
            
            logger.info("osquery manager started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start osquery manager: {e}")
            await self.stop()
            raise
    
    async def stop(self):
        """Stop osquery daemon"""
        logger.info("Stopping osquery manager")
        self.running = False
        
        if self.process:
            try:
                self.process.terminate()
                await asyncio.sleep(2)
                if self.process.poll() is None:
                    self.process.kill()
            except Exception as e:
                logger.error(f"Error stopping osquery process: {e}")
    
    async def _create_config_file(self) -> Path:
        """Create osquery configuration file"""
        config_file = Path(tempfile.gettempdir()) / 'osquery-sensor.conf'
        
        with open(config_file, 'w') as f:
            json.dump(self.osquery_config, f, indent=2)
        
        logger.debug(f"Created osquery config file: {config_file}")
        return config_file
    
    async def _start_osquery_daemon(self, config_file: Path):
        """Start osquery daemon process"""
        # Create a temporary directory for osquery runtime files
        osquery_runtime_dir = Path(tempfile.mkdtemp(prefix="osquery_"))
        logs_dir = osquery_runtime_dir / 'logs'
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        osquery_cmd = [
            'osqueryd', 
            '--config_path', str(config_file),
            '--pidfile', str(osquery_runtime_dir / 'osquery.pid'),
            '--database_path', str(osquery_runtime_dir),
            '--logger_path', str(logs_dir),
            '--disable_events=false',
            '--disable_audit=false'
        ]
        
        # Platform-specific adjustments
        if is_windows():
            osquery_cmd = ['osqueryd.exe', '--config_path', str(config_file)]
        
        logger.debug(f"Starting osquery with command: {' '.join(osquery_cmd)}")
        
        try:
            self.process = subprocess.Popen(
                osquery_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except FileNotFoundError:
            raise RuntimeError("osquery not found. Please install osquery on this system.")
        
        # Wait a moment and check if process started successfully
        await asyncio.sleep(2)
        if self.process.poll() is not None:
            stdout, stderr = self.process.communicate()
            raise RuntimeError(f"osquery failed to start: {stderr}")
    
    async def _collect_results(self):
        """Collect results from osquery and forward to event queue"""
        logger.info("Starting osquery result collection")
        
        while self.running:
            try:
                # Execute queries and collect results
                for pack_name, pack_config in self.query_packs.items():
                    for query_name, query_config in pack_config['queries'].items():
                        try:
                            results = await self.execute_query(query_config['query'])
                            
                            if results:
                                event = {
                                    'timestamp': datetime.now(timezone.utc).isoformat(),
                                    'source': 'osquery',
                                    'type': f"{pack_name}.{query_name}",
                                    'data': results,
                                    'metadata': {
                                        'query': query_config['query'],
                                        'description': query_config.get('description', '')
                                    }
                                }
                                
                                await self.event_queue.put(event)
                                logger.debug(f"Collected {len(results)} results for {pack_name}.{query_name}")
                        
                        except Exception as e:
                            logger.error(f"Error executing query {pack_name}.{query_name}: {e}")
                
                # Wait before next collection cycle
                await asyncio.sleep(self.config.performance.query_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in result collection: {e}")
                await asyncio.sleep(30)
    
    async def execute_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute a single osquery query"""
        if not self.process or self.process.poll() is not None:
            raise RuntimeError("osquery daemon is not running")
        
        try:
            # Use osqueryi for one-off queries
            cmd = ['osqueryi', '--json', query]
            if is_windows():
                cmd[0] = 'osqueryi.exe'
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"osquery query failed: {result.stderr}")
                return []
            
            # Parse JSON results
            try:
                results = json.loads(result.stdout)
                return results if isinstance(results, list) else []
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse osquery results: {e}")
                return []
        
        except subprocess.TimeoutExpired:
            logger.error("osquery query timed out")
            return []
        except Exception as e:
            logger.error(f"Error executing osquery: {e}")
            return []
    
    def get_status(self) -> Dict[str, Any]:
        """Get osquery manager status"""
        return {
            'running': self.running,
            'process_alive': self.process is not None and self.process.poll() is None,
            'query_packs': list(self.query_packs.keys()),
            'total_queries': sum(len(pack['queries']) for pack in self.query_packs.values())
        }
