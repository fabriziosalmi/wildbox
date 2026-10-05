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

# One osqueryi query: seconds it may take, and bytes it may print. Past
# either it is killed and yields nothing.
QUERY_TIMEOUT = 30
MAX_QUERY_OUTPUT = 16 * 1024 * 1024
# Bytes of what osqueryi says on its standard error kept for the log.
QUERY_STDERR_KEPT = 2048
# Seconds a killed osqueryi is given to end and close its output.
KILL_WAIT = 10


class _TooMuchOutput(Exception):
    """A query printed more than MAX_QUERY_OUTPUT."""


class OsqueryManager:
    """Manages osquery daemon and query execution"""
    
    def __init__(self, config: SensorConfig, event_queue: asyncio.Queue):
        self.config = config
        self.event_queue = event_queue
        self.process = None
        self.running = False
        # One osqueryi at a time: the collection cycle and the local API's
        # /api/v1/query do not start them side by side.
        self._query_lock = asyncio.Lock()
        
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
                'system_services': {
                    'query': self._get_services_query(),
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
        """Execute a single osquery query.

        osqueryi runs as a child process the event loop waits for without
        blocking (#745): it used to be a subprocess.run of up to 30 seconds
        in the loop, during which no batch was sent, no log was read and the
        local API did not answer. The query is bounded in time and in what
        it may print.
        """
        if not self.process or self.process.poll() is not None:
            raise RuntimeError("osquery daemon is not running")

        async with self._query_lock:
            return await self._run_osqueryi(query)

    async def _run_osqueryi(self, query: str) -> List[Dict[str, Any]]:
        """One osqueryi: its rows, or none when it fails, takes too long or
        prints too much."""
        # One argument: the query never passes through a shell.
        cmd = ['osqueryi', '--json', query]
        if is_windows():
            cmd[0] = 'osqueryi.exe'

        try:
            child = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            logger.error(f"Error executing osquery: {e}")
            return []

        try:
            output, said = await asyncio.wait_for(
                self._read_bounded(child), timeout=QUERY_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.error("osquery query timed out")
            return []
        except _TooMuchOutput:
            logger.error(
                "osquery query printed more than %d bytes: it is stopped and "
                "its result is not used",
                MAX_QUERY_OUTPUT,
            )
            return []
        finally:
            await self._end(child)

        if child.returncode != 0:
            logger.error(f"osquery query failed: {said}")
            return []

        # Parse JSON results
        try:
            results = json.loads(output)
            return results if isinstance(results, list) else []
        except (ValueError, RecursionError) as e:
            logger.error(f"Failed to parse osquery results: {e}")
            return []

    @staticmethod
    async def _end(child):
        """Whatever happened, the child does not outlive the query."""
        if child.returncode is None:
            try:
                child.kill()
            except (OSError, ProcessLookupError):
                pass

        async def emptied(stream):
            while await stream.read(64 * 1024):
                pass

        # Its pipes are read to their end while it is waited for: asyncio
        # does not report the exit of a child whose output is still unread.
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    emptied(child.stdout), emptied(child.stderr), child.wait()
                ),
                timeout=KILL_WAIT,
            )
        except asyncio.TimeoutError:
            # A process it started still holds its output open: the pipes
            # are closed on this side, so that nothing of the query is left.
            logger.error(
                "osqueryi (pid %s) was killed and its output did not end "
                "within %s seconds: it is closed",
                child.pid,
                KILL_WAIT,
            )
            transport = getattr(child, "_transport", None)
            if transport is not None:
                transport.close()

    @staticmethod
    async def _read_bounded(child):
        """What the child prints, and the end of what it says on its
        standard error; _TooMuchOutput past the bound."""

        async def printed() -> bytes:
            chunks, size = [], 0
            while True:
                chunk = await child.stdout.read(64 * 1024)
                if not chunk:
                    return b"".join(chunks)
                size += len(chunk)
                if size > MAX_QUERY_OUTPUT:
                    raise _TooMuchOutput()
                chunks.append(chunk)

        async def said() -> str:
            kept = b""
            while True:
                chunk = await child.stderr.read(4096)
                if not chunk:
                    return " ".join(kept.decode("utf-8", "replace").split())
                kept = (kept + chunk)[-QUERY_STDERR_KEPT:]

        readers = [asyncio.ensure_future(printed()), asyncio.ensure_future(said())]
        try:
            output, errors = await asyncio.gather(*readers)
            await child.wait()
            return output, errors
        finally:
            # Neither reader is left on a pipe when the other one gave up:
            # _end reads them to their end, and a stream has one reader.
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)

    def get_status(self) -> Dict[str, Any]:
        """Get osquery manager status"""
        return {
            'running': self.running,
            'process_alive': self.process is not None and self.process.poll() is None,
            'query_packs': list(self.query_packs.keys()),
            'total_queries': sum(len(pack['queries']) for pack in self.query_packs.values())
        }
    
    def _get_services_query(self) -> str:
        """Get platform-specific services query"""
        if is_linux():
            # systemd_units exposes none of name, status, pid, path or type.
            # Its columns are id, description, load_state, active_state,
            # sub_state, unit_file_state, following, object_path, job_id,
            # job_type, job_path, fragment_path, user, source_path -- so the
            # previous query failed outright, every collection cycle, with
            #
            #     osquery query failed: Error: no such column: name
            #
            # and the service inventory was permanently empty on the platform
            # this sensor is actually deployed on. Aliased to the names the rest
            # of the pipeline uses. There is no pid: systemd_units does not
            # carry one, and a fabricated column is worse than a missing one.
            return '''
                SELECT id AS name,
                       active_state AS status,
                       sub_state,
                       fragment_path AS path,
                       'systemd' AS service_type
                FROM systemd_units
                WHERE id LIKE '%.service'
            '''
        elif is_macos():
            # Unverified. The Linux query above was wrong in every column, and
            # these two were written the same way, but this machine has no
            # macOS or Windows osquery to check them against -- so they are
            # left as they are rather than changed on a guess.
            return '''
                SELECT name, status, pid, path, 'launchd' as service_type
                FROM launchd
            '''
        elif is_windows():
            # Windows services
            return '''
                SELECT name, status, pid, path, 'windows' as service_type
                FROM services
            '''
        else:
            # Fallback - try generic processes that might be services
            return '''
                SELECT name, 'unknown' as status, pid, path, 'process' as service_type
                FROM processes 
                WHERE name LIKE '%service%' OR name LIKE '%daemon%' OR name LIKE '%server%'
                LIMIT 50
            '''
    
