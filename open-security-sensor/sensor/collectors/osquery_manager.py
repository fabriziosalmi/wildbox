"""
osquery Manager for system telemetry collection

Runs the sensor's query packs through ``osqueryi``, one query at a time, every
``performance.query_interval`` seconds, and one-off queries for the local API:

- the processes running, with their user
- the sockets processes hold open
- the users logged in
- system inventory and configuration

Each answer is a picture of the host at the moment of the query, not a stream
of events. osquery's event tables (``process_events``, ``socket_events``,
``user_events``) are not queried (#745). They are filled by the event
publishers of a long-running osquery. Through osqueryi, in the sensor's
image, each answers no row and says "is event-based but events are
disabled", with ``--disable_events=false`` as without. The sensor ran those
three queries at every cycle for nothing.

There is no osqueryd either. The sensor started one, with the same packs as
its schedule, and never read what it wrote: its results went to a temporary
directory and its pipes were never read. As the sensor's user it enabled no
event publisher, so its event tables stayed empty too, and in the container
it reported that it could not create its extension socket. All it did was
run every query a second time.
"""

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

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
    """Runs the query packs, and one-off queries, through osqueryi"""

    def __init__(self, config: SensorConfig, event_queue: asyncio.Queue):
        self.config = config
        self.event_queue = event_queue
        self.running = False
        # Where osqueryi is, and the version it reported when the manager
        # started; None until then.
        self.osqueryi: Optional[str] = None
        self.osquery_version: Optional[str] = None
        self.queries_run = 0
        self.queries_failed = 0
        self.last_error: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        # One osqueryi at a time: the collection cycle and the local API's
        # /api/v1/query do not start them side by side.
        self._query_lock = asyncio.Lock()

        # Query packs based on enabled collection types
        self.query_packs = self._build_query_packs()

    def _build_query_packs(self) -> Dict[str, Dict[str, Any]]:
        """Build osquery query packs based on configuration.

        Every query of every pack runs once per collection cycle. A pack's
        name is the first part of its events' type ("process_events.
        process_tree"), which the pipeline and the data service's event
        types are keyed on: the names stay, though no pack reads an event
        table.
        """
        packs = {}

        # Processes pack
        if self.config.collection.process_events:
            packs['process_events'] = {
                'queries': {
                    'process_tree': {
                        'query': '''
                            SELECT p.pid, p.name, p.cmdline, p.parent, p.path, p.on_disk,
                                   p.resident_size, p.user_time, p.system_time, p.start_time,
                                   u.username, u.uid
                            FROM processes p
                            LEFT JOIN users u ON p.uid = u.uid;
                        ''',
                        'description': 'Current running processes with user context'
                    }
                }
            }

        # Network connections pack
        if self.config.collection.network_connections:
            packs['network'] = {
                'queries': {
                    'process_open_sockets': {
                        'query': '''
                            SELECT s.pid, s.fd, s.socket, s.family, s.protocol, s.local_address,
                                   s.local_port, s.remote_address, s.remote_port, s.state,
                                   p.name, p.cmdline, p.path
                            FROM process_open_sockets s
                            LEFT JOIN processes p ON s.pid = p.pid;
                        ''',
                        'description': 'Active network connections with process context'
                    }
                }
            }

        # Users pack
        if self.config.collection.user_events:
            user_queries = {
                'logged_in_users': {
                    'query': 'SELECT * FROM logged_in_users;',
                    'description': 'Currently logged in users'
                }
            }

            # Platform-specific user queries
            if is_linux():
                user_queries['sudoers'] = {
                    'query': 'SELECT * FROM sudoers;',
                    'description': 'Sudo configuration'
                }
            elif is_windows():
                # Unverified. windows_events is an event table too, and no
                # Windows osquery was at hand to see whether osqueryi
                # answers it: left as it was rather than removed on a guess.
                user_queries['logon_events'] = {
                    'query': '''
                        SELECT datetime, eventid, source, data
                        FROM windows_events
                        WHERE channel = 'Security' AND eventid IN (4624, 4625, 4634, 4647);
                    ''',
                    'description': 'Windows logon events'
                }

            packs['user_events'] = {'queries': user_queries}

        # System inventory pack
        if self.config.collection.system_inventory:
            inventory_queries = {
                'system_info': {
                    'query': 'SELECT * FROM system_info;',
                    'description': 'Basic system information'
                },
                'os_version': {
                    'query': 'SELECT * FROM os_version;',
                    'description': 'Operating system version'
                },
                'installed_applications': {
                    'query': 'SELECT * FROM programs;' if is_windows() else 'SELECT * FROM deb_packages UNION SELECT * FROM rpm_packages;',
                    'description': 'Installed applications and packages'
                },
                'startup_items': {
                    'query': 'SELECT * FROM startup_items;',
                    'description': 'System startup items'
                },
                'system_services': {
                    'query': self._get_services_query(),
                    'description': 'System services'
                }
            }

            # Platform-specific inventory
            if is_linux():
                inventory_queries.update({
                    'kernel_info': {
                        'query': 'SELECT * FROM kernel_info;',
                        'description': 'Kernel information'
                    },
                    'kernel_modules': {
                        'query': 'SELECT * FROM kernel_modules;',
                        'description': 'Loaded kernel modules'
                    }
                })

            packs['system_inventory'] = {'queries': inventory_queries}

        return packs

    @staticmethod
    def _binary() -> str:
        return 'osqueryi.exe' if is_windows() else 'osqueryi'

    async def start(self):
        """Check that osqueryi answers, then start the collection cycle"""
        logger.info("Starting osquery manager")

        self.osqueryi = shutil.which(self._binary())
        if self.osqueryi is None:
            raise RuntimeError("osquery not found. Please install osquery on this system.")
        # One real query: an osqueryi that is there and does not answer is
        # said now, not at every cycle.
        async with self._query_lock:
            rows = await self._run_osqueryi("SELECT version FROM osquery_info;")
        if not rows:
            raise RuntimeError(f"osqueryi does not answer a query: {self.last_error or 'no rows'}")
        version = rows[0].get('version') if isinstance(rows[0], dict) else None
        self.osquery_version = version if isinstance(version, str) else None

        self.running = True
        self._task = asyncio.create_task(self._collect_results())
        logger.info(
            "osquery manager started: osqueryi %s, %d queries in %d packs",
            self.osquery_version or "of an unknown version",
            sum(len(pack['queries']) for pack in self.query_packs.values()),
            len(self.query_packs),
        )

    async def stop(self):
        """Stop the collection cycle, and the query it is in"""
        logger.info("Stopping osquery manager")
        self.running = False
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

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
        if not self.running:
            raise RuntimeError("osquery manager is not running")

        async with self._query_lock:
            return await self._run_osqueryi(query)

    async def _run_osqueryi(self, query: str) -> List[Dict[str, Any]]:
        """One osqueryi: its rows, or none when it fails, takes too long or
        prints too much."""
        # One argument: the query never passes through a shell.
        cmd = [self._binary(), '--json', query]
        self.queries_run += 1

        try:
            child = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            return self._failed(f"Error executing osquery: {e}")

        try:
            output, said = await asyncio.wait_for(
                self._read_bounded(child), timeout=QUERY_TIMEOUT
            )
        except asyncio.TimeoutError:
            return self._failed("osquery query timed out")
        except _TooMuchOutput:
            return self._failed(
                f"osquery query printed more than {MAX_QUERY_OUTPUT} bytes: "
                f"it is stopped and its result is not used"
            )
        finally:
            await self._end(child)

        if child.returncode != 0:
            return self._failed(f"osquery query failed: {said}")

        # Parse JSON results
        try:
            results = json.loads(output)
            return results if isinstance(results, list) else []
        except (ValueError, RecursionError) as e:
            return self._failed(f"Failed to parse osquery results: {e}")

    def _failed(self, message: str) -> List[Dict[str, Any]]:
        """A query that yields nothing: counted, kept for the status, said."""
        self.queries_failed += 1
        self.last_error = message
        logger.error("%s", message)
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
            # None: the manager has not started, or found no osqueryi.
            'osqueryi': self.osqueryi,
            'osquery_version': self.osquery_version,
            'query_packs': list(self.query_packs.keys()),
            'total_queries': sum(len(pack['queries']) for pack in self.query_packs.values()),
            # Since the sensor started, the local API's queries included. A
            # failed query is one that yielded nothing: it exited with an
            # error, took too long, printed too much or printed no JSON.
            'queries_run': self.queries_run,
            'queries_failed': self.queries_failed,
            'last_error': self.last_error,
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
    
