"""
File Integrity Monitor (FIM)

This module monitors file system changes in critical directories and files,
detecting unauthorized modifications, deletions, and new file creations.

It watches the paths of ``fim.paths`` that exist. A path that does not exist
is not an error: it is said when the monitor starts, reported in the
monitor's status for as long as it is missing, and watched from the moment it
appears. When none of the configured paths exists the monitor says that it
is watching nothing (#725): the shipped container configuration names paths
under ``/host`` that no compose file mounts, and the monitor used to report
itself started over an empty set.
"""

import asyncio
import hashlib
import logging
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
import fnmatch

from sensor.core.config import SensorConfig
from sensor.utils.platform import is_windows, is_linux, is_macos

logger = logging.getLogger(__name__)

# Seconds between two scans.
SCAN_INTERVAL = 60
# A file this large or larger is watched by its size, times, mode and owner,
# without a hash.
MAX_HASHED_BYTES = 10 * 1024 * 1024


class FileMonitor:
    """File integrity monitoring component"""
    
    def __init__(self, config: SensorConfig, event_queue: asyncio.Queue):
        self.config = config
        self.event_queue = event_queue
        self.running = False
        
        # File state tracking
        self.file_states: Dict[str, Dict[str, Any]] = {}
        self.monitored_paths: Set[Path] = set()
        
        # Performance tracking
        self.scan_count = 0
        self.last_scan_duration = 0
        
        # Initialize monitored paths
        self._initialize_paths()
    
    def _initialize_paths(self):
        """Sort the configured paths into those that exist, which are
        watched, and those that do not."""
        # In the configuration's order, each once.
        self.configured_paths: List[str] = list(dict.fromkeys(self.config.fim.paths))
        # Missing when the monitor last looked; a path leaves this set the
        # moment it appears and is watched from then on.
        self.missing_paths: Set[str] = set()
        # Watched paths that have since gone, so that it is said once.
        self._vanished: Set[str] = set()
        for path_str in self.configured_paths:
            path = Path(path_str)
            if path.exists():
                self.monitored_paths.add(path)
                logger.debug(f"Added path to monitoring: {path}")
            else:
                self.missing_paths.add(path_str)

    def _report_paths(self):
        """Say which configured paths are not watched, and whether anything
        is watched at all."""
        for path_str in self.configured_paths:
            if path_str in self.missing_paths:
                logger.warning(
                    "File integrity monitoring: %s does not exist and is not "
                    "watched. fim.paths are this sensor's own paths (in a "
                    "container, the container's): mount the directory "
                    "read-only, or remove the path. It is watched as soon as "
                    "it appears",
                    path_str,
                )
        if not self.monitored_paths:
            logger.warning(
                "File integrity monitoring is enabled and none of the %d "
                "paths in fim.paths exists: it is watching nothing",
                len(self.configured_paths),
            )

    async def start(self):
        """Start file monitoring"""
        if not self.config.fim.enabled:
            logger.info("File integrity monitoring is disabled")
            return

        logger.info("Starting file integrity monitor")
        self.running = True

        try:
            self._report_paths()

            # Perform initial scan to establish baseline
            await self._initial_scan()

            # Start monitoring task
            asyncio.create_task(self._monitor_files())

            if self.monitored_paths:
                logger.info(
                    "File integrity monitor started: watching %s",
                    ", ".join(sorted(str(path) for path in self.monitored_paths)),
                )
            else:
                logger.info("File integrity monitor started: watching nothing")

        except Exception as e:
            logger.error(f"Failed to start file monitor: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Stop file monitoring"""
        logger.info("Stopping file integrity monitor")
        self.running = False
    
    async def _initial_scan(self):
        """Perform initial scan to establish baseline"""
        logger.info("Performing initial file system scan...")
        start_time = time.time()
        
        for monitored_path in self.monitored_paths:
            await self._scan_path(monitored_path, is_initial=True)
        
        scan_duration = time.time() - start_time
        file_count = len(self.file_states)
        
        logger.info(f"Initial scan completed: scanned {file_count} files in {scan_duration:.2f} seconds")
    
    async def _monitor_files(self):
        """Main monitoring loop"""
        logger.info("Starting file monitoring loop")

        while self.running:
            try:
                changes_detected = await self._scan_once()

                if changes_detected > 0:
                    logger.info(f"Scan {self.scan_count} completed: {changes_detected} changes detected in {self.last_scan_duration:.2f}s")
                else:
                    logger.debug(f"Scan {self.scan_count} completed: no changes detected in {self.last_scan_duration:.2f}s")

                # Wait before next scan
                await asyncio.sleep(SCAN_INTERVAL)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in file monitoring loop: {e}")
                await asyncio.sleep(30)

    async def _scan_once(self) -> int:
        """One pass: take up the paths that have appeared, then look for
        changes under every watched path. The number of changes found."""
        scan_start = time.time()
        await self._refresh_paths()

        changes_detected = 0
        for monitored_path in list(self.monitored_paths):
            changes_detected += await self._scan_path(monitored_path, is_initial=False)

        self.last_scan_duration = time.time() - scan_start
        self.scan_count += 1
        return changes_detected

    async def _refresh_paths(self):
        """Watch the configured paths that exist now and did not before,
        and say when a watched path goes or comes back."""
        for path_str in sorted(self.missing_paths):
            path = Path(path_str)
            if not path.exists():
                continue
            # What it holds now is the baseline: reporting every file of a
            # directory that was just mounted as created would bury the
            # changes that matter.
            before = len(self.file_states)
            await self._scan_path(path, is_initial=True)
            self.missing_paths.discard(path_str)
            self.monitored_paths.add(path)
            logger.info(
                "File integrity monitoring: %s exists now and is watched "
                "(%d files)",
                path_str,
                len(self.file_states) - before,
            )

        for path in self.monitored_paths:
            path_str = str(path)
            if path.exists():
                if path_str in self._vanished:
                    self._vanished.discard(path_str)
                    logger.info(
                        "File integrity monitoring: %s is back; what changed "
                        "meanwhile is reported",
                        path_str,
                    )
            elif path_str not in self._vanished:
                self._vanished.add(path_str)
                logger.warning(
                    "File integrity monitoring: %s no longer exists: nothing "
                    "under it is watched until it is back",
                    path_str,
                )

    async def _scan_path(self, path: Path, is_initial: bool = False) -> int:
        """Scan a single path for changes"""
        changes_detected = 0
        
        try:
            if path.is_file():
                # Single file
                if await self._check_file(path, is_initial):
                    changes_detected += 1
            elif path.is_dir():
                # Directory
                changes_detected += await self._scan_directory(path, is_initial)
        
        except PermissionError:
            logger.debug(f"Permission denied accessing: {path}")
        except Exception as e:
            logger.error(f"Error scanning path {path}: {e}")
        
        return changes_detected
    
    async def _scan_directory(self, directory: Path, is_initial: bool = False) -> int:
        """Scan a directory recursively"""
        changes_detected = 0
        current_files = set()
        
        try:
            for root, dirs, files in os.walk(directory):
                root_path = Path(root)
                
                # Check depth limit
                depth = len(root_path.parts) - len(directory.parts)
                if depth > self.config.fim.max_depth:
                    continue
                
                # Skip excluded directories
                dirs[:] = [d for d in dirs if not self._should_exclude(d)]
                
                # Process files
                for filename in files:
                    if self._should_exclude(filename):
                        continue
                    
                    file_path = root_path / filename
                    current_files.add(str(file_path))
                    
                    try:
                        if await self._check_file(file_path, is_initial):
                            changes_detected += 1
                    except Exception as e:
                        logger.debug(f"Error checking file {file_path}: {e}")
                
                # Yield control periodically
                if changes_detected % 100 == 0:
                    await asyncio.sleep(0)
        
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
        
        # Check for deleted files (only on non-initial scans)
        if not is_initial:
            directory_str = str(directory)
            deleted_files = [
                file_path for file_path in self.file_states.keys()
                if file_path.startswith(directory_str) and file_path not in current_files
            ]
            
            for deleted_file in deleted_files:
                await self._handle_file_deleted(deleted_file)
                changes_detected += 1
        
        return changes_detected
    
    async def _check_file(self, file_path: Path, is_initial: bool = False) -> bool:
        """Check a single file for changes"""
        file_path_str = str(file_path)
        
        try:
            # Get file statistics
            file_stat = file_path.stat()
            current_state = {
                'path': file_path_str,
                'size': file_stat.st_size,
                'mtime': file_stat.st_mtime,
                'ctime': file_stat.st_ctime,
                'mode': file_stat.st_mode,
                'uid': getattr(file_stat, 'st_uid', None),
                'gid': getattr(file_stat, 'st_gid', None),
                'hash': await self._calculate_file_hash(file_path) if file_stat.st_size < MAX_HASHED_BYTES else None
            }
            
            # Check if this is a new file or changed file
            if file_path_str not in self.file_states:
                # New file
                self.file_states[file_path_str] = current_state
                if not is_initial:
                    await self._handle_file_created(file_path_str, current_state)
                    return True
            else:
                # Existing file - check for changes
                old_state = self.file_states[file_path_str]
                changes = self._detect_changes(old_state, current_state)
                
                if changes and not is_initial:
                    self.file_states[file_path_str] = current_state
                    await self._handle_file_modified(file_path_str, old_state, current_state, changes)
                    return True
                elif changes:
                    # Update state during initial scan
                    self.file_states[file_path_str] = current_state
        
        except FileNotFoundError:
            # File was deleted
            if file_path_str in self.file_states and not is_initial:
                await self._handle_file_deleted(file_path_str)
                return True
        except Exception as e:
            logger.debug(f"Error checking file {file_path}: {e}")
        
        return False
    
    def _detect_changes(self, old_state: Dict[str, Any], new_state: Dict[str, Any]) -> List[str]:
        """Detect what changed between two file states"""
        changes = []
        
        if old_state['size'] != new_state['size']:
            changes.append('size')
        
        if old_state['mtime'] != new_state['mtime']:
            changes.append('mtime')
        
        if old_state['mode'] != new_state['mode']:
            changes.append('permissions')
        
        if old_state.get('hash') and new_state.get('hash') and old_state['hash'] != new_state['hash']:
            changes.append('content')
        
        if old_state.get('uid') != new_state.get('uid'):
            changes.append('owner')
        
        if old_state.get('gid') != new_state.get('gid'):
            changes.append('group')
        
        return changes
    
    async def _calculate_file_hash(self, file_path: Path) -> Optional[str]:
        """Calculate SHA-256 hash of file content"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.debug(f"Could not hash file {file_path}: {e}")
            return None
    
    def _should_exclude(self, filename: str) -> bool:
        """Check if file should be excluded based on patterns"""
        for pattern in self.config.fim.exclude_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False
    
    async def _handle_file_created(self, file_path: str, state: Dict[str, Any]):
        """Handle file creation event"""
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'fim',
            'type': 'file_created',
            'data': {
                'path': file_path,
                'size': state['size'],
                'permissions': oct(state['mode']),
                'hash': state.get('hash')
            },
            'metadata': {
                'action': 'create',
                'severity': 'medium'
            }
        }
        
        await self.event_queue.put(event)
        logger.info(f"File created: {file_path}")
    
    async def _handle_file_modified(self, file_path: str, old_state: Dict[str, Any], 
                                   new_state: Dict[str, Any], changes: List[str]):
        """Handle file modification event"""
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'fim',
            'type': 'file_modified',
            'data': {
                'path': file_path,
                'changes': changes,
                'old_size': old_state['size'],
                'new_size': new_state['size'],
                'old_hash': old_state.get('hash'),
                'new_hash': new_state.get('hash'),
                'permissions': oct(new_state['mode'])
            },
            'metadata': {
                'action': 'modify',
                'severity': 'high' if 'content' in changes else 'medium'
            }
        }
        
        await self.event_queue.put(event)
        logger.info(f"File modified: {file_path} (changes: {', '.join(changes)})")
    
    async def _handle_file_deleted(self, file_path: str):
        """Handle file deletion event"""
        old_state = self.file_states.pop(file_path, {})
        
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'fim',
            'type': 'file_deleted',
            'data': {
                'path': file_path,
                'old_size': old_state.get('size'),
                'old_hash': old_state.get('hash')
            },
            'metadata': {
                'action': 'delete',
                'severity': 'high'
            }
        }
        
        await self.event_queue.put(event)
        logger.info(f"File deleted: {file_path}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get file monitor status"""
        watched = sorted(str(p) for p in self.monitored_paths if p.exists())
        # A file the sensor's user cannot read is still watched, by its
        # size, times, mode and owner, but a change of its content alone
        # (same size, restored times) is not seen.
        unhashed = sum(
            1 for state in self.file_states.values()
            if state.get('hash') is None and state.get('size', 0) < MAX_HASHED_BYTES
        )
        return {
            'running': self.running,
            # False: enabled, and no configured path exists.
            'watching': bool(watched),
            'configured_paths': list(self.configured_paths),
            'monitored_paths': watched,
            'missing_paths': [
                path for path in self.configured_paths if not Path(path).exists()
            ],
            'tracked_files': len(self.file_states),
            'unhashed_files': unhashed,
            'scan_count': self.scan_count,
            'last_scan_duration': self.last_scan_duration
        }
