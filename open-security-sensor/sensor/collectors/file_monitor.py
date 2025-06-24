"""
File Integrity Monitor (FIM)

This module monitors file system changes in critical directories and files,
detecting unauthorized modifications, deletions, and new file creations.
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
        """Initialize the list of paths to monitor"""
        for path_str in self.config.fim.paths:
            path = Path(path_str)
            if path.exists():
                self.monitored_paths.add(path)
                logger.debug(f"Added path to monitoring: {path}")
            else:
                logger.warning(f"Path does not exist, skipping: {path}")
    
    async def start(self):
        """Start file monitoring"""
        if not self.config.fim.enabled:
            logger.info("File integrity monitoring is disabled")
            return
        
        logger.info("Starting file integrity monitor")
        self.running = True
        
        try:
            # Perform initial scan to establish baseline
            await self._initial_scan()
            
            # Start monitoring task
            asyncio.create_task(self._monitor_files())
            
            logger.info("File integrity monitor started successfully")
            
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
                scan_start = time.time()
                changes_detected = 0
                
                # Scan all monitored paths
                for monitored_path in self.monitored_paths:
                    path_changes = await self._scan_path(monitored_path, is_initial=False)
                    changes_detected += path_changes
                
                self.last_scan_duration = time.time() - scan_start
                self.scan_count += 1
                
                if changes_detected > 0:
                    logger.info(f"Scan {self.scan_count} completed: {changes_detected} changes detected in {self.last_scan_duration:.2f}s")
                else:
                    logger.debug(f"Scan {self.scan_count} completed: no changes detected in {self.last_scan_duration:.2f}s")
                
                # Wait before next scan (configurable interval)
                await asyncio.sleep(60)  # Scan every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in file monitoring loop: {e}")
                await asyncio.sleep(30)
    
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
                'hash': await self._calculate_file_hash(file_path) if file_stat.st_size < 10 * 1024 * 1024 else None  # Hash files < 10MB
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
        return {
            'running': self.running,
            'monitored_paths': [str(p) for p in self.monitored_paths],
            'tracked_files': len(self.file_states),
            'scan_count': self.scan_count,
            'last_scan_duration': self.last_scan_duration
        }
