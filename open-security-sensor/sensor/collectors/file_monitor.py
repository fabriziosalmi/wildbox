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

A scan walks the watched paths, and reads every file under 10 MiB to hash
it, in a worker thread (#745). It used to do both in the event loop: for as
long as a scan took nothing else ran, no batch was sent, no log was read and
the local API did not answer. The work is bounded: only regular files are
read, never more than ``MAX_HASHED_BYTES`` of one, and at most
``fim.max_files`` files are watched.

The baseline outlives the process (``sensor.collectors.baseline_store``): it
is saved under ``data_dir``, and it is what the data service has been told,
so that what changed while the sensor was stopped, and what it had not
delivered when it stopped, is reported when it starts.
"""

import asyncio
import collections
import fnmatch
import hashlib
import logging
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from sensor.collectors.baseline_store import BaselineStore, under
from sensor.core.config import SensorConfig
from sensor.core.stop_limits import STATE_WRITE_SECONDS
from sensor.pipeline.delivery import DELIVERY_KEY, Delivery

logger = logging.getLogger(__name__)

# Seconds between two scans.
SCAN_INTERVAL = 60
# A file this large or larger is watched by its size, times, mode and owner,
# without a hash.
MAX_HASHED_BYTES = 10 * 1024 * 1024
# Seconds between two writes of the baseline, while it moves.
BASELINE_SAVE_INTERVAL = 5.0

_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)

State = Dict[str, Any]
# (kind, path, the state before, the state now, what changed)
Change = Tuple[str, str, Optional[State], Optional[State], List[str]]


class _Stopped(Exception):
    """The monitor stopped while a scan was running."""


@dataclass
class _Survey:
    """What one pass over the watched paths found."""

    # Every watched file after this pass.
    states: Dict[str, State]
    changes: List[Change] = field(default_factory=list)
    # Files found under each path that was looked at.
    files: Dict[str, int] = field(default_factory=dict)
    # Files found and not watched: fim.max_files was reached.
    over_limit: int = 0


def hash_file(path: str) -> Optional[str]:
    """SHA-256 of a regular file's content.

    None when it cannot be read, when what is opened is not a regular file
    (it was replaced since it was looked at), or when it has grown to
    ``MAX_HASHED_BYTES``. Opening never waits: a FIFO has no writer to wait
    for, and a device is not read.
    """
    try:
        fd = os.open(path, os.O_RDONLY | _O_NONBLOCK | _O_CLOEXEC | _O_BINARY)
    except OSError as e:
        logger.debug(f"Could not hash file {path}: {e}")
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        hasher = hashlib.sha256()
        left = MAX_HASHED_BYTES
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                return hasher.hexdigest()
            left -= len(chunk)
            if left <= 0:
                return None
            hasher.update(chunk)
    except OSError as e:
        logger.debug(f"Could not hash file {path}: {e}")
        return None
    finally:
        os.close(fd)


def state_of(path: str) -> State:
    """What the monitor compares of a file. Raises OSError when the file
    cannot be looked at."""
    found = os.stat(path)
    hashed = None
    if stat.S_ISREG(found.st_mode) and found.st_size < MAX_HASHED_BYTES:
        hashed = hash_file(path)
    return {
        "path": path,
        "size": found.st_size,
        "mtime": found.st_mtime,
        "ctime": found.st_ctime,
        "mode": found.st_mode,
        "uid": getattr(found, "st_uid", None),
        "gid": getattr(found, "st_gid", None),
        "hash": hashed,
    }


def detect_changes(old_state: State, new_state: State) -> List[str]:
    """Detect what changed between two file states"""
    changes = []

    if old_state["size"] != new_state["size"]:
        changes.append("size")

    if old_state["mtime"] != new_state["mtime"]:
        changes.append("mtime")

    if old_state["mode"] != new_state["mode"]:
        changes.append("permissions")

    if (
        old_state.get("hash")
        and new_state.get("hash")
        and old_state["hash"] != new_state["hash"]
    ):
        changes.append("content")

    if old_state.get("uid") != new_state.get("uid"):
        changes.append("owner")

    if old_state.get("gid") != new_state.get("gid"):
        changes.append("group")

    return changes


def _excluded(name: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _listed(
    root: str, patterns: Sequence[str], max_depth: int, stopped: threading.Event
) -> Tuple[List[str], List[str]]:
    """The files under ``root`` (itself, when it is not a directory), and
    the directories that could not be listed."""
    if not os.path.isdir(root):
        return [root], []
    paths: List[str] = []
    unlisted: List[str] = []

    def failed(error: OSError):
        unlisted.append(error.filename or root)

    top = len(Path(root).parts)
    for directory, dirs, files in os.walk(root, onerror=failed):
        if stopped.is_set():
            raise _Stopped()
        # Deeper than fim.max_depth is not looked at, nor walked.
        if len(Path(directory).parts) - top >= max_depth:
            dirs[:] = []
        else:
            dirs[:] = sorted(d for d in dirs if not _excluded(d, patterns))
        paths.extend(
            os.path.join(directory, name)
            for name in sorted(files)
            if not _excluded(name, patterns)
        )
    return paths, unlisted


def survey(
    roots: Sequence[Tuple[str, bool]],
    states: Dict[str, State],
    patterns: Sequence[str],
    max_depth: int,
    max_files: int,
    stopped: threading.Event,
) -> _Survey:
    """One pass over ``roots``, each with whether it is new to the monitor
    (what a new root holds is the baseline, and no change).

    It runs in a worker thread and touches nothing of the monitor's:
    ``states`` is its own copy of what the monitor last saw, which it
    brings up to date and returns with the changes.
    """
    result = _Survey(states=states)
    for root, fresh in roots:
        try:
            paths, unlisted = _listed(root, patterns, max_depth, stopped)
        except _Stopped:
            raise
        except Exception as e:
            # A path that cannot be walked does not end the scan of the
            # others, and nothing under it is changed or deleted meanwhile.
            logger.error(f"Error scanning path {root}: {e}")
            continue
        present: Set[str] = set()
        for path in paths:
            if stopped.is_set():
                raise _Stopped()
            try:
                current = state_of(path)
            except FileNotFoundError:
                # Gone since it was listed, or a link to nothing: if it was
                # watched, it is deleted, below.
                continue
            except Exception as e:
                # It is there and cannot be looked at: neither changed nor
                # deleted. Whatever the reason, the scan goes on.
                logger.debug(f"Error checking file {path}: {e}")
                present.add(path)
                continue
            present.add(path)
            old = states.get(path)
            if old is None:
                if len(states) >= max_files:
                    result.over_limit += 1
                    continue
                states[path] = current
                if not fresh:
                    result.changes.append(("created", path, None, current, []))
            else:
                what = detect_changes(old, current)
                if what:
                    states[path] = current
                    if not fresh:
                        result.changes.append(("modified", path, old, current, what))
        result.files[root] = len(present)
        if fresh:
            continue
        for path in [p for p in states if under(p, root) and p not in present]:
            # A directory that could not be listed says nothing about what
            # it holds.
            if any(under(path, directory) for directory in unlisted):
                continue
            result.changes.append(("deleted", path, states.pop(path), None, []))
    return result


class FileMonitor:
    """File integrity monitoring component"""

    def __init__(self, config: SensorConfig, event_queue: asyncio.Queue):
        self.config = config
        self.event_queue = event_queue
        self.running = False

        # What the monitor last saw of each watched file.
        self.file_states: Dict[str, State] = {}
        self.monitored_paths: Set[Path] = set()

        # Performance tracking
        self.scan_count = 0
        self.last_scan_duration = 0
        # Files found at the last scan and not watched: fim.max_files.
        self.files_over_limit = 0

        # What the data service has been told of each file: the baseline
        # that is saved. A file's entry follows file_states when the event
        # that reports its change is settled.
        self.baseline = BaselineStore(config.data_dir)
        self._accepted: Dict[str, State] = {}
        # The configured paths that have a baseline: what they hold is
        # compared with it, where a new path's content is taken as it is.
        self._known_roots: Set[str] = set()
        # Per file with changes on their way: how many, and the number of
        # the latest one settled (an older one settled after it changes
        # nothing).
        self._in_flight: Dict[str, List[int]] = {}
        self._sequence = 0
        self._baseline_dirty = False

        # The changes a scan found whose events are not queued yet, oldest
        # first. Every change goes through here (#765): a scan brings
        # ``file_states`` up to date before any of its events is queued, so
        # a change that was only in the scan's own list was forgotten when
        # the queueing ended early, by an error on another change or by the
        # stop: no later scan saw a difference. The scan of start() leaves
        # here what the queue has no room for, so that a full queue does
        # not keep the sensor from starting.
        self._deferred: collections.deque = collections.deque()
        # Changes found that could not be made into an event: said in the
        # log, counted here, and not in the saved baseline.
        self.changes_failed = 0

        self._stopped = threading.Event()
        self._tasks: List[asyncio.Task] = []
        self._scan_lock = asyncio.Lock()

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

    def _watch(self) -> Dict[str, Any]:
        """The settings that decide which files are watched: a baseline
        taken with others is not compared with."""
        return {
            "exclude_patterns": list(self.config.fim.exclude_patterns),
            "max_depth": self.config.fim.max_depth,
            "max_files": self.config.fim.max_files,
        }

    def _load_baseline(self):
        """Take up the saved baseline of the paths still configured."""
        loaded = self.baseline.load(self._watch())
        if loaded is None:
            return
        saved_at, roots, files = loaded
        configured = {str(Path(path)) for path in self.configured_paths}
        self._known_roots = {root for root in roots if root in configured}
        kept = {
            path: state
            for path, state in files.items()
            if any(under(path, root) for root in self._known_roots)
        }
        self._accepted = kept
        self.file_states = dict(kept)
        if self._known_roots:
            logger.info(
                "File integrity monitoring: comparing %s with the baseline "
                "saved at %s (%d files): what changed since is reported",
                ", ".join(sorted(self._known_roots)),
                saved_at,
                len(kept),
            )

    async def start(self):
        """Start file monitoring"""
        if not self.config.fim.enabled:
            logger.info("File integrity monitoring is disabled")
            return

        logger.info("Starting file integrity monitor")
        self.running = True
        self._stopped.clear()

        try:
            self._report_paths()
            self._load_baseline()

            # The first scan: the baseline of the paths that have none, and
            # what changed under the others since theirs was saved.
            await self._initial_scan()
            if self._stopped.is_set():
                # Stopped while it was starting.
                return
            if self.baseline.persistent and self._baseline_dirty:
                # The baseline of the paths that had none is on disk before
                # the monitor says it has started, when the disk answers:
                # with the limit every other write of it has. Without one,
                # a data directory that does not answer held the monitor's
                # start, and the sensor's behind it, for as long as it did
                # not (#788).
                try:
                    await asyncio.wait_for(self._save(), STATE_WRITE_SECONDS)
                except asyncio.TimeoutError:
                    logger.warning(
                        "File integrity monitoring: the first baseline was "
                        "not written within %.0f seconds of the monitor's "
                        "start: a write to %s has not ended. The monitor "
                        "starts, and reports changes against the baseline "
                        "it holds in memory; the write is tried again every "
                        "%.0f seconds. A sensor that is restarted before "
                        "one succeeds has no saved baseline for the paths "
                        "that had none: it takes what it finds under them "
                        "then as their baseline, and what changed there in "
                        "between is not reported",
                        STATE_WRITE_SECONDS,
                        self.baseline.directory,
                        BASELINE_SAVE_INTERVAL,
                    )

            # Start monitoring task
            self._tasks = [asyncio.create_task(self._monitor_files())]
            if self.baseline.persistent:
                self._tasks.append(asyncio.create_task(self._save_periodically()))

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
        """Stop file monitoring: the scan in progress, and a change that is
        waiting for room in the queue. Such a change stays out of the saved
        baseline, and is found again at the next start; the agent counts
        its event with what the queues held. The changes behind it, which
        have no event yet, are said here."""
        logger.info("Stopping file integrity monitor")
        self.running = False
        self._stopped.set()
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._deferred:
            logger.warning(
                "File integrity monitoring: stopped with %d changes found "
                "and not queued yet: %s",
                len(self._deferred),
                (
                    "they are not in the saved baseline, and are found "
                    "again when the sensor starts"
                    if self.baseline.persistent
                    else "they are not reported. data_dir is not set, so the "
                    "next start takes what it finds as its baseline"
                ),
            )
        # Not for longer than a collector may take: the write waits, in
        # its worker thread, for one that is stuck in another (a data
        # directory that does not answer), and this waited with it for as
        # long as the agent let it (#777).
        try:
            await asyncio.wait_for(self.write_baseline(), STATE_WRITE_SECONDS)
        except asyncio.TimeoutError:
            logger.warning(
                "The file monitor's baseline was not written within %.0f "
                "seconds of the monitor's stop: a write to %s has not ended",
                STATE_WRITE_SECONDS,
                self.baseline.directory,
            )

    async def _initial_scan(self):
        """Perform the first scan"""
        logger.info("Performing initial file system scan...")
        start_time = time.time()

        async with self._scan_lock:
            changes = await self._scan(wait=False)

        scan_duration = time.time() - start_time
        file_count = len(self.file_states)

        logger.info(
            f"Initial scan completed: scanned {file_count} files in {scan_duration:.2f} seconds"
        )
        if changes:
            logger.info(
                "File integrity monitoring: %d changes since the saved "
                "baseline, made while the sensor was stopped or not "
                "delivered before it stopped",
                changes,
            )
        if self._deferred:
            logger.warning(
                "File integrity monitoring: the queue is full: %d of these "
                "changes are reported as it empties",
                len(self._deferred),
            )

    async def _monitor_files(self):
        """Main monitoring loop"""
        logger.info("Starting file monitoring loop")

        try:
            # What the scan of start() left for when the queue has room.
            await self._hand_over()
        except asyncio.CancelledError:
            return

        while self.running:
            try:
                # start() has just scanned: the next scan is an interval away.
                await asyncio.sleep(SCAN_INTERVAL)
                changes_detected = await self._scan_once()

                if changes_detected > 0:
                    logger.info(
                        f"Scan {self.scan_count} completed: {changes_detected} changes detected in {self.last_scan_duration:.2f}s"
                    )
                else:
                    logger.debug(
                        f"Scan {self.scan_count} completed: no changes detected in {self.last_scan_duration:.2f}s"
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in file monitoring loop: {e}")
                await asyncio.sleep(30)

    async def _scan_once(self) -> int:
        """One pass: take up the paths that have appeared, then look for
        changes under every watched path. The number of changes found."""
        async with self._scan_lock:
            scan_start = time.time()
            changes_detected = await self._scan()
            self.last_scan_duration = time.time() - scan_start
            self.scan_count += 1
            return changes_detected

    async def _scan(self, wait: bool = True) -> int:
        """Look at the watched paths in a worker thread, then report what
        changed. Without ``wait``, what the queue has no room for is left in
        ``_deferred`` instead of being waited for."""
        appeared = [
            path_str
            for path_str in sorted(self.missing_paths)
            if Path(path_str).exists()
        ]
        self._note_vanished()
        roots = sorted(
            {str(path) for path in self.monitored_paths if path.exists()}
            | {str(Path(path_str)) for path_str in appeared}
        )
        try:
            found = await asyncio.to_thread(
                survey,
                [(root, root not in self._known_roots) for root in roots],
                dict(self.file_states),
                tuple(self.config.fim.exclude_patterns),
                self.config.fim.max_depth,
                self.config.fim.max_files,
                self._stopped,
            )
        except _Stopped:
            return 0
        self.file_states = found.states
        self._note_limit(found.over_limit)

        for root in roots:
            if root in self._known_roots:
                continue
            # What a new path holds is the baseline at once: nothing is
            # sent for it, so nothing is waited for.
            self._known_roots.add(root)
            for path, state in found.states.items():
                if under(path, root):
                    self._accepted[path] = state
            self._baseline_dirty = True

        for path_str in appeared:
            # What it holds now is the baseline: reporting every file of a
            # directory that was just mounted as created would bury the
            # changes that matter.
            self.missing_paths.discard(path_str)
            self.monitored_paths.add(Path(path_str))
            logger.info(
                "File integrity monitoring: %s exists now and is watched " "(%d files)",
                path_str,
                found.files.get(str(Path(path_str)), 0),
            )

        # In line first, all of them, and queued from there: file_states is
        # already past these changes, so the line is the only place that
        # still knows of one until its event is queued.
        self._deferred.extend(found.changes)
        await self._hand_over(wait)
        return len(found.changes)

    async def _hand_over(self, wait: bool = True):
        """Queue the events of the changes in line, oldest first. Without
        ``wait``, only for as long as the queue has room.

        A change leaves the line when its event is handed to the queue,
        which answers for it from then on, also when the monitor is stopped
        while it waits for room there. One that cannot be made into an
        event is said and counted, and the others follow: it used to end
        the pass, and the changes behind it were never reported.
        """
        handed = 0
        while self._deferred:
            if not wait and self.event_queue.full():
                return
            change = self._deferred.popleft()
            try:
                event = self._event_of(change)
            except Exception as e:
                self._not_reported(change, e)
                continue
            await self._queue(change, event)
            handed += 1
            if handed % 100 == 0:
                await asyncio.sleep(0)

    def _not_reported(self, change: Change, error: Exception):
        """A change no event could be made of. It stays out of the saved
        baseline, so a sensor with ``data_dir`` finds it again when it
        starts."""
        kind, path = change[0], change[1]
        self.changes_failed += 1
        logger.error(
            "File integrity monitoring: the change of %s (%s) could not be "
            "made into an event and is not reported: %s: %s",
            path,
            kind,
            type(error).__name__,
            error,
        )

    def _note_vanished(self):
        """Say when a watched path goes or comes back."""
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

    def _note_limit(self, over_limit: int):
        """Say, once, that there are more files than the monitor watches."""
        if over_limit and not self.files_over_limit:
            logger.warning(
                "File integrity monitoring: fim.paths hold more than "
                "fim.max_files (%d) files: %d are not watched. Raise "
                "fim.max_files, or watch less",
                self.config.fim.max_files,
                over_limit,
            )
        elif self.files_over_limit and not over_limit:
            logger.info(
                "File integrity monitoring: every file under fim.paths is "
                "watched again"
            )
        self.files_over_limit = over_limit

    def _event_of(self, change: Change) -> Dict[str, Any]:
        """The event of one change."""
        kind, path, old, new, what = change
        if kind == "created":
            event = self._created_event(path, new)
            logger.info(f"File created: {path}")
        elif kind == "modified":
            event = self._modified_event(path, old, new, what)
            logger.info(f"File modified: {path} (changes: {', '.join(what)})")
        else:
            event = self._deleted_event(path, old)
            logger.info(f"File deleted: {path}")
        return event

    async def _queue(self, change: Change, event: Dict[str, Any]):
        """Queue the event of one change. Its Delivery moves the saved
        baseline when the sensor has finished with the event."""
        path, new = change[1], change[3]
        self._sequence += 1
        sequence = self._sequence
        self._in_flight.setdefault(path, [0, 0])[0] += 1
        event[DELIVERY_KEY] = Delivery(
            lambda: self._settled(path, sequence, new),
            replayable=self.baseline.persistent,
        )
        await self.event_queue.put(event)

    def _settled(self, path: str, sequence: int, state: Optional[State]):
        """The event of a change was accepted, or dropped for good: the
        change is part of the baseline."""
        entry = self._in_flight.get(path)
        if entry is None:
            return
        entry[0] -= 1
        if sequence > entry[1]:
            entry[1] = sequence
            if state is None:
                self._accepted.pop(path, None)
            else:
                self._accepted[path] = state
            self._baseline_dirty = True
        if entry[0] <= 0:
            del self._in_flight[path]

    def _picture(self) -> tuple:
        """The baseline as it is now, numbered: taken on the event loop, so
        that a write made in a worker thread has a copy of its own, and one
        that reaches the disk late does not replace a later one."""
        self._baseline_dirty = False
        return (
            self._watch(),
            sorted(self._known_roots),
            dict(self._accepted),
            self.baseline.next_serial(),
        )

    def save_baseline(self) -> bool:
        """Write the baseline now, if it has moved since the last write.

        In the calling thread, which waits for a write in progress: not for
        the event loop, whose writes are ``write_baseline()``.
        """
        if not self.baseline.persistent or not self._baseline_dirty:
            return False
        if self.baseline.save(*self._picture()):
            return True
        self._baseline_dirty = True  # tried again at the next interval
        return False

    async def write_baseline(self) -> Optional[str]:
        """Write the baseline now, if it has moved since the last write, in
        a worker thread: the event loop never waits for the disk, nor for a
        write that is waiting for it.

        Why it could not be written, or None: it is written, or had not
        moved. It has no time limit of its own; a caller that has one gives
        it up (``asyncio.wait_for``), and the write is then left to its
        thread.
        """
        if not self.baseline.persistent or not self._baseline_dirty:
            return None
        return await self._save()

    async def _save(self) -> Optional[str]:
        """Write the baseline off the event loop; why it could not be."""
        picture = self._picture()
        loop = asyncio.get_running_loop()
        try:
            saved = await loop.run_in_executor(None, self.baseline.save, *picture)
        except asyncio.CancelledError:
            # Given up meanwhile: how the write ends is not known here, so
            # the next one is made whatever became of it.
            self._baseline_dirty = True
            raise
        if saved:
            return None
        self._baseline_dirty = True
        return self.baseline.problem or "the write failed"

    async def _save_periodically(self):
        """Write the baseline while it moves."""
        while self.running:
            await asyncio.sleep(BASELINE_SAVE_INTERVAL)
            if self._baseline_dirty:
                await self._save()

    def _created_event(self, file_path: str, state: State) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "fim",
            "type": "file_created",
            "data": {
                "path": file_path,
                "size": state["size"],
                "permissions": oct(state["mode"]),
                "hash": state.get("hash"),
            },
            "metadata": {"action": "create", "severity": "medium"},
        }

    def _modified_event(
        self, file_path: str, old_state: State, new_state: State, changes: List[str]
    ) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "fim",
            "type": "file_modified",
            "data": {
                "path": file_path,
                "changes": changes,
                "old_size": old_state["size"],
                "new_size": new_state["size"],
                "old_hash": old_state.get("hash"),
                "new_hash": new_state.get("hash"),
                "permissions": oct(new_state["mode"]),
            },
            "metadata": {
                "action": "modify",
                "severity": "high" if "content" in changes else "medium",
            },
        }

    def _deleted_event(self, file_path: str, old_state: State) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "fim",
            "type": "file_deleted",
            "data": {
                "path": file_path,
                "old_size": old_state.get("size"),
                "old_hash": old_state.get("hash"),
            },
            "metadata": {"action": "delete", "severity": "high"},
        }

    def get_status(self) -> Dict[str, Any]:
        """Get file monitor status"""
        watched = sorted(str(p) for p in self.monitored_paths if p.exists())
        # A file the sensor's user cannot read is still watched, by its
        # size, times, mode and owner, but a change of its content alone
        # (same size, restored times) is not seen. So is what is not a
        # regular file.
        unhashed = sum(
            1
            for state in self.file_states.values()
            if state.get("hash") is None and state.get("size", 0) < MAX_HASHED_BYTES
        )
        baseline = self.baseline.get_status()
        # Changes found whose events the data service has not taken yet:
        # they are not in the saved baseline.
        baseline["changes_not_delivered"] = len(self._deferred) + sum(
            entry[0] for entry in self._in_flight.values()
        )
        return {
            "running": self.running,
            # False: enabled, and no configured path exists.
            "watching": bool(watched),
            "configured_paths": list(self.configured_paths),
            "monitored_paths": watched,
            "missing_paths": [
                path for path in self.configured_paths if not Path(path).exists()
            ],
            "tracked_files": len(self.file_states),
            "unhashed_files": unhashed,
            "max_files": self.config.fim.max_files,
            # Found at the last scan and not watched: over max_files.
            "files_over_limit": self.files_over_limit,
            "scan_count": self.scan_count,
            "last_scan_duration": self.last_scan_duration,
            # Changes found that could not be made into an event: each is
            # in the log with its path.
            "changes_failed": self.changes_failed,
            "baseline": baseline,
        }
