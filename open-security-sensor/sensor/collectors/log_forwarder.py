"""
Log Forwarder

Forwards system and application logs to the data service: log files, the
systemd journal, the Windows Event Log and the macOS unified log.

What it reads is the configuration's ``log_sources`` section (#638). The
section used to be ignored: the forwarder read a fixed, per-platform list of
paths whatever the file said. That list is now only the default, used when
the configuration has no ``log_sources`` key at all.

A file source is tailed with these rules:

* It reads regular files only, and no file that resolves outside the
  directory the source names (``LogSourceConfig.root``): a link in a log
  directory that points at ``/etc/shadow`` is reported and not followed.
* The first time the sensor sees a source, a file that exists is read from
  its end (or from its beginning with ``read_from: beginning``). A file that
  appears later is read from its beginning.
* A source the sensor has seen before goes on where it stopped (#725): each
  file from the offset after the last line the data service accepted, kept
  in the data directory (``sensor.collectors.position_store``). The offset
  moves when an event is settled (``sensor.pipeline.delivery``), not when
  its line is read, so a sensor that stops or is killed with events still in
  it reads those lines again; ``read_from`` no longer applies to such a
  source. A saved position is used only for the file it was taken from: the
  same device and inode, still at least that long, with the same first
  bytes and the same bytes before the offset. Without ``data_dir`` positions
  are in memory only, and every start is a first time.
* A rotated file (renamed or removed, another one in its place) is read to its
  end before the new one is opened; a file truncated in place is read again
  from its beginning. Truncation shows by the file's size, by its first
  ``HEAD_BYTES`` bytes or by the ``CHECK_BYTES`` bytes before the position
  reached: a file rewritten to at least its old length with all of those
  unchanged cannot be told from one that was appended to.
* A line is forwarded when its newline has been written, never in two halves.
  A line longer than ``MAX_LINE_BYTES`` is forwarded once, cut to that
  length and marked ``truncated``.
* Bytes that are not UTF-8, and NUL bytes, become U+FFFD.
* Memory is bounded: it reads ``READ_CHUNK`` bytes at a time and waits for the
  event queue to take each line. When the data service is unreachable the
  queue fills, the forwarder stops reading, and the file is the buffer.

The systemd journal and the macOS unified log are read from a command that
follows them (``journalctl --follow``, ``log stream``):

* An entry is a line of the command's output. One longer than
  ``MAX_ENTRY_BYTES`` is forwarded once, as the text it begins with, marked
  ``truncated``; the rest of it is dropped as it arrives, so the memory held
  does not depend on what is logged. (The readers used to stop for good at
  the first entry over 64 KiB.)
* What the command writes to its standard error is read, so that it never
  blocks on it, and the last of it is kept for the log and the status.
* A command that ends is started again, after a delay that doubles from
  ``CHILD_RESTART_MIN`` to ``CHILD_RESTART_MAX`` seconds and starts over
  once a run has lasted ``CHILD_STABLE_SECONDS``.
* The journal is followed from the cursor of the last entry read, so a
  restart of the command neither skips nor repeats; the cursor of the last
  entry the data service accepted is saved with the file positions, and a
  restart of the sensor goes on from it. The unified log has no such
  position: ``log stream`` shows what is logged while it runs.

A Windows event log is asked, every ``WINDOWS_POLL_INTERVAL`` seconds, for
the events after the last record id read, oldest first, at most
``WINDOWS_MAX_EVENTS`` at a time; the query is a PowerShell command and runs
in a worker thread, not in the event loop. The first time, the log is
followed from its newest event on; the record id of the last event the data
service accepted is saved with the other positions. (The reader used to ask
for the ten newest events every 30 seconds and forward all ten each time,
from a blocking call in the event loop.) The PowerShell text has not been
run on Windows: see the README.

A path that does not exist, cannot be read or is refused is a warning that
names the source, logged once, and the source keeps being checked: logs appear
and rotate while the sensor runs. A source the configuration gets wrong (an
unknown type, a relative path) stops the sensor at start-up instead; see
``sensor.core.config.parse_log_sources``.
"""

import asyncio
import errno
import glob
import hashlib
import json
import logging
import os
import re
import stat
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from sensor.collectors.position_store import (
    CURSOR_PATTERN,
    MAX_FILES,
    PositionStore,
    file_entries,
)
from sensor.core.config import LogSourceConfig, SensorConfig, has_wildcard
from sensor.pipeline.delivery import DELIVERY_KEY, Delivery
from sensor.utils.platform import is_windows, is_linux, is_macos

logger = logging.getLogger(__name__)

# Seconds between two looks at a source that had nothing new.
POLL_INTERVAL = 1.0
# Seconds between two expansions of a glob pattern.
GLOB_INTERVAL = 5.0
# Bytes read from a file at a time.
READ_CHUNK = 64 * 1024
# Bytes read from one file before the source's other files get their turn.
MAX_READ_PER_PASS = 1024 * 1024
# A longer line is forwarded cut to this many bytes. A batch of 100 such
# lines of text is about 3 MB, under the gateway's 10 MB request limit; a
# batch the gateway refuses all the same is dropped, not sent again.
MAX_LINE_BYTES = 16 * 1024
# U+FFFD, what a byte that is not UTF-8 decodes to; a NUL byte becomes it too.
REPLACEMENT = chr(0xFFFD)
# Bytes of a file's beginning remembered to notice that it was rewritten.
HEAD_BYTES = 256
# Bytes before the position reached, remembered for the same reason: a file
# rewritten with the same beginning (a banner, a header line) differs there.
CHECK_BYTES = 64
# Files one source reads at once; a pattern's further matches are reported.
MAX_FILES_PER_SOURCE = 64
# Rotated-and-compressed logs a pattern such as "access.log*" also matches.
COMPRESSED_SUFFIXES = (".gz", ".bz2", ".xz", ".zst", ".zip", ".lz4", ".Z")
# An entry of the journal or of the unified log longer than this is
# forwarded cut. journalctl prints a field of more than 4096 bytes as null,
# and a field that is not text as a list of numbers, so an entry rarely comes
# near it.
MAX_ENTRY_BYTES = 256 * 1024
# Seconds before a command that follows a system log is started again after
# it ended: the first delay, the longest, and how long a run must last for
# the next delay to be the first one again.
CHILD_RESTART_MIN = 1.0
CHILD_RESTART_MAX = 300.0
CHILD_STABLE_SECONDS = 60.0
# Seconds a command gets to end after it is told to.
CHILD_STOP_SECONDS = 5.0
# Bytes of a command's standard error kept for the log and the status.
STDERR_KEPT = 512
# Starts in a row that a saved journal cursor may fail before it is given up.
CURSOR_ATTEMPTS = 3
_JOURNAL_CURSOR = re.compile(rb'"__CURSOR"\s*:\s*"([^"\\]{1,512})"')
# A Windows event log: seconds between two queries, events asked for at a
# time, and seconds a query may take.
WINDOWS_POLL_INTERVAL = 30.0
WINDOWS_MAX_EVENTS = 50
WINDOWS_QUERY_TIMEOUT = 30
_WINDOWS_LOG_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,63}$")
# What PowerShell is given. {log} is a name that matches _WINDOWS_LOG_NAME,
# so it cannot end the quoted string it is put in; {after} and {most} are
# whole numbers. It prints one JSON object: the log's newest record id (0
# for an empty log) and the events after {after}, oldest first.
_WINDOWS_QUERY = """\
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$log = '{log}'
$newest = 0
try {{ $newest = (Get-WinEvent -LogName $log -MaxEvents 1).RecordId }}
catch {{ if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }} }}
$found = @()
if ({after} -ge 0) {{
  try {{ $found = @(Get-WinEvent -LogName $log -FilterXPath '*[System[EventRecordID > {after}]]' -MaxEvents {most} -Oldest) }}
  catch {{ if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }} }}
}}
$events = @($found | ForEach-Object {{ [ordered]@{{
  RecordId = [int64]$_.RecordId; Id = $_.Id; Level = $_.LevelDisplayName
  ProviderName = $_.ProviderName; MachineName = $_.MachineName
  TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o'); Message = $_.Message
}} }})
[ordered]@{{ newest = [int64]$newest; events = $events }} | ConvertTo-Json -Depth 3 -Compress
"""
# Seconds between two writes of the positions, when they have moved. What a
# killed sensor sends again is what the data service accepted since the last
# write.
POSITION_SAVE_INTERVAL = 1.0

_O_BINARY = getattr(os, "O_BINARY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# A FIFO a pattern matches must not block the open; it is refused just after.
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_NOCTTY = getattr(os, "O_NOCTTY", 0)
_OPEN_FILE = os.O_RDONLY | _O_BINARY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK | _O_NOCTTY
_OPEN_DIR = os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW
_OPEN_BENEATH = bool(_O_NOFOLLOW) and os.open in os.supports_dir_fd


def default_log_sources() -> List[LogSourceConfig]:
    """What is read when the configuration has no ``log_sources`` section.

    The sources the forwarder read before #638, when it read nothing else.
    """
    if is_linux():
        return [
            LogSourceConfig(name="syslog", path="/var/log/syslog", format="syslog"),
            LogSourceConfig(name="auth", path="/var/log/auth.log", format="syslog"),
            LogSourceConfig(name="journald", type="journald", format="json"),
        ]
    if is_windows():
        return [
            LogSourceConfig(
                name=log_name.lower(),
                type="windows_event",
                log_name=log_name,
                format="windows_event",
            )
            for log_name in ("Security", "System", "Application")
        ]
    if is_macos():
        return [
            LogSourceConfig(
                name="system_log", path="/var/log/system.log", format="syslog"
            ),
            LogSourceConfig(name="unified_log", type="unified_log", format="json"),
        ]
    return []


class _Refused(Exception):
    """Why a path is not read."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Record:
    """What is kept about one file of a source, to go on with it later.

    ``offset`` is where to: just after the last line whose event was settled
    with every line before it. ``check`` and ``head`` are digests of the
    bytes before that offset and of the file's first ``head_len`` bytes, by
    which the file is recognized.
    """

    __slots__ = ("key", "path", "offset", "check", "head_len", "head", "seen")

    def __init__(self, key: Tuple[int, int], path: str):
        self.key = key
        self.path = path
        self.offset = 0
        self.check = _digest(b"")
        self.head_len = 0
        self.head = _digest(b"")
        self.seen = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.key[0],
            "inode": self.key[1],
            "offset": self.offset,
            "check": self.check,
            "head_bytes": self.head_len,
            "head": self.head,
            "path": self.path,
            "seen": self.seen,
        }

    @classmethod
    def from_dict(cls, entry: Dict[str, Any]) -> "_Record":
        record = cls((entry["device"], entry["inode"]), entry["path"])
        record.offset = entry["offset"]
        record.check = entry["check"]
        record.head_len = entry["head_bytes"]
        record.head = entry["head"]
        record.seen = entry["seen"]
        return record


class _Pending:
    """A line whose event is in the sensor: where it ends in its file, and
    the bytes before that point. For a journal entry, its cursor."""

    __slots__ = ("end", "window", "settled")

    def __init__(self, end: Any, window: bytes = b""):
        self.end = end
        self.window = window
        self.settled = False


def _settle_in_order(pending: Deque[_Pending], entry: _Pending) -> Optional[_Pending]:
    """Mark ``entry`` settled; the last of the entries now settled with all
    those read before them, if that moved."""
    entry.settled = True
    last = None
    while pending and pending[0].settled:
        last = pending.popleft()
    return last


class _SystemSource:
    """A source read from a command or a query, and what it is doing."""

    def __init__(self, source: LogSourceConfig):
        self.source = source
        # starting, running, restarting (the command ended and will be
        # started again), unavailable (it cannot be started here), skipped
        # (this platform has no such log), stopped.
        self.state = "starting"
        self.restarts = 0
        self.last_exit: Optional[int] = None
        self.last_error: Optional[str] = None
        self.entries_forwarded = 0
        self.entries_truncated = 0
        self.entries_unparsed = 0
        # Called when the source's command has ended, with whether that run
        # of it produced an entry.
        self.ended = None
        # journald: the cursor of the last entry read, from which the
        # command is started again, and of the last entry accepted, which
        # is what is saved.
        self.read_cursor: Optional[str] = None
        self.accepted_cursor: Optional[str] = None
        # windows_event: the same two, as record ids. None: the log has not
        # been asked yet, and is followed from its newest event on.
        self.read_record: Optional[int] = None
        self.accepted_record: Optional[int] = None
        self.pending: Deque[_Pending] = deque()

    def saved(self) -> Optional[Dict[str, Any]]:
        """What to keep for this source in the position file."""
        if self.source.type == "journald" and self.accepted_cursor:
            return {"type": "journald", "cursor": self.accepted_cursor}
        if self.source.type == "windows_event" and self.accepted_record is not None:
            return {
                "type": "windows_event",
                "log_name": self.source.log_name,
                "record_id": self.accepted_record,
            }
        return None

    def status(self) -> Dict[str, Any]:
        status = {
            "state": self.state,
            "restarts": self.restarts,
            "last_exit": self.last_exit,
            "last_error": self.last_error,
            "entries_forwarded": self.entries_forwarded,
            "entries_truncated": self.entries_truncated,
            "entries_unparsed": self.entries_unparsed,
        }
        if self.source.type == "journald":
            status["accepted_cursor"] = self.accepted_cursor
        if self.source.type == "windows_event":
            status["log_name"] = self.source.log_name
            status["read_record_id"] = self.read_record
            status["accepted_record_id"] = self.accepted_record
        return status


class _Tail:
    """One open log file and how far it has been read."""

    __slots__ = (
        "path",
        "fd",
        "key",
        "position",
        "head",
        "carry",
        "partial",
        "discarding",
        "rotated",
        "record",
        "pending",
    )

    def __init__(self, path: str, fd: int, key: Tuple[int, int], position: int):
        self.path = path
        self.fd = fd
        self.key = key  # (device, inode): the file, whatever its name becomes
        self.position = position
        # What is saved for this file, and the lines read from it whose
        # events are not settled yet, in the order they were read.
        self.record = _Record(key, path)
        self.pending: Deque[_Pending] = deque()
        # The first bytes that were read. If the file no longer begins with
        # them it was rewritten, even when it is not shorter than before.
        self.head = b""
        # The last bytes read, those just before ``position``. If the file
        # no longer holds them there it was rewritten, even when it begins
        # as before.
        self.carry = b""
        self.partial = b""  # the bytes of a line whose newline is not written yet
        self.discarding = False  # inside a line that is not to be forwarded
        self.rotated = False  # the path now names another file, or none


class _FileSource:
    """A file source and the files it is reading."""

    def __init__(self, source: LogSourceConfig):
        self.source = source
        self.root = source.root
        self.wildcard = has_wildcard(source.path)
        self.tails: Dict[str, _Tail] = {}
        # The files that existed at the first look, as ((device, inode), size):
        # those, and only those, start at that size with read_from: end.
        self.preexisting: Dict[str, Tuple[Tuple[int, int], int]] = {}
        self.scanned = False
        self.candidates: List[str] = []
        self.next_glob = 0.0
        # path -> the problem last reported for it, so each is logged once.
        self.problems: Dict[str, str] = {}
        # Was this source, with this path, read by an earlier run? Then its
        # files go on from their records and read_from does not apply.
        self.known = False
        # (device, inode) -> what is kept about a file: those being read,
        # and those read before that may come back.
        self.records: Dict[Tuple[int, int], _Record] = {}


class LogForwarder:
    """Forward system and application logs to data lake"""

    def __init__(self, config: SensorConfig, event_queue: asyncio.Queue):
        self.config = config
        self.event_queue = event_queue
        self.running = False
        self.poll_interval = POLL_INTERVAL

        # Log sources configuration
        self.using_default_sources = config.log_sources is None
        self.log_sources = self._initialize_log_sources()

        self._file_sources: Dict[str, _FileSource] = {}
        self._system_sources: Dict[str, _SystemSource] = {}
        self._tasks: List[asyncio.Task] = []

        # Read positions (#725). What an earlier run saved is read once,
        # here; a file that cannot be used is reported and ignored.
        self.positions = PositionStore(config.data_dir)
        self._saved = self.positions.load()
        self._positions_dirty = False
        # The sensor's own log file is never a source: forwarding it would
        # make every forwarded line produce another.
        own_log = getattr(config.logging, "file", None)
        self._own_log = os.path.realpath(own_log) if own_log else None

        self.stats = {"lines_forwarded": 0, "lines_truncated": 0}

    def _initialize_log_sources(self) -> List[LogSourceConfig]:
        """The enabled sources: the configured ones, or the platform's
        defaults when the configuration has no log_sources section."""
        if self.config.log_sources is None:
            sources = default_log_sources()
        else:
            sources = self.config.log_sources
        return [source for source in sources if source.enabled]

    @staticmethod
    def _unsupported_here(source: LogSourceConfig) -> Optional[str]:
        """Why this platform cannot read the source, if it cannot."""
        if source.type == "journald" and not is_linux():
            return "the systemd journal is read on Linux only"
        if source.type == "windows_event" and not is_windows():
            return "the Windows Event Log is read on Windows only"
        if source.type == "unified_log" and not is_macos():
            return "the unified log is read on macOS only"
        return None

    async def start(self):
        """Start log forwarding"""
        if not self.config.collection.log_forwarding:
            logger.info("Log forwarding is disabled")
            return

        logger.info("Starting log forwarder")
        self.running = True

        if self.using_default_sources:
            logger.info(
                "The configuration has no log_sources section: reading the "
                "platform's default sources (%s)",
                ", ".join(source.name for source in self.log_sources) or "none",
            )
        if not self.log_sources:
            logger.warning(
                "Log forwarding is enabled but no log source is: nothing will "
                "be forwarded. List the sources under log_sources."
            )

        try:
            # Start a monitoring task for each log source
            for source in self.log_sources:
                monitor = None
                unsupported = self._unsupported_here(source)
                if source.type != "file":
                    runtime = self._system_source(source)
                    self._system_sources[source.name] = runtime
                if unsupported:
                    runtime.state = "skipped"
                    runtime.last_error = unsupported
                    logger.warning(
                        "Log source %r (%s) is skipped: %s",
                        source.name,
                        source.type,
                        unsupported,
                    )
                elif source.type == "file":
                    state = self._file_source(source)
                    self._file_sources[source.name] = state
                    if state.known:
                        logger.info(
                            "Log source %r: %s (format %s), going on from "
                            "the saved positions of %d files",
                            source.name,
                            source.path,
                            source.format,
                            len(state.records),
                        )
                    else:
                        logger.info(
                            "Log source %r: %s (format %s, from the %s of a "
                            "file that already exists)",
                            source.name,
                            source.path,
                            source.format,
                            source.read_from,
                        )
                    # A first look now, so that what is wrong with a path is
                    # in the log before the forwarder says it has started.
                    self._scan(state)
                    monitor = self._monitor_file(state)
                elif source.type == "journald":
                    monitor = self._monitor_journald(runtime)
                elif source.type == "windows_event":
                    monitor = self._monitor_windows_events(runtime)
                elif source.type == "unified_log":
                    monitor = self._monitor_unified_log(runtime)

                if monitor is not None:
                    self._tasks.append(asyncio.create_task(monitor))

            logger.info(f"Log forwarder started with {len(self._tasks)} sources")

            if self.positions.persistent:
                self._tasks.append(asyncio.create_task(self._save_periodically()))
            elif self._file_sources or any(
                runtime.source.type in ("journald", "windows_event")
                and runtime.state != "skipped"
                for runtime in self._system_sources.values()
            ):
                logger.warning(
                    "data_dir is not set: read positions are kept in memory "
                    "only. After a restart each file source starts as its "
                    "read_from says: from the end, it skips what was written "
                    "meanwhile; from the beginning, it sends everything "
                    "again. The journal and an event log are followed from "
                    "that moment on"
                )

        except Exception as e:
            logger.error(f"Failed to start log forwarder: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Stop log forwarding"""
        logger.info("Stopping log forwarder")
        self.running = False

        # A monitor waiting on a full queue would never see ``running``.
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for state in self._file_sources.values():
            self._close_all(state)
        for runtime in self._system_sources.values():
            if runtime.state not in ("skipped", "unavailable"):
                runtime.state = "stopped"
        self.save_positions()

    # -- read positions ---------------------------------------------------

    def _file_source(self, source: LogSourceConfig) -> _FileSource:
        """The state of a file source, with what an earlier run saved for
        it: for this name and this path, or it is a first time."""
        state = _FileSource(source)
        entries = file_entries(self._saved, source.name, source.path)
        if entries is not None:
            state.known = True
            for entry in entries:
                record = _Record.from_dict(entry)
                state.records[record.key] = record
        return state

    def _system_source(self, source: LogSourceConfig) -> _SystemSource:
        """The state of a source that is not a file, with what an earlier
        run saved for it."""
        runtime = _SystemSource(source)
        saved = self._saved.get(source.name) or {}
        if source.type == "journald" and saved.get("type") == "journald":
            runtime.accepted_cursor = runtime.read_cursor = saved["cursor"]
        if (
            source.type == "windows_event"
            and saved.get("type") == "windows_event"
            # A source pointed at another log starts as a new one.
            and saved.get("log_name") == source.log_name
        ):
            runtime.accepted_record = runtime.read_record = saved["record_id"]
        return runtime

    def _settled(self, tail: _Tail, entry: _Pending):
        """The sensor has finished with a line's event: move the file's
        saved offset past every line settled with all those before it."""
        last = _settle_in_order(tail.pending, entry)
        if last is not None:
            tail.record.offset = last.end
            tail.record.check = _digest(last.window)
            self._positions_dirty = True

    def _snapshot(self) -> Dict[str, Dict[str, Any]]:
        """What to save: every configured source's positions."""
        configured = {source.name for source in self.config.log_sources or []}
        configured.update(source.name for source in self.log_sources)
        # A source that is listed and not read now (disabled, or of a type
        # this platform cannot read) keeps what was saved for it.
        sources = {
            name: entry
            for name, entry in self._saved.items()
            if name in configured
            and name not in self._file_sources
            and name not in self._system_sources
        }
        for name, runtime in self._system_sources.items():
            entry = runtime.saved() or self._saved.get(name)
            if entry and entry.get("type") == runtime.source.type:
                sources[name] = entry
        now = time.time()
        for name, state in self._file_sources.items():
            if not state.scanned:
                continue
            reading = {tail.key for tail in state.tails.values()}
            for key in reading:
                state.records[key].seen = now
            others = sorted(
                (record for key, record in state.records.items() if key not in reading),
                key=lambda record: record.seen,
                reverse=True,
            )
            for record in others[max(0, MAX_FILES - len(reading)) :]:
                del state.records[record.key]
            sources[name] = {
                "type": "file",
                "path": state.source.path,
                "files": [record.to_dict() for record in state.records.values()],
            }
        return sources

    def save_positions(self) -> bool:
        """Write the positions now, if they have moved since the last write."""
        if not self.positions.persistent or not self._positions_dirty:
            return False
        self._positions_dirty = False
        serial = self.positions.next_serial()
        if self.positions.save(self._snapshot(), serial):
            return True
        self._positions_dirty = True  # tried again at the next interval
        return False

    async def _save_periodically(self):
        """Write the positions while they move, off the event loop."""
        loop = asyncio.get_running_loop()
        while self.running:
            await asyncio.sleep(POSITION_SAVE_INTERVAL)
            if not self._positions_dirty:
                continue
            self._positions_dirty = False
            # Numbered here, on the loop: a write that reaches the disk
            # after the one made at stop must not replace it.
            serial = self.positions.next_serial()
            snapshot = self._snapshot()
            saved = await loop.run_in_executor(
                None, self.positions.save, snapshot, serial
            )
            if not saved:
                self._positions_dirty = True

    # -- file sources -----------------------------------------------------

    async def _monitor_file(self, state: _FileSource):
        """Follow a file source until the forwarder stops"""
        try:
            while self.running:
                try:
                    progressed = await self._poll_source(state)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(
                        "Error reading log source %r: %s", state.source.name, e
                    )
                    await asyncio.sleep(5 * self.poll_interval)
                    continue
                # Yield either way; wait only when there was nothing to read.
                await asyncio.sleep(0 if progressed else self.poll_interval)
        finally:
            self._close_all(state)

    async def _poll_source(self, state: _FileSource) -> bool:
        """One look at a source: find its files, read what is new.

        True when something was read, in which case there may be more.
        """
        self._scan(state)
        progressed = False
        for tail in list(state.tails.values()):
            if await self._drain(state, tail):
                progressed = True
        return progressed

    def _candidates(self, state: _FileSource) -> List[str]:
        """The paths the source names now."""
        source = state.source
        if not state.wildcard:
            return [source.path]

        now = time.monotonic()
        if state.scanned and now < state.next_glob:
            return state.candidates
        state.next_glob = now + GLOB_INTERVAL

        matches = [
            path
            for path in sorted(glob.glob(source.path))
            if not path.endswith(COMPRESSED_SUFFIXES)
        ]
        if not matches:
            if not os.path.isdir(state.root):
                problem = f"the directory {state.root} does not exist yet"
            elif not os.access(state.root, os.R_OK | os.X_OK):
                problem = (
                    f"this process (uid {_uid()}) is not allowed to list "
                    f"{state.root}"
                )
            else:
                problem = "no file matches the pattern yet"
            self._report(state, source.path, problem)
        elif len(matches) > MAX_FILES_PER_SOURCE:
            self._warn_once(
                state,
                source.path,
                f"matches {len(matches)} files; only the first "
                f"{MAX_FILES_PER_SOURCE} are read. Use a narrower pattern or "
                f"several sources",
            )
            matches = matches[:MAX_FILES_PER_SOURCE]
        else:
            self._resolved(state, source.path)
        state.candidates = matches
        return matches

    def _scan(self, state: _FileSource):
        """Open the source's new files and notice the rotated ones."""
        candidates = self._candidates(state)
        first = not state.scanned
        state.scanned = True

        # Which file each path names now: None when it names none.
        current: Dict[str, Optional[Tuple[int, int]]] = {}
        for path in candidates:
            try:
                found = os.stat(path)
            except (FileNotFoundError, NotADirectoryError):
                current[path] = None
                continue
            except OSError:
                # It could not be looked at (a directory above it lost its
                # search permission, an I/O error): that says nothing about
                # rotation, and taking it for one would close the file and
                # forward all of it again once it can be opened.
                tail = state.tails.get(path)
                current[path] = tail.key if tail else None
                continue
            current[path] = (found.st_dev, found.st_ino)
            if first and not state.known and state.source.read_from == "end":
                state.preexisting[path] = (current[path], found.st_size)
        if first:
            # Saved even if nothing is read: the source is known from now on.
            self._positions_dirty = True

        for path, tail in list(state.tails.items()):
            if current.get(path) == tail.key:
                continue
            # The path names another file now, or none. If the pattern also
            # matches the file's new name ("access.log*" and access.log.1),
            # go on reading it there: opening it as a new file would forward
            # the whole of it a second time.
            renamed = next(
                (
                    other
                    for other, key in current.items()
                    if key == tail.key and other not in state.tails
                ),
                None,
            )
            if renamed is None:
                tail.rotated = True
                continue
            logger.info(
                "Log source %r: %s was renamed to %s",
                state.source.name,
                path,
                renamed,
            )
            del state.tails[path]
            tail.path = renamed
            tail.record.path = renamed
            self._positions_dirty = True
            state.tails[renamed] = tail

        for path in candidates:
            if path not in state.tails:
                self._open(state, path)

    def _open(self, state: _FileSource, path: str):
        """Start reading ``path``, or report why it is not read."""
        source = state.source
        try:
            fd = self._open_beneath(path, state.root)
        except _Refused as refusal:
            self._report(state, path, str(refusal))
            return

        try:
            found = os.fstat(fd)
            key = (found.st_dev, found.st_ino)
            if not stat.S_ISREG(found.st_mode):
                raise _Refused("it is not a regular file")
            if any(tail.key == key for tail in state.tails.values()):
                # The same file under a second name (a link beside it).
                raise _Refused("it is the same file as another one being read")

            position = 0
            was_key, was_size = state.preexisting.pop(path, (None, 0))
            record = state.records.get(key)
            if record is not None and self._is_the_file(fd, found.st_size, record):
                # Read before, by this run or an earlier one: go on after
                # the last line the data service accepted.
                position = record.offset
            elif was_key == key and 0 < was_size <= found.st_size:
                # It was there when the sensor first saw the source: only
                # what has been written since.
                position = was_size
            # If it starts in the middle of a line (the file ended there, or
            # a long line was sent cut at this point), the rest of that line
            # is not a line.
            discarding = position > 0 and self._read_at(fd, 1, position - 1) != b"\n"
        except _Refused as refusal:
            os.close(fd)
            self._report(state, path, str(refusal))
            return
        except OSError as e:
            os.close(fd)
            self._report(state, path, f"it cannot be read: {e.strerror or e}")
            return

        tail = _Tail(path, fd, key, position)
        tail.discarding = discarding
        if position:
            tail.head = self._read_at(fd, min(HEAD_BYTES, position), 0)
            kept = min(CHECK_BYTES, position)
            tail.carry = self._read_at(fd, kept, position - kept)
        tail.record.offset = position
        tail.record.check = _digest(tail.carry)
        tail.record.head_len = len(tail.head)
        tail.record.head = _digest(tail.head)
        state.records[key] = tail.record
        self._positions_dirty = True
        state.tails[path] = tail
        self._resolved(state, path)
        logger.info(
            "Log source %r: reading %s from %s",
            source.name,
            path,
            f"byte {position}" if position else "its beginning",
        )

    def _open_beneath(self, path: str, root: str) -> int:
        """A read-only descriptor for ``path``, which must be under ``root``.

        The path may be, or pass through, a symbolic link, as long as what it
        resolves to is still inside the directory the source names. The file
        is then opened component by component from that directory without
        following links, so that a link swapped in between the check and the
        open is refused rather than followed.
        """
        if not os.path.lexists(path):
            raise _Refused("it does not exist yet")

        real_root = os.path.realpath(root)
        real = os.path.realpath(path)
        inside = real_root.rstrip(os.sep) + os.sep
        if not real.startswith(inside):
            raise _Refused(
                f"it resolves to {real}, outside {real_root}: the forwarder "
                f"does not follow a link out of a source's directory"
            )
        if self._own_log and (
            real == self._own_log or real.startswith(self._own_log + ".")
        ):
            raise _Refused("it is the sensor's own log file")

        try:
            if not _OPEN_BENEATH:
                return os.open(real, _OPEN_FILE)
            parts = real[len(inside):].split(os.sep)
            directory = os.open(real_root, _OPEN_DIR & ~_O_NOFOLLOW)
            try:
                for part in parts[:-1]:
                    deeper = os.open(part, _OPEN_DIR, dir_fd=directory)
                    os.close(directory)
                    directory = deeper
                return os.open(parts[-1], _OPEN_FILE, dir_fd=directory)
            finally:
                os.close(directory)
        except FileNotFoundError:
            raise _Refused("it does not exist yet") from None
        except PermissionError:
            raise _Refused(
                f"this process (uid {_uid()}) is not allowed to read it"
            ) from None
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                raise _Refused(
                    "it changed into a link while it was being opened"
                ) from None
            raise _Refused(f"it cannot be opened: {e.strerror or e}") from None

    def _is_the_file(self, fd: int, size: int, record: _Record) -> bool:
        """Is this open file the one the record was taken from, with what
        was read of it still in place?

        The record names it by device and inode, which another file can
        come to have: a position is used only where the bytes agree.
        """
        if record.offset > size or record.head_len > size:
            return False  # shorter than what was read: another file, or truncated
        if _digest(self._read_at(fd, record.head_len, 0)) != record.head:
            return False
        kept = min(CHECK_BYTES, record.offset)
        return _digest(self._read_at(fd, kept, record.offset - kept)) == record.check

    @staticmethod
    def _read_at(fd: int, length: int, position: int) -> bytes:
        if hasattr(os, "pread"):
            return os.pread(fd, length, position)
        os.lseek(fd, position, os.SEEK_SET)
        return os.read(fd, length)

    async def _drain(self, state: _FileSource, tail: _Tail) -> bool:
        """Read what is new in one file, up to MAX_READ_PER_PASS bytes."""
        source = state.source
        budget = MAX_READ_PER_PASS
        progressed = False
        at_end = False

        while budget > 0:
            size = os.fstat(tail.fd).st_size
            # Shorter than what was read: truncated. Longer, but not
            # beginning as it did, or not holding before the position what
            # was read there: truncated and written past that point before
            # this look, which the size alone does not show.
            if size < tail.position or (
                size > tail.position and self._rewritten(tail)
            ):
                logger.info(
                    "Log source %r: %s was truncated; reading it from its "
                    "beginning",
                    source.name,
                    tail.path,
                )
                tail.position = 0
                tail.head = b""
                tail.carry = b""
                tail.partial = b""
                tail.discarding = False
                # The lines read before are gone with their offsets: an
                # event of theirs settled later must not move the position.
                tail.pending.clear()
                tail.record.offset = 0
                tail.record.check = tail.record.head = _digest(b"")
                tail.record.head_len = 0
                self._positions_dirty = True
            if size == tail.position:
                at_end = True
                break

            chunk = self._read_at(tail.fd, min(READ_CHUNK, budget), tail.position)
            if not chunk:
                at_end = True
                break
            if tail.position < HEAD_BYTES:
                tail.head = (tail.head[: tail.position] + chunk)[:HEAD_BYTES]
                tail.record.head_len = len(tail.head)
                tail.record.head = _digest(tail.head)
            before = tail.carry
            if len(chunk) >= CHECK_BYTES:
                tail.carry = chunk[-CHECK_BYTES:]
            else:
                tail.carry = (tail.carry + chunk)[-CHECK_BYTES:]
            base = tail.position
            tail.position += len(chunk)
            budget -= len(chunk)
            progressed = True
            # Waits for the queue: with nobody taking events, nothing more is
            # read and no more than this chunk is held.
            await self._consume(source, tail, chunk, base, before)
            await asyncio.sleep(0)

        if tail.rotated and at_end:
            # Nothing more will be written to it. What it ends with is a
            # line even without its newline.
            if tail.partial and not tail.discarding:
                await self._forward_line(
                    source, tail, tail.partial, tail.position, tail.carry
                )
            logger.info(
                "Log source %r: %s was rotated or removed", source.name, tail.path
            )
            self._close(state, tail)
            # Look again at once: the file that replaced it is waiting.
            return True
        return progressed

    def _rewritten(self, tail: _Tail) -> bool:
        """Does the file no longer hold what was read from it?

        Two short reads, at its beginning and just before the position.
        """
        if self._read_at(tail.fd, len(tail.head), 0) != tail.head:
            return True
        start = tail.position - len(tail.carry)
        return self._read_at(tail.fd, len(tail.carry), start) != tail.carry

    async def _consume(
        self,
        source: LogSourceConfig,
        tail: _Tail,
        chunk: bytes,
        base: int,
        before: bytes,
    ):
        """Forward the lines a chunk completes; keep the unfinished one.

        ``base`` is the chunk's offset in the file and ``before`` the bytes
        just before it: each line is forwarded with the offset it ends at
        and the bytes before that offset, which is what is saved once its
        event is settled.
        """

        def window(end: int) -> bytes:
            cut = end - base
            if cut >= CHECK_BYTES:
                return chunk[cut - CHECK_BYTES : cut]
            return (before + chunk[:cut])[-CHECK_BYTES:]

        lines = (tail.partial + chunk).split(b"\n")
        end = base - len(tail.partial)
        tail.partial = lines.pop()

        for line in lines:
            end += len(line) + 1
            if tail.discarding:
                # The end of a line whose beginning was not forwarded as one.
                tail.discarding = False
                continue
            await self._forward_line(source, tail, line, end, window(end))

        if len(tail.partial) > MAX_LINE_BYTES:
            # Still no newline: forward what fits, once, and drop the rest of
            # the line as it arrives instead of holding it.
            if not tail.discarding:
                end = base + len(chunk)
                await self._forward_line(source, tail, tail.partial, end, window(end))
                tail.discarding = True
            tail.partial = b""

    async def _forward_line(
        self,
        source: LogSourceConfig,
        tail: _Tail,
        raw: bytes,
        end: int,
        window: bytes,
    ):
        """Decode one line and queue it.

        ``end`` is the offset the line ends at (for a line sent cut, where
        the reading had got to) and ``window`` the bytes before it.
        """
        truncated = len(raw) > MAX_LINE_BYTES
        if truncated:
            raw = raw[:MAX_LINE_BYTES]
        # A log is not always UTF-8, and a truncated file leaves NUL bytes:
        # neither may stop the line, or the batch it travels in.
        line = raw.decode("utf-8", errors="replace").replace("\x00", REPLACEMENT)
        line = line.strip()
        if not line:
            # No event: a later line's offset covers it.
            return
        entry = _Pending(end, window)
        tail.pending.append(entry)
        delivery = Delivery(
            lambda: self._settled(tail, entry),
            replayable=self.positions.persistent,
        )
        queued = await self._process_log_line(
            line, source, path=tail.path, truncated=truncated, delivery=delivery
        )
        if not queued:
            delivery.settle()

    def _close(self, state: _FileSource, tail: _Tail):
        state.tails.pop(tail.path, None)
        try:
            if tail.rotated and os.fstat(tail.fd).st_nlink == 0:
                # Removed, not renamed: it cannot come back, and another
                # file may get its inode. Nothing is kept about it.
                if state.records.get(tail.key) is tail.record:
                    del state.records[tail.key]
                    self._positions_dirty = True
        except OSError:
            pass
        try:
            os.close(tail.fd)
        except OSError:
            pass

    def _close_all(self, state: _FileSource):
        for tail in list(state.tails.values()):
            self._close(state, tail)

    def _report(self, state: _FileSource, path: str, problem: str):
        """Warn that a path of a source is not read, once per reason."""
        self._warn_once(state, path, problem, "is not read: ")

    @staticmethod
    def _warn_once(state: _FileSource, path: str, problem: str, verb: str = ""):
        """Warn about a path of a source; again only when the problem changes."""
        if state.problems.get(path) == problem:
            return
        state.problems[path] = problem
        logger.warning("Log source %r: %s %s%s", state.source.name, path, verb, problem)

    @staticmethod
    def _resolved(state: _FileSource, path: str):
        state.problems.pop(path, None)

    # -- system logs ------------------------------------------------------

    async def _follow_command(self, runtime: _SystemSource, command, handle):
        """Run a command that follows a system log, for as long as the
        forwarder runs: read its entries, and start it again when it ends.

        ``command`` gives the arguments of each start; ``handle(line, cut)``
        is awaited for each line of output, ``cut`` when the line is only
        the beginning of an entry longer than ``MAX_ENTRY_BYTES``.
        """
        source = runtime.source
        delay = CHILD_RESTART_MIN
        while self.running:
            argv = command()
            started = time.monotonic()
            forwarded = runtime.entries_forwarded
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                runtime.state = "unavailable"
                runtime.last_error = f"{argv[0]} is not installed"
                logger.warning(
                    "Log source %r (%s) is not read: %s is not installed here",
                    source.name,
                    source.type,
                    argv[0],
                )
                return
            except OSError as e:
                runtime.last_exit = None
                runtime.last_error = f"{argv[0]} cannot be started: {e.strerror or e}"
            else:
                runtime.state = "running"
                errors = asyncio.create_task(self._read_stderr(process, runtime))
                closed = False
                try:
                    await self._read_entries(process.stdout, handle)
                    closed = True  # it closed its output: it is ending
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    # Not the end of the source: the command is started
                    # again, from where the reading had got to.
                    logger.error("Log source %r: error reading %s: %s", source.name, argv[0], e)
                finally:
                    await self._end_command(process, ending=closed)
                    # What it had written and nobody read: taken out of the
                    # pipe, so that the pipe closes with the command.
                    rest = asyncio.gather(self._discard(process.stdout), errors)
                    try:
                        await asyncio.wait_for(rest, CHILD_STOP_SECONDS)
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        pass
                runtime.last_exit = process.returncode
            if not self.running:
                break

            self._command_ended(runtime, runtime.entries_forwarded > forwarded)
            if time.monotonic() - started >= CHILD_STABLE_SECONDS:
                delay = CHILD_RESTART_MIN
            runtime.state = "restarting"
            runtime.restarts += 1
            logger.warning(
                "Log source %r: %s ended (exit status %s%s); it is started "
                "again in %.0f seconds",
                source.name,
                argv[0],
                runtime.last_exit,
                f", it said: {runtime.last_error}" if runtime.last_error else "",
                delay,
            )
            await self._restart_pause(delay)
            delay = min(delay * 2, CHILD_RESTART_MAX)

    async def _restart_pause(self, seconds: float):
        await asyncio.sleep(seconds)

    @staticmethod
    def _command_ended(runtime: _SystemSource, forwarded: bool):
        """A source's command has ended and will be started again;
        ``forwarded`` when this run of it produced an entry."""
        if runtime.ended is not None:
            runtime.ended(forwarded)

    async def _read_entries(self, stream: asyncio.StreamReader, handle):
        """Give ``handle`` each line of ``stream``, holding at most
        ``MAX_ENTRY_BYTES`` and one read of it."""
        partial = b""
        discarding = False
        while True:
            # read(), not readline(): a line longer than the stream's limit
            # makes readline() raise, and whatever follows it is lost.
            chunk = await stream.read(READ_CHUNK)
            if not chunk:
                return  # the command closed its output: it has ended
            lines = (partial + chunk).split(b"\n")
            partial = lines.pop()
            for line in lines:
                if discarding:
                    # The end of an entry whose beginning was forwarded cut.
                    discarding = False
                    continue
                await handle(line, len(line) > MAX_ENTRY_BYTES)
            if len(partial) > MAX_ENTRY_BYTES:
                if not discarding:
                    await handle(partial, True)
                    discarding = True
                partial = b""

    async def _read_stderr(self, process, runtime: _SystemSource):
        """Read what the command says on its standard error, so that it
        never waits for someone to; keep the last of it."""
        kept = b""
        while True:
            chunk = await process.stderr.read(4096)
            if not chunk:
                return
            kept = (kept + chunk)[-STDERR_KEPT:]
            text = kept.decode("utf-8", errors="replace").replace("\x00", REPLACEMENT)
            runtime.last_error = " ".join(text.split()) or None
            logger.debug("Log source %r: %s", runtime.source.name, runtime.last_error)

    @staticmethod
    async def _discard(stream: asyncio.StreamReader):
        while await stream.read(READ_CHUNK):
            pass

    @staticmethod
    async def _end_command(process, ending: bool = False):
        """End the command if it is still running, and wait for it.

        ``ending``: it closed its output and is expected to exit by itself.
        It is then waited for first: signalling a process that has exited
        and was not waited for yet loses its exit status.
        """
        if process.returncode is not None:
            return
        if ending:
            try:
                await asyncio.wait_for(process.wait(), CHILD_STOP_SECONDS)
                return
            except asyncio.TimeoutError:
                pass
        try:
            process.terminate()
        except (OSError, ProcessLookupError):
            pass
        try:
            await asyncio.wait_for(process.wait(), CHILD_STOP_SECONDS)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
            await process.wait()

    @staticmethod
    def _cut_text(raw: bytes) -> str:
        """The beginning of an entry too long to forward whole, as text."""
        text = raw[:MAX_LINE_BYTES].decode("utf-8", errors="replace")
        return text.replace("\x00", REPLACEMENT).strip()

    # journald

    def _journal_command(self, runtime: _SystemSource) -> List[str]:
        """journalctl, following the journal from the last entry read; the
        first time, from now on."""
        argv = ["journalctl", "--follow", "--output=json", "--no-pager"]
        if runtime.read_cursor:
            # One argument, and a cursor is checked before it is kept: it
            # cannot be taken for another option.
            argv.append(f"--after-cursor={runtime.read_cursor}")
        else:
            argv.append("--lines=0")
        return argv

    async def _monitor_journald(self, runtime: _SystemSource):
        """Follow the systemd journal"""
        logger.info(
            "Log source %r: following the systemd journal %s",
            runtime.source.name,
            "from the saved cursor" if runtime.read_cursor else "from now on",
        )
        failed_with_cursor = 0

        def ended(forwarded: bool):
            # A cursor journalctl does not accept (the journal it pointed
            # into is gone) would fail every start for ever.
            nonlocal failed_with_cursor
            if forwarded or not runtime.read_cursor or runtime.last_exit == 0:
                failed_with_cursor = 0
                return
            failed_with_cursor += 1
            if failed_with_cursor < CURSOR_ATTEMPTS:
                return
            failed_with_cursor = 0
            logger.warning(
                "Log source %r: journalctl failed %d times in a row from the "
                "saved cursor; the cursor is given up and the journal is "
                "followed from now on. Entries logged in between are not read",
                runtime.source.name,
                CURSOR_ATTEMPTS,
            )
            runtime.read_cursor = None

        async def handle(line: bytes, cut: bool):
            await self._journal_entry(runtime, line, cut)

        runtime.ended = ended
        await self._follow_command(
            runtime, lambda: self._journal_command(runtime), handle
        )

    async def _journal_entry(self, runtime: _SystemSource, raw: bytes, cut: bool):
        """Queue one entry of journalctl's output."""
        source = runtime.source
        metadata = {'log_source': source.name, 'format': 'json'}
        if cut:
            data: Any = {'raw_message': self._cut_text(raw)}
            metadata['truncated'] = True
            # Wherever it is in what was kept: journalctl does not print
            # an entry's fields in a fixed order.
            found = _JOURNAL_CURSOR.search(raw)
            cursor = found.group(1).decode("ascii", errors="replace") if found else None
        else:
            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                return
            try:
                data = json.loads(text)
            except (ValueError, RecursionError):
                data = None
            if not isinstance(data, dict):
                runtime.entries_unparsed += 1
                logger.debug("Log source %r: a line of journalctl is not an entry", source.name)
                return
            cursor = data.get('__CURSOR')
        if not isinstance(cursor, str) or not CURSOR_PATTERN.match(cursor):
            cursor = None

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'log_forwarder',
            'type': f"log.{source.name}",
            'data': data,
            'metadata': metadata
        }
        entry = _Pending(cursor)
        runtime.pending.append(entry)
        event[DELIVERY_KEY] = Delivery(
            lambda: self._journal_settled(runtime, entry),
            replayable=self.positions.persistent,
        )
        if cursor:
            # From here if journalctl has to be started again: this entry
            # is in the sensor, and must not be read a second time.
            runtime.read_cursor = cursor

        await self.event_queue.put(event)
        runtime.entries_forwarded += 1
        if cut:
            runtime.entries_truncated += 1

    def _journal_settled(self, runtime: _SystemSource, entry: _Pending):
        """The sensor has finished with an entry's event: the saved cursor
        moves to the last entry settled with all those read before it."""
        last = _settle_in_order(runtime.pending, entry)
        if last is not None and last.end:
            runtime.accepted_cursor = last.end
            self._positions_dirty = True

    # the Windows event log

    @staticmethod
    def _windows_events_command(log_name: str, after: Optional[int]) -> List[str]:
        """PowerShell, asked for the log's newest record id and, unless
        ``after`` is None, the events after that record id.

        Nothing but a checked log name and whole numbers goes into the
        command's text.
        """
        if not isinstance(log_name, str) or not _WINDOWS_LOG_NAME.match(log_name):
            raise ValueError(f"not a Windows event log name: {log_name!r}")
        if after is None:
            after = -1  # only the newest record id is wanted
        if isinstance(after, bool) or not isinstance(after, int) or after < -1:
            raise ValueError(f"not a record id: {after!r}")
        script = _WINDOWS_QUERY.format(
            log=log_name, after=after, most=int(WINDOWS_MAX_EVENTS)
        )
        return ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]

    @staticmethod
    def _run_windows_query(argv: List[str]) -> str:
        """Run the query and return what it printed. Blocking: it is called
        in a worker thread."""
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=WINDOWS_QUERY_TIMEOUT,
        )
        if result.returncode != 0:
            said = " ".join((result.stderr or "").split())[-STDERR_KEPT:]
            raise RuntimeError(
                f"PowerShell ended with exit status {result.returncode}: {said}"
            )
        return result.stdout

    @staticmethod
    def _parse_windows_events(output: str, after: Optional[int]):
        """The newest record id and the events of a query's output, oldest
        first, without any at or before ``after``.

        Raises ValueError for anything that is not what the query prints:
        nothing is forwarded from an answer that cannot be trusted whole.
        """
        answer = json.loads(output)
        if not isinstance(answer, dict):
            raise ValueError("the answer is not an object")
        newest = answer.get("newest")
        if isinstance(newest, bool) or not isinstance(newest, int) or newest < 0:
            raise ValueError("the answer has no newest record id")
        events = answer.get("events")
        if events is None:
            events = []
        if isinstance(events, dict):
            events = [events]  # ConvertTo-Json writes a list of one as the one
        if not isinstance(events, list):
            raise ValueError("the answer's events are not a list")
        for event in events:
            record = event.get("RecordId") if isinstance(event, dict) else None
            if isinstance(record, bool) or not isinstance(record, int) or record < 0:
                raise ValueError("an event has no record id")
        events = sorted(events, key=lambda event: event["RecordId"])
        if after is not None:
            # Whatever the query returned: nothing is forwarded twice.
            events = [event for event in events if event["RecordId"] > after]
        return newest, events

    async def _windows_pause(self, seconds: float):
        await asyncio.sleep(seconds)

    async def _monitor_windows_events(self, runtime: _SystemSource):
        """Follow a Windows event log"""
        source = runtime.source
        log_name = source.log_name
        logger.info(
            "Log source %r: following the Windows event log %s %s",
            source.name,
            log_name,
            (
                "from its newest event on"
                if runtime.read_record is None
                else f"after record {runtime.read_record}"
            ),
        )

        while self.running:
            more = False
            try:
                argv = self._windows_events_command(log_name, runtime.read_record)
                # Off the event loop: PowerShell takes seconds to start, and
                # everything else the sensor does would wait for it.
                output = await asyncio.to_thread(self._run_windows_query, argv)
                newest, events = self._parse_windows_events(
                    output, runtime.read_record
                )
            except asyncio.CancelledError:
                raise
            except FileNotFoundError:
                runtime.state = "unavailable"
                runtime.last_error = "powershell is not installed"
                logger.warning(
                    "Log source %r (windows_event) is not read: powershell is "
                    "not installed here",
                    source.name,
                )
                return
            except Exception as e:
                problem = f"{type(e).__name__}: {e}"[:STDERR_KEPT]
                if runtime.state != "failing" or runtime.last_error != problem:
                    logger.warning(
                        "Log source %r: the event log %s cannot be read: %s. It "
                        "is asked again every %.0f seconds",
                        source.name,
                        log_name,
                        problem,
                        WINDOWS_POLL_INTERVAL,
                    )
                runtime.state = "failing"
                runtime.last_error = problem
            else:
                if runtime.state == "failing":
                    logger.info(
                        "Log source %r: the event log %s is read again",
                        source.name,
                        log_name,
                    )
                runtime.state = "running"
                runtime.last_error = None
                if runtime.read_record is None:
                    # The first look: from here on, like a file read from
                    # its end. Saved, so that a restart goes on from here.
                    runtime.read_record = runtime.accepted_record = newest
                    self._positions_dirty = True
                elif newest < runtime.read_record:
                    logger.warning(
                        "Log source %r: the event log %s was cleared (its "
                        "newest record is %d, the last one read was %d); it "
                        "is read from its beginning",
                        source.name,
                        log_name,
                        newest,
                        runtime.read_record,
                    )
                    runtime.pending.clear()
                    runtime.read_record = runtime.accepted_record = 0
                    self._positions_dirty = True
                    more = True  # asked again at once, from record 0
                else:
                    for event in events:
                        await self._windows_event(runtime, event)
                    more = len(events) >= WINDOWS_MAX_EVENTS
            await self._windows_pause(0 if more else WINDOWS_POLL_INTERVAL)

    async def _windows_event(self, runtime: _SystemSource, data: Dict[str, Any]):
        """Queue one event of a Windows event log."""
        source = runtime.source
        record = data["RecordId"]
        metadata = {
            'log_source': source.name,
            'log_name': source.log_name,
            'format': 'windows_event'
        }
        message = data.get("Message")
        if isinstance(message, str) and len(message) > MAX_LINE_BYTES:
            data = dict(data, Message=message[:MAX_LINE_BYTES])
            metadata['truncated'] = True
            runtime.entries_truncated += 1

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'log_forwarder',
            'type': f"log.{source.name}",
            'data': data,
            'metadata': metadata
        }
        entry = _Pending(record)
        runtime.pending.append(entry)
        event[DELIVERY_KEY] = Delivery(
            lambda: self._windows_settled(runtime, entry),
            replayable=self.positions.persistent,
        )
        runtime.read_record = record

        await self.event_queue.put(event)
        runtime.entries_forwarded += 1

    def _windows_settled(self, runtime: _SystemSource, entry: _Pending):
        """The sensor has finished with an event: the saved record id moves
        to the last event settled with all those read before it."""
        last = _settle_in_order(runtime.pending, entry)
        if last is not None:
            runtime.accepted_record = last.end
            self._positions_dirty = True

    # the macOS unified log

    @staticmethod
    def _unified_log_command() -> List[str]:
        """log stream, one JSON object per line. (--style json prints one
        array over many lines, of which no line is an entry: the reader
        that asked for it never forwarded anything.)"""
        return ["log", "stream", "--style", "ndjson"]

    async def _monitor_unified_log(self, runtime: _SystemSource):
        """Follow the macOS unified log"""
        logger.info(
            "Log source %r: following the unified log from now on",
            runtime.source.name,
        )

        async def handle(line: bytes, cut: bool):
            await self._unified_log_entry(runtime, line, cut)

        await self._follow_command(runtime, self._unified_log_command, handle)

    async def _unified_log_entry(self, runtime: _SystemSource, raw: bytes, cut: bool):
        """Queue one entry of log stream's output."""
        source = runtime.source
        metadata = {'log_source': source.name, 'format': 'json'}
        if cut:
            data: Any = {'raw_message': self._cut_text(raw)}
            metadata['truncated'] = True
        else:
            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                return
            try:
                data = json.loads(text)
            except (ValueError, RecursionError):
                data = None
            if not isinstance(data, dict):
                # Among them the line log stream begins with, which says
                # what it filters on.
                runtime.entries_unparsed += 1
                return

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'log_forwarder',
            'type': f"log.{source.name}",
            'data': data,
            'metadata': metadata
        }
        # No Delivery: log stream cannot be asked for an entry again.
        await self.event_queue.put(event)
        runtime.entries_forwarded += 1
        if cut:
            runtime.entries_truncated += 1

    # -- events -----------------------------------------------------------

    async def _process_log_line(
        self,
        line: str,
        source: LogSourceConfig,
        path: Optional[str] = None,
        truncated: bool = False,
        delivery: Optional[Delivery] = None,
    ) -> bool:
        """Process a single log line; False when it yields no event"""
        try:
            parsed_log = self._parse_log_line(line, source.format)
        except Exception as e:
            logger.debug(f"Error processing log line: {e}")
            return False

        if not parsed_log:
            return False

        metadata = {
            'log_source': source.name,
            # The file the line was read from: for a pattern, the match.
            'log_file': path or source.path or '',
            'format': source.format
        }
        if truncated:
            metadata['truncated'] = True
            self.stats["lines_truncated"] += 1

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'log_forwarder',
            'type': f"log.{source.name}",
            'data': parsed_log,
            'metadata': metadata
        }
        if delivery is not None:
            # Not part of the event: the pipeline takes it out and settles
            # it when the sensor has finished with the event.
            event[DELIVERY_KEY] = delivery

        await self.event_queue.put(event)
        self.stats["lines_forwarded"] += 1
        return True

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

    @staticmethod
    def _behind(tail: _Tail) -> Optional[int]:
        """Bytes of the file beyond what was read; None if it cannot be
        looked at."""
        try:
            return max(0, os.fstat(tail.fd).st_size - tail.position)
        except OSError:
            return None

    def get_status(self) -> Dict[str, Any]:
        """Get log forwarder status"""
        sources = []
        monitored = 0
        for source in self.log_sources:
            entry = {
                'name': source.name,
                'type': source.type,
                'enabled': source.enabled
            }
            state = self._file_sources.get(source.name)
            if source.type == 'file':
                entry['path'] = source.path
                entry['format'] = source.format
                entry['files'] = sorted(state.tails) if state else []
                entry['problems'] = dict(state.problems) if state else {}
                # How far each file was read, and up to where the data
                # service has accepted its lines (what a restart goes on
                # from): the difference is in the sensor, or on its way.
                entry['positions'] = {
                    path: {
                        'read': tail.position,
                        'accepted': tail.record.offset,
                        # What the file holds that has not been read yet:
                        # it grows when the log is written faster than the
                        # sensor can deliver.
                        'behind': self._behind(tail),
                    }
                    for path, tail in sorted(state.tails.items())
                } if state else {}
                monitored += len(entry['files'])
            runtime = self._system_sources.get(source.name)
            if runtime is not None:
                entry.update(runtime.status())
            sources.append(entry)
        return {
            'running': self.running,
            'default_sources': self.using_default_sources,
            'log_sources': sources,
            'monitored_files': monitored,
            'positions': self.positions.get_status(),
            'stats': self.stats.copy()
        }


def _uid() -> Any:
    return os.geteuid() if hasattr(os, "geteuid") else "unknown"
