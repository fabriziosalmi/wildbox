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

from sensor.collectors.position_store import MAX_FILES, PositionStore, file_entries
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
    the bytes before that point."""

    __slots__ = ("end", "window", "settled")

    def __init__(self, end: int, window: bytes):
        self.end = end
        self.window = window
        self.settled = False


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
                if unsupported:
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
                    monitor = self._monitor_journald(source)
                elif source.type == "windows_event":
                    monitor = self._monitor_windows_events(source)
                elif source.type == "unified_log":
                    monitor = self._monitor_unified_log(source)

                if monitor is not None:
                    self._tasks.append(asyncio.create_task(monitor))

            logger.info(f"Log forwarder started with {len(self._tasks)} sources")

            if self.positions.persistent:
                self._tasks.append(asyncio.create_task(self._save_periodically()))
            elif self._file_sources:
                logger.warning(
                    "data_dir is not set: read positions are kept in memory "
                    "only. After a restart each file source starts as its "
                    "read_from says: from the end, it skips what was written "
                    "meanwhile; from the beginning, it sends everything again"
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

    def _settled(self, tail: _Tail, entry: _Pending):
        """The sensor has finished with a line's event: move the file's
        saved offset past every line settled with all those before it."""
        entry.settled = True
        last = None
        while tail.pending and tail.pending[0].settled:
            last = tail.pending.popleft()
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
            if name in configured and name not in self._file_sources
        }
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

    async def _monitor_journald(self, source: LogSourceConfig):
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

            try:
                while self.running:
                    try:
                        line = await process.stdout.readline()
                        if not line:
                            break

                        line_str = line.decode('utf-8', errors='replace').strip()
                        if line_str:
                            await self._process_journal_entry(line_str, source)

                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.error(f"Error reading journald: {e}")
                        break
            finally:
                # Cleanup
                try:
                    process.terminate()
                    await process.wait()
                except (OSError, ProcessLookupError):
                    pass

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                "Log source %r: journald cannot be read: %s", source.name, e
            )

    async def _monitor_windows_events(self, source: LogSourceConfig):
        """Monitor Windows Event Log"""
        if not is_windows():
            return

        log_name = source.log_name

        # SECURITY: Validate log_name to prevent command injection
        if not re.match(r'^[A-Za-z][A-Za-z0-9 _-]{0,63}$', log_name or ''):
            logger.error(f"Invalid Windows Event Log name rejected: {log_name!r}")
            return

        logger.info(f"Starting Windows Event Log monitoring: {log_name}")

        # This would require Windows-specific implementation
        # For now, we'll use a placeholder
        while self.running:
            try:
                # PowerShell command to get latest events
                # log_name is validated above — pass as a single argument to prevent injection
                ps_command = f'Get-EventLog -LogName "{log_name}" -Newest 10 | ConvertTo-Json'
                cmd = [
                    'powershell',
                    '-NoProfile',
                    '-NonInteractive',
                    '-Command', ps_command
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
                raise
            except Exception as e:
                logger.error(f"Error monitoring Windows events: {e}")
                await asyncio.sleep(30)

    async def _monitor_unified_log(self, source: LogSourceConfig):
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

            try:
                while self.running:
                    try:
                        line = await process.stdout.readline()
                        if not line:
                            break

                        line_str = line.decode('utf-8', errors='replace').strip()
                        if line_str:
                            await self._process_unified_log_entry(line_str, source)

                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.error(f"Error reading unified log: {e}")
                        break
            finally:
                # Cleanup
                try:
                    process.terminate()
                    await process.wait()
                except (OSError, ProcessLookupError):
                    pass

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                "Log source %r: the unified log cannot be read: %s", source.name, e
            )

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

    async def _process_journal_entry(self, entry: str, source: LogSourceConfig):
        """Process a journald entry"""
        try:
            journal_data = json.loads(entry)
        except ValueError as e:
            logger.debug(f"Error processing journal entry: {e}")
            return

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'log_forwarder',
            'type': f"log.{source.name}",
            'data': journal_data,
            'metadata': {
                'log_source': source.name,
                'format': 'json'
            }
        }

        await self.event_queue.put(event)

    async def _process_windows_event(self, event: Dict[str, Any], source: LogSourceConfig):
        """Process a Windows event"""
        processed_event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'log_forwarder',
            'type': f"log.windows.{source.log_name.lower()}",
            'data': event,
            'metadata': {
                'log_source': source.log_name,
                'format': 'windows_event'
            }
        }

        await self.event_queue.put(processed_event)

    async def _process_unified_log_entry(self, entry: str, source: LogSourceConfig):
        """Process a macOS unified log entry"""
        try:
            log_data = json.loads(entry)
        except ValueError as e:
            logger.debug(f"Error processing unified log entry: {e}")
            return

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'log_forwarder',
            'type': 'log.unified',
            'data': log_data,
            'metadata': {
                'log_source': source.name,
                'format': 'json'
            }
        }

        await self.event_queue.put(event)

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
                    path: {'read': tail.position, 'accepted': tail.record.offset}
                    for path, tail in sorted(state.tails.items())
                } if state else {}
                monitored += len(entry['files'])
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
