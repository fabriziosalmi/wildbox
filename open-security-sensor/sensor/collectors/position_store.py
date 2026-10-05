"""Where the log forwarder's read positions outlive the process (#725).

One small JSON file, ``log-positions.json``, in the sensor's data directory
(``data_dir``). For each log source it holds what is needed to go on where
the data service's last accepted event was:

* a file source: its configured path and, for each file it read, the file's
  identity (device and inode), the offset after the last line the data
  service accepted, and two SHA-256 digests that tell this file from another
  one with the same identity: of its first bytes, and of the bytes just
  before the offset. No log content is stored, only digests of it;
* a journald source: the cursor of the last accepted entry;
* a Windows event log source: the record id of the last accepted event.

It is written atomically (a temporary file in the same directory, flushed to
disk, renamed over the old one, the directory flushed), so a crash leaves the
old file or the new one, never half of one.

It is read once, when the sensor starts, and it is not trusted: the file
must be a regular file of the sensor's own user, not a link, within the size
limit, and every value in it must have the type and range this module
writes. Anything else and the whole file is ignored, with a warning, as if
there were none; so is a position that does not match the file it names (see
the log forwarder). A state file can therefore make the sensor read a log
again, never read a file it would not have read.

One sensor per data directory: two sensors sharing one would each overwrite
the other's positions.
"""

import glob
import json
import logging
import os
import re
import stat
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

STATE_FILE = "log-positions.json"
STATE_FORMAT = "wildbox-sensor-log-positions"
STATE_VERSION = 1
# The file is refused beyond this. What the forwarder writes stays far below:
# at most MAX_SOURCES sources of MAX_FILES files, about 250 bytes each.
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_SOURCES = 64
# Files remembered per source: those being read and the most recent others.
MAX_FILES = 128
MAX_PATH = 4096
HEAD_BYTES = 256

_TMP_PREFIX = ".log-positions."
_TMP_SUFFIX = ".tmp"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
# A journal cursor: "s=...;i=...;b=...;m=...;t=...;x=...".
_CURSOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9=;:_.+/-]{0,511}$")
_WINDOWS_LOG_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,63}$")
_MAX_INT = 2**63 - 1

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)


class _Invalid(Exception):
    """Why the state file is not used."""


def _whole(value: Any, what: str, most: int = _MAX_INT) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Invalid(f"{what} is not a whole number")
    if not 0 <= value <= most:
        raise _Invalid(f"{what} is out of range")
    return value


def _text(value: Any, what: str, pattern: Optional[re.Pattern] = None) -> str:
    if not isinstance(value, str) or len(value) > MAX_PATH or "\x00" in value:
        raise _Invalid(f"{what} is not a string this sensor wrote")
    if pattern is not None and not pattern.match(value):
        raise _Invalid(f"{what} is not a value this sensor wrote")
    return value


def _mapping(value: Any, what: str, keys: tuple) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise _Invalid(f"{what} is not a mapping")
    if set(value) != set(keys):
        raise _Invalid(f"{what} does not have exactly the keys {', '.join(keys)}")
    return value


_FILE_KEYS = (
    "device",
    "inode",
    "offset",
    "check",
    "head_bytes",
    "head",
    "path",
    "seen",
)


def _valid_file(value: Any, what: str) -> Dict[str, Any]:
    entry = _mapping(value, what, _FILE_KEYS)
    seen = entry["seen"]
    if isinstance(seen, bool) or not isinstance(seen, (int, float)):
        raise _Invalid(f"{what}.seen is not a number")
    if not 0 <= seen <= 1e12:  # also refuses NaN
        raise _Invalid(f"{what}.seen is out of range")
    return {
        "device": _whole(entry["device"], f"{what}.device", 2**64 - 1),
        "inode": _whole(entry["inode"], f"{what}.inode", 2**64 - 1),
        "offset": _whole(entry["offset"], f"{what}.offset"),
        "check": _text(entry["check"], f"{what}.check", _DIGEST),
        "head_bytes": _whole(entry["head_bytes"], f"{what}.head_bytes", HEAD_BYTES),
        "head": _text(entry["head"], f"{what}.head", _DIGEST),
        "path": _text(entry["path"], f"{what}.path"),
        "seen": float(seen),
    }


def _valid_source(value: Any, what: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise _Invalid(f"{what} is not a mapping")
    kind = value.get("type")
    if kind == "file":
        entry = _mapping(value, what, ("type", "path", "files"))
        files = entry["files"]
        if not isinstance(files, list) or len(files) > MAX_FILES:
            raise _Invalid(f"{what}.files is not a list of at most {MAX_FILES}")
        valid = [
            _valid_file(item, f"{what}.files[{index}]")
            for index, item in enumerate(files)
        ]
        identities = {(item["device"], item["inode"]) for item in valid}
        if len(identities) != len(valid):
            raise _Invalid(f"{what}.files names the same file twice")
        return {
            "type": "file",
            "path": _text(entry["path"], f"{what}.path"),
            "files": valid,
        }
    if kind == "journald":
        entry = _mapping(value, what, ("type", "cursor"))
        return {
            "type": "journald",
            "cursor": _text(entry["cursor"], f"{what}.cursor", _CURSOR),
        }
    if kind == "windows_event":
        entry = _mapping(value, what, ("type", "log_name", "record_id"))
        return {
            "type": "windows_event",
            "log_name": _text(entry["log_name"], f"{what}.log_name", _WINDOWS_LOG_NAME),
            "record_id": _whole(entry["record_id"], f"{what}.record_id"),
        }
    raise _Invalid(f"{what}.type is not one this sensor writes")


def validate_state(document: Any) -> Dict[str, Dict[str, Any]]:
    """The sources of a state document; raises _Invalid for anything this
    module would not have written."""
    top = _mapping(
        document, "the document", ("format", "version", "saved_at", "sources")
    )
    if top["format"] != STATE_FORMAT:
        raise _Invalid("it is not a sensor's position file")
    if isinstance(top["version"], bool) or top["version"] != STATE_VERSION:
        raise _Invalid(
            f"its version is {top['version']!r}, this sensor reads " f"{STATE_VERSION}"
        )
    _text(top["saved_at"], "saved_at")
    sources = top["sources"]
    if not isinstance(sources, dict) or len(sources) > MAX_SOURCES:
        raise _Invalid(f"sources is not a mapping of at most {MAX_SOURCES}")
    valid = {}
    for name, value in sources.items():
        if not isinstance(name, str) or not _NAME.match(name):
            raise _Invalid("a source's name is not one a configuration allows")
        valid[name] = _valid_source(value, f"sources[{name!r}]")
    return valid


def data_dir_problem(directory: str) -> Optional[str]:
    """Why ``directory`` cannot hold the sensor's state, if it cannot."""
    if not os.path.isabs(directory):
        return f"data_dir must be an absolute path, got {directory!r}"
    if not os.path.isdir(directory):
        return (
            f"data_dir {directory!r} does not exist or is not a directory: "
            f"create it, owned by the sensor's user"
        )
    if not os.access(directory, os.R_OK | os.W_OK | os.X_OK):
        return (
            f"data_dir {directory!r} is not writable by the sensor's user "
            f"(uid {_uid()})"
        )
    return None


class PositionStore:
    """Read and write the position file; in memory only without a directory."""

    def __init__(self, directory: Optional[str]):
        self.directory = directory or None
        self.path = os.path.join(directory, STATE_FILE) if directory else None
        # Why the last read or write did not work, for the status and so
        # that the same failure is logged once.
        self.problem: Optional[str] = None
        self.last_saved: Optional[str] = None
        # Writes come from the event loop (at stop) and from a worker
        # thread (while running): one at a time, and never an older picture
        # of the positions over a newer one.
        self._lock = threading.Lock()
        self._serial = 0
        self._written = 0

    @property
    def persistent(self) -> bool:
        return self.path is not None

    def load(self) -> Dict[str, Dict[str, Any]]:
        """The saved positions by source name; empty when there is no usable
        file. Never raises: a file that cannot be used is reported and
        ignored."""
        if not self.persistent:
            return {}
        self._remove_leftovers()
        try:
            document = self._read()
        except FileNotFoundError:
            logger.info(
                "No saved log positions in %s yet: each source starts as its "
                "read_from says",
                self.directory,
            )
            return {}
        except (_Invalid, OSError, ValueError, RecursionError) as e:
            reason = e.strerror if isinstance(e, OSError) and e.strerror else e
            logger.warning(
                "The saved log positions in %s are ignored: %s. Each source "
                "starts as its read_from says, and the file is replaced at "
                "the next save",
                self.path,
                reason,
            )
            return {}
        return document

    def _read(self) -> Dict[str, Dict[str, Any]]:
        flags = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC | _O_BINARY
        fd = os.open(self.path, flags)
        try:
            found = os.fstat(fd)
            if not stat.S_ISREG(found.st_mode):
                raise _Invalid("it is not a regular file")
            if hasattr(os, "geteuid") and found.st_uid != os.geteuid():
                raise _Invalid(
                    f"it belongs to uid {found.st_uid}, not to the sensor's "
                    f"user (uid {os.geteuid()})"
                )
            if found.st_size > MAX_STATE_BYTES:
                raise _Invalid(
                    f"its {found.st_size} bytes are more than a position "
                    f"file holds ({MAX_STATE_BYTES})"
                )
            raw = b""
            while len(raw) <= MAX_STATE_BYTES:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(fd)
        if len(raw) > MAX_STATE_BYTES:
            raise _Invalid("it is larger than a position file")
        try:
            document = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise _Invalid("it is not valid JSON") from None
        return validate_state(document)

    def next_serial(self) -> int:
        """A number for a picture of the positions about to be taken; a
        later picture has a higher one."""
        self._serial += 1
        return self._serial

    def save(
        self, sources: Dict[str, Dict[str, Any]], serial: Optional[int] = None
    ) -> bool:
        """Write the positions; False, and ``problem`` set, when it fails.

        With ``serial`` (see ``next_serial``), a picture older than the one
        already written is not written over it.
        """
        if not self.persistent:
            return False
        with self._lock:
            if serial is not None:
                if serial < self._written:
                    return True
            if not self._write(sources):
                return False
            if serial is not None:
                self._written = serial
            return True

    def _write(self, sources: Dict[str, Dict[str, Any]]) -> bool:
        saved_at = datetime.now(timezone.utc).isoformat()
        document = {
            "format": STATE_FORMAT,
            "version": STATE_VERSION,
            "saved_at": saved_at,
            "sources": sources,
        }
        payload = json.dumps(document, sort_keys=True, allow_nan=False).encode()
        temporary = None
        try:
            if len(payload) > MAX_STATE_BYTES:
                raise OSError(
                    f"the positions take {len(payload)} bytes, more than "
                    f"the file may hold ({MAX_STATE_BYTES})"
                )
            fd, temporary = tempfile.mkstemp(
                dir=self.directory, prefix=_TMP_PREFIX, suffix=_TMP_SUFFIX
            )
            try:
                view = memoryview(payload)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, self.path)
            temporary = None
            self._sync_directory()
        except OSError as e:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            problem = f"the log positions cannot be saved in {self.directory}: " + (
                e.strerror or str(e)
            )
            if problem != self.problem:
                self.problem = problem
                logger.error(
                    "%s. Until it works, a restart reads again what was "
                    "sent since the last save",
                    problem,
                )
            return False
        if self.problem is not None:
            logger.info("The log positions are saved in %s again", self.path)
        self.problem = None
        self.last_saved = saved_at
        return True

    def _sync_directory(self):
        """Make the rename itself durable, where the platform can."""
        if not hasattr(os, "O_DIRECTORY"):
            return
        try:
            fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _remove_leftovers(self):
        """Temporary files of a save that a crash interrupted."""
        pattern = os.path.join(
            glob.escape(self.directory), _TMP_PREFIX + "*" + _TMP_SUFFIX
        )
        for path in glob.glob(pattern)[:1000]:
            try:
                if stat.S_ISREG(os.lstat(path).st_mode):
                    os.unlink(path)
            except OSError:
                pass

    def get_status(self) -> Dict[str, Any]:
        return {
            "persisted": self.persistent and self.problem is None,
            "file": self.path,
            "last_saved": self.last_saved,
            "problem": (
                self.problem
                if self.persistent
                else "data_dir is not set: positions are kept in memory only"
            ),
        }


def _uid() -> Any:
    return os.geteuid() if hasattr(os, "geteuid") else "unknown"


def file_entries(
    sources: Dict[str, Dict[str, Any]], name: str, path: str
) -> Optional[List[Dict[str, Any]]]:
    """The saved files of file source ``name``, if it was saved for ``path``.

    None when the source is not known: never seen, of another type then, or
    pointed at another path since.
    """
    entry = sources.get(name)
    if not entry or entry.get("type") != "file" or entry.get("path") != path:
        return None
    return entry["files"]
