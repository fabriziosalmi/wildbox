"""Where the file monitor's baseline outlives the process (#745).

One JSON file, ``fim-baseline.json``, in the sensor's data directory
(``data_dir``). For each watched file it holds what the monitor compares at
every scan: size, modification and change time, mode, owner, group and, when
the file was hashed, the SHA-256 of its content. No file content is stored.

The baseline is what the data service has been told, not what the monitor
last saw: a file's entry moves when the event that reports its change is
accepted (or dropped for good, and counted), as a log's read position does.
A sensor that stops with a change still unsent reports it again when it
starts; and what changed while it was stopped is found by comparing the
files with the baseline, where it used to be taken for the new normal.

The file is written and read like the position file
(``sensor.utils.state_file``): atomically, and without trust. Every value in
it must have the type and range this module writes, every path must be
under one of the roots the file names, and the file must have been written
for the same ``fim`` settings. Anything else and the whole file is ignored,
with a warning, as if there were none: the monitor then takes what it finds
as its baseline, which is what it did at every start before. A baseline file
can therefore make the monitor report changes, or miss those made while it
was stopped; it cannot make it read a path the configuration does not name.
"""

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sensor.utils.state_file import Invalid, StateFile

logger = logging.getLogger(__name__)

BASELINE_FILE = "fim-baseline.json"
BASELINE_FORMAT = "wildbox-sensor-fim-baseline"
BASELINE_VERSION = 1
# The file is refused beyond this. An entry takes about 250 bytes with a
# path of ordinary length, so the default fim.max_files (50,000) is about
# 12 MiB.
MAX_BASELINE_BYTES = 128 * 1024 * 1024
MAX_ROOTS = 256
MAX_PATH = 4096
MAX_PATTERNS = 256

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_INT = 2**63 - 1
_STATE_KEYS = ("size", "mtime", "ctime", "mode", "uid", "gid", "hash")
_WATCH_KEYS = ("exclude_patterns", "max_depth", "max_files")

State = Dict[str, Any]


def under(path: str, root: str) -> bool:
    """Is ``path`` the root itself or something below it? "/etc2/x" is not
    under "/etc"."""
    if path == root:
        return True
    prefix = root if root.endswith(os.sep) else root + os.sep
    return path.startswith(prefix)


def _mapping(value: Any, what: str, keys: tuple) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise Invalid(f"{what} is not a mapping")
    if set(value) != set(keys):
        raise Invalid(f"{what} does not have exactly the keys {', '.join(keys)}")
    return value


def _whole(value: Any, what: str, most: int = _MAX_INT) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise Invalid(f"{what} is not a whole number")
    if not 0 <= value <= most:
        raise Invalid(f"{what} is out of range")
    return value


def _time(value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Invalid(f"{what} is not a number")
    if not -1e12 <= value <= 1e12:  # also refuses NaN
        raise Invalid(f"{what} is out of range")
    return value


def _path(value: Any, what: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_PATH
        or "\x00" in value
        or not os.path.isabs(value)
    ):
        raise Invalid(f"{what} is not an absolute path")
    return value


def _valid_state(path: str, value: Any) -> State:
    what = f"files[{path!r}]"
    entry = _mapping(value, what, _STATE_KEYS)
    digest = entry["hash"]
    if digest is not None and (
        not isinstance(digest, str) or not _DIGEST.match(digest)
    ):
        raise Invalid(f"{what}.hash is not a SHA-256 digest")
    owner = {}
    for key in ("uid", "gid"):
        # None where the platform has no such thing.
        owner[key] = (
            None if entry[key] is None else _whole(entry[key], f"{what}.{key}", 2**32)
        )
    return {
        "path": path,
        "size": _whole(entry["size"], f"{what}.size"),
        "mtime": _time(entry["mtime"], f"{what}.mtime"),
        "ctime": _time(entry["ctime"], f"{what}.ctime"),
        "mode": _whole(entry["mode"], f"{what}.mode", 2**32),
        "uid": owner["uid"],
        "gid": owner["gid"],
        "hash": digest,
    }


def valid_watch(value: Any) -> Dict[str, Any]:
    """The fim settings a baseline was taken with."""
    watch = _mapping(value, "watch", _WATCH_KEYS)
    patterns = watch["exclude_patterns"]
    if (
        not isinstance(patterns, list)
        or len(patterns) > MAX_PATTERNS
        or not all(isinstance(p, str) and len(p) <= MAX_PATH for p in patterns)
    ):
        raise Invalid("watch.exclude_patterns is not a list of patterns")
    return {
        "exclude_patterns": list(patterns),
        "max_depth": _whole(watch["max_depth"], "watch.max_depth"),
        "max_files": _whole(watch["max_files"], "watch.max_files"),
    }


def validate_baseline(
    document: Any,
) -> Tuple[str, Dict[str, Any], List[str], Dict[str, State]]:
    """(saved_at, watch, roots, files) of a baseline document; raises
    Invalid for anything this module would not have written."""
    top = _mapping(
        document,
        "the document",
        ("format", "version", "saved_at", "watch", "roots", "files"),
    )
    if top["format"] != BASELINE_FORMAT:
        raise Invalid("it is not a sensor's file monitor baseline")
    if isinstance(top["version"], bool) or top["version"] != BASELINE_VERSION:
        raise Invalid(
            f"its version is {top['version']!r}, this sensor reads "
            f"{BASELINE_VERSION}"
        )
    saved_at = top["saved_at"]
    if not isinstance(saved_at, str) or len(saved_at) > 64:
        raise Invalid("saved_at is not a time this sensor wrote")
    watch = valid_watch(top["watch"])
    roots = top["roots"]
    if not isinstance(roots, list) or len(roots) > MAX_ROOTS:
        raise Invalid(f"roots is not a list of at most {MAX_ROOTS}")
    roots = [_path(root, f"roots[{index}]") for index, root in enumerate(roots)]
    if len(set(roots)) != len(roots):
        raise Invalid("roots names the same path twice")
    files = top["files"]
    if not isinstance(files, dict) or len(files) > watch["max_files"]:
        raise Invalid(
            f"files is not a mapping of at most {watch['max_files']} "
            f"(watch.max_files)"
        )
    valid = {}
    for path, value in files.items():
        _path(path, "a file's path")
        if not any(under(path, root) for root in roots):
            raise Invalid(f"files[{path!r}] is under none of the roots")
        valid[path] = _valid_state(path, value)
    return saved_at, watch, roots, valid


class BaselineStore:
    """Read and write the baseline file; in memory only without a directory."""

    def __init__(self, directory: Optional[str]):
        self.directory = directory or None
        self._file = (
            StateFile(directory, BASELINE_FILE, MAX_BASELINE_BYTES, "a baseline file")
            if directory
            else None
        )
        self.path = self._file.path if self._file else None
        # Why the last write did not work, for the status and so that the
        # same failure is logged once.
        self.problem: Optional[str] = None
        self.last_saved: Optional[str] = None
        # What became of the file found at start, for the status.
        self.loaded: Optional[str] = None
        # Writes come from a worker thread (while running) and from the
        # event loop (at stop): one at a time, and never an older picture of
        # the baseline over a newer one.
        self._lock = threading.Lock()
        self._serial = 0
        self._written = 0

    @property
    def persistent(self) -> bool:
        return self._file is not None

    def load(
        self, watch: Dict[str, Any]
    ) -> Optional[Tuple[str, List[str], Dict[str, State]]]:
        """(saved_at, roots, files) of the saved baseline, or None when
        there is no usable one. Never raises: a file that cannot be used is
        reported and ignored."""
        if not self.persistent:
            self.loaded = "data_dir is not set"
            return None
        self._file.remove_leftovers()
        try:
            raw = self._file.read()
            try:
                document = json.loads(raw.decode("utf-8"))
            except ValueError:
                raise Invalid("it is not valid JSON") from None
            saved_at, saved_watch, roots, files = validate_baseline(document)
        except FileNotFoundError:
            self.loaded = "none was saved yet"
            logger.info(
                "No saved file monitor baseline in %s yet: what the watched "
                "paths hold now is the baseline",
                self.directory,
            )
            return None
        except (Invalid, OSError, ValueError, RecursionError) as e:
            reason = e.strerror if isinstance(e, OSError) and e.strerror else e
            self.loaded = f"ignored: {reason}"
            logger.warning(
                "The saved file monitor baseline %s is ignored: %s. What the "
                "watched paths hold now is the baseline: a change made while "
                "the sensor was stopped is not reported. The file is "
                "replaced at the next save",
                self.path,
                reason,
            )
            return None
        if saved_watch != watch:
            self.loaded = "ignored: the fim settings have changed since"
            logger.warning(
                "The saved file monitor baseline %s was taken with other fim "
                "settings (exclude_patterns, max_depth or max_files) and is "
                "not used: what the watched paths hold now is the baseline",
                self.path,
            )
            return None
        self.loaded = f"saved at {saved_at}"
        return saved_at, roots, files

    def next_serial(self) -> int:
        """A number for a picture of the baseline about to be taken; a later
        picture has a higher one."""
        self._serial += 1
        return self._serial

    def save(
        self,
        watch: Dict[str, Any],
        roots: List[str],
        files: Dict[str, State],
        serial: Optional[int] = None,
    ) -> bool:
        """Write the baseline; False, and ``problem`` set, when it fails.

        With ``serial`` (see ``next_serial``), a picture older than the one
        already written is not written over it.
        """
        if not self.persistent:
            return False
        with self._lock:
            if serial is not None and serial < self._written:
                return True
            if not self._write(watch, roots, files):
                return False
            if serial is not None:
                self._written = serial
            return True

    def _write(self, watch, roots, files) -> bool:
        saved_at = datetime.now(timezone.utc).isoformat()
        document = {
            "format": BASELINE_FORMAT,
            "version": BASELINE_VERSION,
            "saved_at": saved_at,
            "watch": watch,
            "roots": roots,
            "files": {
                path: {key: state.get(key) for key in _STATE_KEYS}
                for path, state in files.items()
            },
        }
        try:
            try:
                payload = json.dumps(document, sort_keys=True, allow_nan=False).encode()
            except (ValueError, TypeError) as e:
                raise OSError(f"it cannot be written as JSON ({e})") from None
            self._file.write(payload)
        except OSError as e:
            problem = (
                f"the file monitor baseline cannot be saved in "
                f"{self.directory}: " + (e.strerror or str(e))
            )
            if problem != self.problem:
                self.problem = problem
                logger.error(
                    "%s. Until it works, a restart compares the files with "
                    "the baseline last saved, and reports again what was "
                    "sent since; or, if none was ever saved, takes what it "
                    "finds as the baseline",
                    problem,
                )
            return False
        if self.problem is not None:
            logger.info("The file monitor baseline is saved in %s again", self.path)
        self.problem = None
        self.last_saved = saved_at
        return True

    def get_status(self) -> Dict[str, Any]:
        return {
            "persisted": self.persistent and self.problem is None,
            "file": self.path,
            "loaded": self.loaded,
            "last_saved": self.last_saved,
            "problem": (
                self.problem
                if self.persistent
                else "data_dir is not set: the baseline is kept in memory only, "
                "and what changes while the sensor is stopped is not reported"
            ),
        }
