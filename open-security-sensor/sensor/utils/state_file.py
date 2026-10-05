"""One file of the sensor's own state under ``data_dir``, read and written
the same way whatever it holds (the log positions, the file monitor's
baseline).

Written atomically: a temporary file in the same directory, flushed to
disk, renamed over the old one, the directory flushed. A crash leaves the
old file or the new one, never half of one.

Read without trust: the file must be a regular file of the sensor's own
user, not a link, and within its size limit. What its bytes mean, and
whether every value in them is one the sensor wrote, is for the caller to
check; ``Invalid`` is how either says that the file is not used.
"""

import glob
import os
import stat
import tempfile

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)

_TMP_SUFFIX = ".tmp"


class Invalid(Exception):
    """Why a state file is not used."""


class StateFile:
    """``name`` in ``directory``: at most ``max_bytes``, and called ``what``
    ("a position file") when it is refused."""

    def __init__(self, directory: str, name: str, max_bytes: int, what: str):
        self.directory = directory
        self.path = os.path.join(directory, name)
        self.max_bytes = max_bytes
        self.what = what
        # ".log-positions." for "log-positions.json".
        self._tmp_prefix = "." + name.rsplit(".", 1)[0] + "."

    def read(self) -> bytes:
        """The file's bytes. FileNotFoundError when there is none, Invalid
        when it is not one this sensor could have written."""
        flags = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC | _O_BINARY
        fd = os.open(self.path, flags)
        try:
            found = os.fstat(fd)
            if not stat.S_ISREG(found.st_mode):
                raise Invalid("it is not a regular file")
            if hasattr(os, "geteuid") and found.st_uid != os.geteuid():
                raise Invalid(
                    f"it belongs to uid {found.st_uid}, not to the sensor's "
                    f"user (uid {os.geteuid()})"
                )
            if found.st_size > self.max_bytes:
                raise Invalid(
                    f"its {found.st_size} bytes are more than {self.what} "
                    f"holds ({self.max_bytes})"
                )
            chunks, size = [], 0
            while size <= self.max_bytes:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
        finally:
            os.close(fd)
        if size > self.max_bytes:
            raise Invalid(f"it is larger than {self.what}")
        return b"".join(chunks)

    def write(self, payload: bytes) -> None:
        """Replace the file with ``payload``, or raise OSError and leave the
        file as it was."""
        if len(payload) > self.max_bytes:
            raise OSError(
                f"it takes {len(payload)} bytes, more than the file may "
                f"hold ({self.max_bytes})"
            )
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(
                dir=self.directory, prefix=self._tmp_prefix, suffix=_TMP_SUFFIX
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
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

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

    def remove_leftovers(self):
        """Temporary files of a save that a crash interrupted."""
        pattern = os.path.join(
            glob.escape(self.directory), self._tmp_prefix + "*" + _TMP_SUFFIX
        )
        for path in glob.glob(pattern)[:1000]:
            try:
                if stat.S_ISREG(os.lstat(path).st_mode):
                    os.unlink(path)
            except OSError:
                pass
