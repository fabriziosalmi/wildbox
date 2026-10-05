"""A scan of the file monitor does not stop the sensor, and is bounded (#745).

The monitor walked its paths and hashed every file under 10 MiB in the
event loop, at every scan. For as long as that took nothing else ran: no
batch was sent, no log was read, the local API did not answer. And what it
read was not bounded: a FIFO under a watched path was opened and waited on
for ever, a link to ``/dev/zero`` was read for ever.

Real directories, files, FIFOs and links; the scan runs in its real worker
thread.
"""

import asyncio
import hashlib
import logging
import os
import sys
import threading
import time
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import file_monitor  # noqa: E402
from sensor.collectors.file_monitor import FileMonitor  # noqa: E402
from sensor.core.config import DataLakeConfig, FIMConfig, SensorConfig  # noqa: E402

NOT_ROOT = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="root reads a directory whatever its mode",
)


def _monitor(*paths, queue=None, **fim):
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        fim=FIMConfig(enabled=True, paths=[str(path) for path in paths], **fim),
    )
    return FileMonitor(config, queue or asyncio.Queue())


def _events(monitor):
    events = []
    while not monitor.event_queue.empty():
        event = monitor.event_queue.get_nowait()
        events.append((event["type"], event["data"]["path"]))
    return sorted(events)


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


@pytest.fixture(autouse=True)
def no_background_scan(monkeypatch):
    """The tests scan by hand."""
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 3600)


@pytest.fixture
def slow_hash(monkeypatch):
    """Hashing takes its time, as it does on a large file or a slow disk."""
    real = hashlib.sha256

    class Slow:
        seconds = 0.05

        def __init__(self):
            self._hash = real()

        def update(self, data):
            time.sleep(self.seconds)
            self._hash.update(data)

        def hexdigest(self):
            return self._hash.hexdigest()

    monkeypatch.setattr(file_monitor.hashlib, "sha256", Slow)
    return Slow


@pytest.fixture
def etc(tmp_path):
    directory = tmp_path / "etc"
    directory.mkdir()
    return directory


@pytest.mark.asyncio
async def test_the_event_loop_runs_while_a_scan_hashes(etc, slow_hash):
    for index in range(12):
        (etc / f"file-{index}").write_text(str(index))
    monitor = _monitor(etc)
    ticks = 0

    async def everything_else():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    others = asyncio.ensure_future(everything_else())
    try:
        started = time.monotonic()
        await monitor.start()
        took = time.monotonic() - started
        during = ticks
    finally:
        others.cancel()
        await monitor.stop()

    assert monitor.get_status()["tracked_files"] == 12
    assert took >= 0.6
    # main: 0. The loop was inside the scan from its first file to its last.
    assert during >= 20


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO")
@pytest.mark.asyncio
async def test_what_is_not_a_regular_file_is_watched_and_never_read(etc, monkeypatch):
    (etc / "hosts").write_text("127.0.0.1 localhost\n")
    # main: opened for reading, which waits for a writer that never comes.
    os.mkfifo(etc / "pipe")
    # main: read to its end, which it does not have.
    os.symlink("/dev/zero", etc / "zero")
    monitor = _monitor(etc)
    opened = []
    real_open = os.open

    def recording(path, flags, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(file_monitor.os, "open", recording)

    await asyncio.wait_for(monitor.start(), timeout=20)
    try:
        states = dict(monitor.file_states)
        (etc / "hosts").write_text("127.0.0.1 localhost\n203.0.113.9 update\n")
        os.chmod(etc / "pipe", 0o600)
        changes = await asyncio.wait_for(monitor._scan_once(), timeout=20)
    finally:
        await monitor.stop()

    assert sorted(states) == [str(etc / name) for name in ("hosts", "pipe", "zero")]
    assert states[str(etc / "hosts")]["hash"]
    assert states[str(etc / "pipe")]["hash"] is None
    assert states[str(etc / "zero")]["hash"] is None
    # Not even opened: opening a device can be an act in itself.
    assert str(etc / "hosts") in opened
    assert str(etc / "pipe") not in opened
    assert str(etc / "zero") not in opened
    # Still watched, by what can be seen of them without reading.
    assert changes == 2
    assert _events(monitor) == [
        ("file_modified", str(etc / "hosts")),
        ("file_modified", str(etc / "pipe")),
    ]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO")
def test_a_file_replaced_by_a_fifo_since_it_was_looked_at_is_not_read(etc):
    # Between the look and the read anything can take a file's place: the
    # open does not wait for a writer, and what was opened is looked at
    # again before it is read.
    os.mkfifo(etc / "pipe")

    assert file_monitor.hash_file(str(etc / "pipe")) is None


def test_a_file_is_never_read_past_the_limit(etc, monkeypatch):
    monkeypatch.setattr(file_monitor, "MAX_HASHED_BYTES", 1000)
    under, at = etc / "under", etc / "at"
    under.write_bytes(b"x" * 999)
    at.write_bytes(b"x" * 1000)

    assert file_monitor.state_of(str(under))["hash"] == (
        hashlib.sha256(b"x" * 999).hexdigest()
    )
    assert file_monitor.state_of(str(at))["hash"] is None
    # It was under the limit when it was looked at, and has grown since:
    # the read stops at the limit, and half a hash is no hash.
    assert file_monitor.hash_file(str(at)) is None
    at.write_bytes(b"x" * 100000)
    assert file_monitor.hash_file(str(at)) is None


@pytest.mark.asyncio
async def test_a_path_that_begins_like_another_is_not_under_it(tmp_path):
    # main: "/host/etc-backup/x".startswith("/host/etc"), so at every scan
    # of the first path the second one's files were reported deleted, and at
    # every scan of the second, created.
    first, second = tmp_path / "etc", tmp_path / "etc-backup"
    for directory in (first, second):
        directory.mkdir()
        (directory / "hosts").write_text("127.0.0.1 localhost\n")
    monitor = _monitor(first, second)

    await monitor.start()
    try:
        quiet = await monitor._scan_once()
        os.unlink(first / "hosts")
        changes = await monitor._scan_once()
    finally:
        await monitor.stop()

    assert quiet == 0
    assert changes == 1
    assert _events(monitor) == [("file_deleted", str(first / "hosts"))]
    assert sorted(monitor.file_states) == [str(second / "hosts")]


@NOT_ROOT
@pytest.mark.asyncio
async def test_a_directory_that_cannot_be_listed_is_not_an_empty_one(etc):
    private = etc / "private"
    private.mkdir()
    (private / "key").write_text("secret\n")
    (etc / "hosts").write_text("127.0.0.1 localhost\n")
    monitor = _monitor(etc)

    await monitor.start()
    try:
        private.chmod(0o000)
        try:
            closed = await monitor._scan_once()
        finally:
            private.chmod(0o700)
        (private / "key").write_text("another secret\n")
        opened = await monitor._scan_once()
    finally:
        await monitor.stop()

    # main: file_deleted for the key, which is where it was.
    assert closed == 0
    assert opened == 1
    assert _events(monitor) == [("file_modified", str(private / "key"))]


@pytest.mark.asyncio
async def test_one_file_or_one_path_that_fails_does_not_end_the_scan(
    tmp_path, monkeypatch, caplog
):
    first, second = tmp_path / "etc", tmp_path / "opt"
    for directory in (first, second):
        directory.mkdir()
        (directory / "one").write_text("1")
        (directory / "two").write_text("2")
    monitor = _monitor(first, second)
    await monitor.start()
    real_state, real_listed = file_monitor.state_of, file_monitor._listed

    def state_of(path):
        if path == str(first / "one"):
            raise ValueError("embedded null byte")
        return real_state(path)

    def listed(root, *rest):
        if root == str(second):
            raise RuntimeError("the walk failed")
        return real_listed(root, *rest)

    monkeypatch.setattr(file_monitor, "state_of", state_of)
    monkeypatch.setattr(file_monitor, "_listed", listed)
    for directory in (first, second):
        (directory / "one").write_text("changed")
        (directory / "two").write_text("changed")
    with caplog.at_level(logging.ERROR, logger=file_monitor.__name__):
        failing = await monitor._scan_once()
    reported = _events(monitor)
    monkeypatch.undo()
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 3600)
    after = await monitor._scan_once()
    await monitor.stop()

    # What could be looked at is reported; what could not is neither
    # changed nor deleted, and is reported when it can be.
    assert failing == 1
    assert reported == [("file_modified", str(first / "two"))]
    assert f"Error scanning path {second}: the walk failed" in caplog.text
    assert after == 3
    assert _events(monitor) == [
        ("file_modified", str(first / "one")),
        ("file_modified", str(second / "one")),
        ("file_modified", str(second / "two")),
    ]


@pytest.mark.asyncio
async def test_a_path_that_appears_is_said_once(tmp_path, caplog):
    late = tmp_path / "host" / "etc"
    monitor = _monitor(late)
    await monitor.start()
    late.mkdir(parents=True)
    (late / "hosts").write_text("127.0.0.1 localhost\n")

    with caplog.at_level(logging.INFO, logger=file_monitor.__name__):
        for _ in range(3):
            assert await monitor._scan_once() == 0
    await monitor.stop()

    assert caplog.text.count(f"{late} exists now and is watched (1 files)") == 1
    assert monitor.missing_paths == set()


@pytest.mark.asyncio
async def test_no_more_than_max_files_are_watched_and_it_is_said(etc, caplog):
    for name in "abcde":
        (etc / name).write_text(name)
    monitor = _monitor(etc, max_files=3)

    with caplog.at_level(logging.INFO, logger=file_monitor.__name__):
        await monitor.start()
        try:
            first = monitor.get_status()
            await monitor._scan_once()
            (etc / "a").write_text("changed")
            changes = await monitor._scan_once()
            # Fewer files: all of them are watched again.
            os.unlink(etc / "d")
            os.unlink(etc / "e")
            await monitor._scan_once()
            last = monitor.get_status()
        finally:
            await monitor.stop()

    assert first["max_files"] == 3
    assert first["tracked_files"] == 3
    assert first["files_over_limit"] == 2
    # In the order of their names, so the same ones at every scan.
    assert sorted(monitor.file_states) == [str(etc / name) for name in "abc"]
    # Said once, not at every scan.
    assert _warnings(caplog) == [
        "File integrity monitoring: fim.paths hold more than fim.max_files "
        "(3) files: 2 are not watched. Raise fim.max_files, or watch less"
    ]
    assert changes == 1
    assert _events(monitor) == [("file_modified", str(etc / "a"))]
    assert last["files_over_limit"] == 0
    assert "every file under fim.paths is watched again" in caplog.text


@pytest.mark.asyncio
async def test_depth_and_exclusions_decide_what_is_watched(etc):
    deep = etc / "one" / "two" / "three"
    deep.mkdir(parents=True)
    (etc / "top").write_text("0")
    (etc / "one" / "first").write_text("1")
    (etc / "one" / "two" / "second").write_text("2")
    (deep / "third").write_text("3")
    (etc / "one" / "skipped.tmp").write_text("x")
    cache = etc / "cache.d"
    cache.mkdir()
    (cache / "inside").write_text("x")
    monitor = _monitor(etc, max_depth=2, exclude_patterns=["*.tmp", "cache.d"])

    await monitor.start()
    await monitor.stop()

    assert sorted(monitor.file_states) == sorted(
        str(path)
        for path in (
            etc / "top",
            etc / "one" / "first",
            etc / "one" / "two" / "second",
        )
    )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs links")
@pytest.mark.asyncio
async def test_links(etc, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target").write_text("one\n")
    (outside / "unseen").write_text("x")
    os.symlink(outside / "target", etc / "to-a-file")
    os.symlink(outside, etc / "to-a-directory")
    os.symlink(tmp_path / "nothing", etc / "to-nothing")
    monitor = _monitor(etc)

    await monitor.start()
    try:
        # A link to a file is watched as the file it points to; a link to a
        # directory is not gone into; a link to nothing is not a file.
        watched = sorted(monitor.file_states)
        (outside / "target").write_text("two\n")
        changed = await monitor._scan_once()
        os.unlink(outside / "target")
        gone = await monitor._scan_once()
    finally:
        await monitor.stop()

    assert watched == [str(etc / "to-a-file")]
    assert (changed, gone) == (1, 1)
    assert _events(monitor) == [
        ("file_deleted", str(etc / "to-a-file")),
        ("file_modified", str(etc / "to-a-file")),
    ]


@pytest.mark.asyncio
async def test_stopping_ends_the_scan_in_progress(etc, slow_hash):
    slow_hash.seconds = 0.2
    for index in range(100):
        (etc / f"file-{index:03}").write_text(str(index))
    monitor = _monitor(etc)
    threads = threading.active_count()

    starting = asyncio.ensure_future(monitor.start())
    await asyncio.sleep(0.5)
    began = time.monotonic()
    await monitor.stop()
    await asyncio.wait_for(starting, timeout=5)
    took = time.monotonic() - began

    # Twenty seconds of hashing were left.
    assert took < 3
    assert monitor.get_status()["running"] is False
    # The scan's thread has ended, or is idle in the pool: it hashes no more.
    hashed = len(monitor.file_states)
    await asyncio.sleep(0.5)
    assert len(monitor.file_states) == hashed
    assert threading.active_count() <= threads + 1
    # And no scan was started after the stop.
    assert monitor._tasks == []


@pytest.mark.asyncio
async def test_stopping_ends_a_monitor_that_waits_for_the_queue(etc, monkeypatch):
    # With a full queue the monitor waits to hand over a change, as every
    # collector does; stop does not wait with it, and leaves no task behind.
    for name in "abc":
        (etc / name).write_text(name)
    monitor = _monitor(etc, queue=asyncio.Queue(maxsize=1))
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 0.01)
    before = len(asyncio.all_tasks())

    await monitor.start()
    for name in "abc":
        (etc / name).write_text("changed")
    deadline = time.monotonic() + 10
    while not monitor.event_queue.full():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.1)

    await asyncio.wait_for(monitor.stop(), timeout=5)
    await asyncio.sleep(0.05)

    # main: the loop was a task nobody kept, left waiting on the queue.
    assert len(asyncio.all_tasks()) == before
    assert monitor.event_queue.qsize() == 1


@pytest.mark.asyncio
async def test_the_monitor_scans_again_an_interval_after_it_started(etc, monkeypatch):
    (etc / "hosts").write_text("one\n")
    monitor = _monitor(etc)
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 0.05)

    await monitor.start()
    try:
        # The scan of start() was the first: none follows it at once.
        assert monitor.scan_count == 0
        (etc / "hosts").write_text("two\n")
        deadline = time.monotonic() + 10
        while monitor.event_queue.empty():
            assert time.monotonic() < deadline, "timed out"
            await asyncio.sleep(0.01)
    finally:
        await monitor.stop()
    scans = monitor.scan_count
    await asyncio.sleep(0.2)

    assert _events(monitor) == [("file_modified", str(etc / "hosts"))]
    assert scans >= 1
    assert monitor.scan_count == scans


@pytest.mark.parametrize(
    "setting, value",
    [
        ("exclude_patterns", "*.tmp"),
        ("exclude_patterns", ["*.tmp", 5]),
        ("exclude_patterns", None),
        ("max_depth", "10"),
        ("max_depth", -1),
        ("max_depth", True),
        ("max_depth", 2.5),
        ("max_files", 0),
        ("max_files", "many"),
        ("max_files", 1000001),
        ("max_files", None),
    ],
)
def test_fim_settings_that_decide_what_is_watched_are_validated(setting, value):
    config = _monitor("/etc").config
    assert config.validate() == []
    setattr(config.fim, setting, value)

    (error,) = config.validate()

    # A string of patterns would be read one character at a time, and its
    # "*" would exclude every file.
    assert error.startswith(f"fim.{setting} must be ")


def test_max_files_is_read_from_the_configuration(tmp_path):
    from sensor.core.config import load_config

    path = tmp_path / "config.yaml"
    path.write_text(
        "data_lake:\n  endpoint: https://gateway.example\n"
        "fim:\n  paths: [/etc]\n  max_files: 1234\n"
    )

    assert load_config(str(path)).fim.max_files == 1234
    path.write_text("data_lake:\n  endpoint: https://gateway.example\n")
    assert load_config(str(path)).fim.max_files == 50000
