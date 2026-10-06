"""The journal and the unified log are read from a command that follows them (#725).

The readers used ``readline()`` on the command's output: at the first entry
longer than 64 KiB it raised, the reader logged an error and ended, and the
source was silent for good. Nothing read the command's standard error, and a
command that ended was never started again.

The command is played by a real child process, a Python script written for
each test: pipes, long lines, a blocked standard error and exits are the real
thing. ``journalctl`` and ``log`` themselves are not run here; what was
checked against them by hand is in the pull request.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import textwrap
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import log_forwarder  # noqa: E402
from sensor.collectors.log_forwarder import (  # noqa: E402
    MAX_ENTRY_BYTES,
    MAX_LINE_BYTES,
    READ_CHUNK,
    LogForwarder,
)
from sensor.collectors.position_store import STATE_FILE, PositionStore  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    LogSourceConfig,
    SensorConfig,
)
from sensor.pipeline.delivery import DELIVERY_KEY, take_delivery  # noqa: E402

JOURNAL = LogSourceConfig(name="journal", type="journald", format="json")
UNIFIED = LogSourceConfig(name="unified", type="unified_log", format="json")


@pytest.fixture(autouse=True)
def every_platform(monkeypatch):
    """The platform check is not what is tested: the command is a stand-in."""
    for name in ("linux", "macos"):
        monkeypatch.setattr(log_forwarder, f"is_{name}", lambda: True)


def _forwarder(source, data_dir=None, queue_size=0):
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        collection=CollectionConfig(log_forwarding=True),
        log_sources=[source],
        data_dir=str(data_dir) if data_dir else None,
    )
    return LogForwarder(config, asyncio.Queue(maxsize=queue_size))


def _script(tmp_path, body, name="command.py"):
    """A command: a Python script that plays journalctl or log."""
    path = tmp_path / name
    path.write_text(
        "import json, os, sys, time\n"
        "def entry(message, cursor=None, **fields):\n"
        "    record = {'__CURSOR': cursor} if cursor else {}\n"
        "    record.update(MESSAGE=message, **fields)\n"
        "    sys.stdout.write(json.dumps(record) + '\\n')\n"
        "    sys.stdout.flush()\n" + textwrap.dedent(body)
    )
    return [sys.executable, str(path)]


def _plays(forwarder, argv, source=JOURNAL, seen=None):
    """Make the forwarder run ``argv`` for its command; the arguments it
    would have given the real one are appended, and recorded in ``seen``."""
    name = "_journal_command" if source.type == "journald" else "_unified_log_command"
    real = getattr(forwarder, name)

    def command(*args):
        arguments = real(*args)[1:]
        if seen is not None:
            seen.append(arguments)
        return argv + arguments

    setattr(forwarder, name, command)


async def _event(forwarder, timeout=10):
    event = await asyncio.wait_for(forwarder.event_queue.get(), timeout=timeout)
    return event, take_delivery(event)


async def _messages(forwarder, count):
    return [(await _event(forwarder))[0]["data"].get("MESSAGE") for _ in range(count)]


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


def _status(forwarder):
    (status,) = forwarder.get_status()["log_sources"]
    return status


# -- long entries -----------------------------------------------------------


@pytest.mark.asyncio
async def test_an_entry_longer_than_64_kib_does_not_end_the_reader(tmp_path, caplog):
    argv = _script(
        tmp_path,
        """
        entry("one", "s=1")
        entry("A" * 100_000, "s=2")          # over asyncio's 64 KiB line limit
        entry("B" * (2 * %d), "s=3")         # over what an entry may be
        entry("four", "s=4")
        time.sleep(60)
        """ % MAX_ENTRY_BYTES,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await forwarder.start()
    try:
        received = [await _event(forwarder) for _ in range(4)]
        events = [event for event, _ in received]
        status = _status(forwarder)
    finally:
        await forwarder.stop()

    # No data directory here: the cursor is not kept, the sensor says so,
    # and an entry unsent at a stop is one that will not be read again.
    assert "data_dir is not set" in caplog.text
    assert [delivery.replayable for _, delivery in received] == [False] * 4
    one, whole, cut, four = events
    assert one["data"]["MESSAGE"] == "one" and one["type"] == "log.journal"
    # Whole: main's reader ended here, and "four" never came.
    assert whole["data"]["MESSAGE"] == "A" * 100_000
    assert "truncated" not in whole["metadata"]
    # Cut: the text it begins with, not half an object passed off as one.
    assert cut["metadata"] == {
        "log_source": "journal",
        "format": "json",
        "truncated": True,
    }
    assert set(cut["data"]) == {"raw_message"}
    assert cut["data"]["raw_message"].startswith('{"__CURSOR": "s=3", "MESSAGE": "BBB')
    assert len(cut["data"]["raw_message"]) == MAX_LINE_BYTES
    assert four["data"]["MESSAGE"] == "four"
    assert status["state"] == "running"
    assert (status["entries_forwarded"], status["entries_truncated"]) == (4, 1)
    assert status["restarts"] == 0


@pytest.mark.asyncio
async def test_an_entry_with_no_end_is_not_held_in_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(log_forwarder, "MAX_ENTRY_BYTES", 10_000)
    argv = _script(
        tmp_path,
        """
        for _ in range(200):                 # 13 MB, and no newline yet
            sys.stdout.write("C" * 65536)
            sys.stdout.flush()
        sys.stdout.write("\\n")
        entry("after")
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)
    handled = []
    real = forwarder._journal_entry

    async def watched(runtime, raw, cut):
        handled.append((len(raw), cut))
        await real(runtime, raw, cut)

    forwarder._journal_entry = watched

    await forwarder.start()
    try:
        (cut, _), (after, _) = await _event(forwarder), await _event(forwarder)
    finally:
        await forwarder.stop()

    # One event for the 13 MB, made from what one read may add to the bound.
    assert handled == [(handled[0][0], True), (len(b'{"MESSAGE": "after"}'), False)]
    assert 10_000 < handled[0][0] <= 10_000 + READ_CHUNK
    assert set(cut["data"]["raw_message"]) == {"C"}
    assert 10_000 < len(cut["data"]["raw_message"]) <= MAX_LINE_BYTES
    assert cut["metadata"]["truncated"] is True
    assert after["data"]["MESSAGE"] == "after"


@pytest.mark.asyncio
async def test_an_entry_over_the_bound_that_arrives_in_one_read_is_cut_too(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(log_forwarder, "MAX_ENTRY_BYTES", 10_000)
    argv = _script(
        tmp_path,
        """
        entry("D" * 12_000, "s=1")           # one write, newline included
        entry("after", "s=2")
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)

    await forwarder.start()
    try:
        (cut, _), (after, _) = await _event(forwarder), await _event(forwarder)
    finally:
        await forwarder.stop()

    assert cut["metadata"].get("truncated") is True
    assert set(cut["data"]) == {"raw_message"}
    assert after["data"]["MESSAGE"] == "after"


@pytest.mark.asyncio
async def test_a_cut_entry_still_moves_the_cursor(tmp_path, monkeypatch):
    # The entry is not parsed, but its cursor is in what is kept of it:
    # without it the next start of journalctl would read the entry again.
    argv = _script(
        tmp_path,
        """
        if "--lines=0" in sys.argv:
            entry("E" * (2 * %d), "s=9;i=77")
            sys.exit(1)
        entry("after")
        time.sleep(60)
        """ % MAX_ENTRY_BYTES,
    )
    forwarder = _forwarder(JOURNAL)
    arguments = []
    _plays(forwarder, argv, seen=arguments)

    async def no_wait(seconds):
        pass

    monkeypatch.setattr(forwarder, "_restart_pause", no_wait)
    await forwarder.start()
    try:
        (cut, _), (after, _) = await _event(forwarder), await _event(forwarder)
    finally:
        await forwarder.stop()

    assert cut["metadata"]["truncated"] is True
    assert after["data"]["MESSAGE"] == "after"
    assert [argument[-1] for argument in arguments] == [
        "--lines=0",
        "--after-cursor=s=9;i=77",
    ]


@pytest.mark.asyncio
async def test_a_line_that_is_not_an_entry_is_counted_and_passed_over(tmp_path):
    argv = _script(
        tmp_path,
        """
        entry("one")
        print("-- No entries --")
        print("[" * 100_000)                 # nests deeper than a parser goes
        print("[1, 2]")
        entry("two")
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)

    await forwarder.start()
    try:
        assert await _messages(forwarder, 2) == ["one", "two"]
        status = _status(forwarder)
    finally:
        await forwarder.stop()

    assert status["entries_unparsed"] == 3
    assert status["restarts"] == 0


@pytest.mark.asyncio
async def test_an_error_while_reading_starts_the_command_again(
    tmp_path, monkeypatch, caplog
):
    argv = _script(
        tmp_path,
        """
        if "--lines=0" in sys.argv:
            entry("one", "s=1")
            entry("the reader fails on this one", "s=2")
        entry("three", "s=3")
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    arguments = []
    _plays(forwarder, argv, seen=arguments)
    real = forwarder._journal_entry
    failed = []

    async def fails_once(runtime, raw, cut):
        if b"fails on this one" in raw and not failed:
            failed.append(raw)
            raise OSError("a pipe broke")
        await real(runtime, raw, cut)

    async def no_wait(seconds):
        pass

    forwarder._journal_entry = fails_once
    monkeypatch.setattr(forwarder, "_restart_pause", no_wait)
    with caplog.at_level(logging.ERROR, logger=log_forwarder.__name__):
        await forwarder.start()
        try:
            messages = await _messages(forwarder, 2)
        finally:
            await forwarder.stop()

    # Not the end of the source: started again after the last entry read.
    assert messages == ["one", "three"]
    assert [argument[-1] for argument in arguments] == [
        "--lines=0",
        "--after-cursor=s=1",
    ]
    assert "error reading" in caplog.text and "a pipe broke" in caplog.text


# -- standard error ---------------------------------------------------------


@pytest.mark.asyncio
async def test_what_the_command_writes_to_standard_error_is_read(tmp_path):
    # More than a pipe holds: unread, the command blocks on it before it
    # prints a single entry, which is what main's reader made of it.
    argv = _script(
        tmp_path,
        """
        for _ in range(300):
            sys.stderr.write("x" * 8191 + "\\n")
        sys.stderr.write("Hint: You are not seeing messages from other users\\n")
        sys.stderr.flush()
        entry("after two megabytes of standard error")
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)

    await forwarder.start()
    try:
        event, _ = await _event(forwarder)
        await _until(lambda: "other users" in (_status(forwarder)["last_error"] or ""))
        kept = _status(forwarder)["last_error"]
    finally:
        await forwarder.stop()

    assert event["data"]["MESSAGE"] == "after two megabytes of standard error"
    # The last of it, bounded.
    assert kept.endswith("Hint: You are not seeing messages from other users")
    assert len(kept) <= log_forwarder.STDERR_KEPT


# -- a command that ends ----------------------------------------------------

ENDS_FOUR_TIMES = """
count = os.path.join(os.path.dirname(__file__), "starts")
starts = int(open(count).read()) + 1 if os.path.exists(count) else 1
open(count, "w").write(str(starts))
entry("from start %d" % starts, "s=%d" % starts)
if starts <= 4:
    sys.stderr.write("journal file rotated, giving up\\n")
    sys.exit(3)
time.sleep(60)
"""


async def _restarts(tmp_path, monkeypatch, caplog=None):
    """Run ENDS_FOUR_TIMES; the pauses asked for, the arguments of each
    start, the forwarder's status at the end and the messages forwarded."""
    forwarder = _forwarder(JOURNAL)
    arguments, pauses = [], []
    _plays(forwarder, _script(tmp_path, ENDS_FOUR_TIMES), seen=arguments)

    async def no_wait(seconds):
        pauses.append(seconds)

    monkeypatch.setattr(forwarder, "_restart_pause", no_wait)
    await forwarder.start()
    try:
        messages = await _messages(forwarder, 5)
        await _until(lambda: _status(forwarder)["state"] == "running")
        status = _status(forwarder)
    finally:
        await forwarder.stop()
    return pauses, arguments, status, messages


@pytest.mark.asyncio
async def test_a_command_that_ends_is_started_again_with_a_growing_delay(
    tmp_path, monkeypatch, caplog
):
    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        pauses, arguments, status, messages = await _restarts(tmp_path, monkeypatch)

    assert messages == [f"from start {start}" for start in range(1, 6)]
    assert pauses == [1, 2, 4, 8]
    assert status["restarts"] == 4
    assert status["last_exit"] == 3
    assert status["last_error"] == "journal file rotated, giving up"
    assert (
        "Log source 'journal': journalctl ended (exit status 3, it said: journal "
        "file rotated, giving up); it is started again in 1 seconds"
    ).replace("journalctl", sys.executable) in caplog.text
    # Each start goes on after the last entry read: none skipped, none twice.
    assert arguments == [
        ["--follow", "--output=json", "--no-pager", "--lines=0"],
        ["--follow", "--output=json", "--no-pager", "--after-cursor=s=1"],
        ["--follow", "--output=json", "--no-pager", "--after-cursor=s=2"],
        ["--follow", "--output=json", "--no-pager", "--after-cursor=s=3"],
        ["--follow", "--output=json", "--no-pager", "--after-cursor=s=4"],
    ]


@pytest.mark.asyncio
async def test_a_command_that_closes_its_output_is_left_to_end_by_itself(
    tmp_path, monkeypatch
):
    # It is about to exit: its status is what it exits with, not that of a
    # signal sent to hurry it.
    argv = _script(
        tmp_path,
        """
        if "--lines=0" in sys.argv:
            entry("one", "s=1")
            os.close(1)
            time.sleep(0.3)
            os._exit(7)
        entry("two", "s=2")
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)

    async def no_wait(seconds):
        pass

    monkeypatch.setattr(forwarder, "_restart_pause", no_wait)
    await forwarder.start()
    try:
        assert await _messages(forwarder, 2) == ["one", "two"]
        status = _status(forwarder)
    finally:
        await forwarder.stop()

    assert status["last_exit"] == 7
    assert status["restarts"] == 1


@pytest.mark.asyncio
async def test_the_delay_has_an_upper_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(log_forwarder, "CHILD_RESTART_MAX", 3.0)

    pauses, _, _, _ = await _restarts(tmp_path, monkeypatch)

    assert pauses == [1, 2, 3, 3]


@pytest.mark.asyncio
async def test_the_delay_starts_over_after_a_run_that_lasted(tmp_path, monkeypatch):
    monkeypatch.setattr(log_forwarder, "CHILD_STABLE_SECONDS", 0.0)

    pauses, _, _, _ = await _restarts(tmp_path, monkeypatch)

    assert pauses == [1, 1, 1, 1]


@pytest.mark.asyncio
async def test_a_command_that_is_not_installed_is_said_once_and_not_retried(
    tmp_path, caplog
):
    forwarder = _forwarder(JOURNAL)
    forwarder._journal_command = lambda runtime: [str(tmp_path / "no-journalctl")]

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await forwarder.start()
        (task,) = forwarder._tasks
        await asyncio.wait_for(asyncio.shield(task), timeout=5)
        status = _status(forwarder)
        await forwarder.stop()

    assert status["state"] == "unavailable"
    assert status["last_error"] == f"{tmp_path / 'no-journalctl'} is not installed"
    assert status["restarts"] == 0
    assert [r.getMessage() for r in caplog.records if "is not read" in r.message] == [
        f"Log source 'journal' (journald) is not read: {tmp_path / 'no-journalctl'} "
        f"is not installed here"
    ]
    # Unavailable stays unavailable after the stop.
    assert _status(forwarder)["state"] == "unavailable"


@pytest.mark.asyncio
async def test_stopping_ends_the_command(tmp_path):
    argv = _script(
        tmp_path,
        """
        entry("running", pid=os.getpid())
        time.sleep(600)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)

    await forwarder.start()
    event, _ = await _event(forwarder)
    pid = event["data"]["pid"]
    os.kill(pid, 0)  # alive
    await asyncio.wait_for(forwarder.stop(), timeout=10)

    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert _status(forwarder)["state"] == "stopped"


@pytest.mark.asyncio
async def test_a_command_that_ignores_the_request_to_end_is_killed(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(log_forwarder, "CHILD_TERM_SECONDS", 0.3)
    argv = _script(
        tmp_path,
        """
        import signal
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        entry("running", pid=os.getpid())
        time.sleep(600)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)

    await forwarder.start()
    event, _ = await _event(forwarder)
    await asyncio.wait_for(forwarder.stop(), timeout=10)

    # Not there, and not a zombie either, which this would still find: it
    # was waited for.
    with pytest.raises(ProcessLookupError):
        os.kill(event["data"]["pid"], 0)
    assert _status(forwarder)["last_exit"] is None  # stopped, not restarted


@pytest.mark.asyncio
async def test_such_a_command_is_killed_and_waited_for_with_its_output_unread(
    tmp_path, monkeypatch, caplog
):
    # The queue is full, so the reader has stopped reading and the command
    # is writing to a pipe nobody empties; it ignores the request to end.
    # main killed it after its 5 seconds and then waited, without a limit,
    # for an exit asyncio (3.11) does not report while output is unread:
    # the forwarder's stop ended when the agent stopped waiting for it.
    monkeypatch.setattr(log_forwarder, "CHILD_TERM_SECONDS", 0.3)
    full = tmp_path / "the-pipe-is-full"
    argv = _script(
        tmp_path,
        """
        import fcntl, signal
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        entry("running", pid=os.getpid())
        entry("held")
        # Until the pipe takes no more and stays full, which is when nobody
        # reads it: a reader that is only slower empties it in no time.
        fcntl.fcntl(1, fcntl.F_SETFL, fcntl.fcntl(1, fcntl.F_GETFL) | os.O_NONBLOCK)
        more = (json.dumps({"MESSAGE": "more", "pad": "p" * 4000}) + "\\n").encode()
        refused = 0
        while refused < 50:
            try:
                os.write(1, more)
                refused = 0
            except BlockingIOError:
                refused += 1
                time.sleep(0.01)
        open(%r, "w").close()
        time.sleep(600)
        """
        % str(full),
    )
    forwarder = _forwarder(JOURNAL, queue_size=1)
    _plays(forwarder, argv)

    await forwarder.start()
    event, _ = await _event(forwarder)
    pid = event["data"]["pid"]
    await _until(full.exists)
    assert forwarder.event_queue.full()

    with caplog.at_level(logging.ERROR, logger=log_forwarder.__name__):
        await asyncio.wait_for(forwarder.stop(), timeout=30)

    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    # Gone when it was killed, its output read to the end: not given up
    # after the time a killed command has, with its pipes closed on it.
    assert [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR] == []


@pytest.mark.asyncio
async def test_a_stop_while_the_command_is_ending_by_itself_does_not_leave_it(
    tmp_path, monkeypatch
):
    # The command has closed its output, which is how one that is ending
    # looks, and the forwarder is giving it the time to exit by itself:
    # longer than this test, here. The stop comes then. main went away
    # from that wait and left the command running, neither asked to end
    # nor killed.
    monkeypatch.setattr(log_forwarder, "CHILD_TERM_SECONDS", 600)
    argv = _script(
        tmp_path,
        """
        import signal
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        entry("running", pid=os.getpid())
        os.close(1)
        time.sleep(600)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)
    ending = asyncio.Event()
    end = forwarder._end_command
    commands = []

    async def watched(process, errors, what, ending_by_itself=False):
        commands.append(process)
        if ending_by_itself:
            ending.set()
        await end(process, errors, what, ending_by_itself)

    forwarder._end_command = (
        lambda process, errors, what, ending=False: watched(
            process, errors, what, ending
        )
    )

    await forwarder.start()
    event, _ = await _event(forwarder)
    pid = event["data"]["pid"]
    await asyncio.wait_for(ending.wait(), timeout=10)
    for _ in range(10):
        await asyncio.sleep(0)
    os.kill(pid, 0)  # there, and waited for
    await asyncio.wait_for(forwarder.stop(), timeout=30)

    # Killed, and waited for before the stop returned: its exit is known,
    # and no process is left, not even one nobody has waited for.
    (command,) = commands
    assert command.returncode == -signal.SIGKILL
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert _status(forwarder)["state"] == "stopped"


# -- what a stopped reader holds ----------------------------------------------


@pytest.mark.asyncio
async def test_a_reader_stopped_in_the_middle_of_a_read_says_which_lines_it_held():
    forwarder = _forwarder(JOURNAL)
    stream = asyncio.StreamReader()
    stream.feed_data(b"one\ntwo\nthree\n\nfour\nand the beginning of fi")
    handled, left = [], []
    held = asyncio.Event()

    async def handle(line, cut):
        handled.append(line)
        if line == b"two":
            held.set()
            await asyncio.Event().wait()  # as put() on a full queue

    reading = asyncio.ensure_future(forwarder._read_entries(stream, handle, left.append))
    await asyncio.wait_for(held.wait(), timeout=5)
    reading.cancel()
    await asyncio.gather(reading, return_exceptions=True)

    assert handled == [b"one", b"two"]
    # The lines after the one being handled, as they were read. Not the
    # beginning of a line: an entry is one when its newline is written.
    assert left == [[b"three", b"", b"four"]]


@pytest.mark.asyncio
async def test_a_reader_stopped_between_two_reads_holds_no_line():
    forwarder = _forwarder(JOURNAL)
    stream = asyncio.StreamReader()
    stream.feed_data(b"one\ntwo\n")
    handled, left = [], []

    async def handle(line, cut):
        handled.append(line)

    reading = asyncio.ensure_future(forwarder._read_entries(stream, handle, left.append))
    await _until(lambda: len(handled) == 2)
    reading.cancel()
    await asyncio.gather(reading, return_exceptions=True)

    assert left == []


@pytest.mark.parametrize(
    "source, with_data_dir, read_again",
    [
        (JOURNAL, True, True),
        # Nothing keeps the cursor.
        (JOURNAL, False, False),
        # log stream cannot be asked for an entry again.
        (UNIFIED, True, False),
        (UNIFIED, False, False),
    ],
)
def test_the_lines_a_reader_held_are_counted_when_they_are_entries(
    tmp_path, source, with_data_dir, read_again
):
    forwarder = _forwarder(source, tmp_path if with_data_dir else None)
    runtime = forwarder._system_source(source)
    long = b'{"MESSAGE": "' + b"A" * MAX_ENTRY_BYTES + b'"}'

    forwarder._not_handled(
        runtime,
        [
            b'{"MESSAGE": "one"}',
            b"",
            b"   ",
            b"not an entry",
            b"[1, 2]",
            b'"a string"',
            long,  # forwarded cut: an event all the same
            b'{"MESSAGE": "two"}',
        ],
    )

    assert len(forwarder.interrupted) == 3
    assert [
        delivery is not None and delivery.replayable
        for delivery in forwarder.interrupted
    ] == [read_again] * 3
    # Never settled: they are no events, and settling moves a cursor.
    for delivery in forwarder.interrupted:
        if delivery is not None:
            delivery.settle()
    assert runtime.accepted_cursor is None and not forwarder._positions_dirty


@pytest.mark.parametrize(
    "line, cut, expected",
    [
        (b'{"MESSAGE": "one"}', False, ({"MESSAGE": "one"}, None)),
        (b'  {"MESSAGE": "one"}\r', False, ({"MESSAGE": "one"}, None)),
        (b"", False, (None, "blank")),
        (b" \t ", False, (None, "blank")),
        (b"Filtering the log data using ...", False, (None, "unparsed")),
        (b"[1, 2]", False, (None, "unparsed")),
        (b"null", False, (None, "unparsed")),
        (b'{"MESSAGE": "cut he', True, ({"raw_message": '{"MESSAGE": "cut he'}, None)),
    ],
)
def test_what_a_line_of_a_commands_output_is(line, cut, expected):
    assert LogForwarder._entry_data(line, cut) == expected


@pytest.mark.asyncio
async def test_a_full_queue_makes_the_reader_wait_and_loses_no_entry(tmp_path):
    argv = _script(
        tmp_path,
        """
        for index in range(3000):
            entry("entry %d" % index, "s=%d" % index, pad="p" * 500)
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL, queue_size=5)
    _plays(forwarder, argv)

    await forwarder.start()
    try:
        await _until(forwarder.event_queue.full)
        for _ in range(50):
            await asyncio.sleep(0)
        # Nobody takes events: what was read is the queue and one read more.
        assert _status(forwarder)["entries_forwarded"] <= 5 + READ_CHUNK // 500
        messages = await _messages(forwarder, 3000)
    finally:
        await forwarder.stop()

    assert messages == [f"entry {index}" for index in range(3000)]


# -- the journal's cursor ---------------------------------------------------

THREE_ENTRIES = """
entry("one", "s=a1;i=1")
entry("two", "s=a1;i=2")
entry("three", "s=a1;i=3")
time.sleep(60)
"""


@pytest.mark.asyncio
async def test_the_cursor_saved_is_the_last_entry_accepted_and_a_restart_uses_it(
    tmp_path,
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    forwarder = _forwarder(JOURNAL, data_dir)
    _plays(forwarder, _script(tmp_path, THREE_ENTRIES))

    await forwarder.start()
    try:
        (_, one), (_, two), (_, three) = [await _event(forwarder) for _ in range(3)]
        assert one.replayable is True
        two.settle()  # accepted before "one": the cursor does not move
        assert _status(forwarder)["accepted_cursor"] is None
        one.settle()
        assert _status(forwarder)["accepted_cursor"] == "s=a1;i=2"
    finally:
        await forwarder.stop()  # "three" is still in the sensor

    saved = json.loads((data_dir / STATE_FILE).read_text())["sources"]
    assert saved == {"journal": {"type": "journald", "cursor": "s=a1;i=2"}}

    # The sensor starts again: after the last entry accepted, so "three",
    # read and never delivered, is read again.
    again = _forwarder(JOURNAL, data_dir)
    runtime = again._system_source(JOURNAL)
    assert again._journal_command(runtime) == [
        "journalctl",
        "--follow",
        "--output=json",
        "--no-pager",
        "--after-cursor=s=a1;i=2",
    ]
    # And it is kept if this run reads nothing.
    again._system_sources["journal"] = runtime
    again._positions_dirty = True
    again.save_positions()
    assert json.loads((data_dir / STATE_FILE).read_text())["sources"] == saved


@pytest.mark.asyncio
async def test_the_first_start_follows_the_journal_from_now_on(tmp_path):
    forwarder = _forwarder(JOURNAL)

    # Not journalctl's default, the last ten entries, sent at every start.
    assert forwarder._journal_command(forwarder._system_source(JOURNAL)) == [
        "journalctl",
        "--follow",
        "--output=json",
        "--no-pager",
        "--lines=0",
    ]


@pytest.mark.asyncio
async def test_a_cursor_that_could_be_an_option_is_not_kept(tmp_path):
    argv = _script(
        tmp_path,
        """
        entry("one", "--file=/etc/shadow")
        entry("two", "s=1 --all")
        entry("three")
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL)
    _plays(forwarder, argv)

    await forwarder.start()
    try:
        assert await _messages(forwarder, 3) == ["one", "two", "three"]
        runtime = forwarder._system_sources["journal"]
        assert runtime.read_cursor is None
        assert forwarder._journal_command(runtime)[-1] == "--lines=0"
    finally:
        await forwarder.stop()


@pytest.mark.asyncio
async def test_a_saved_cursor_journalctl_refuses_is_given_up_after_three_starts(
    tmp_path, monkeypatch, caplog
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    PositionStore(str(data_dir)).save(
        {"journal": {"type": "journald", "cursor": "s=gone;i=9"}}
    )
    argv = _script(
        tmp_path,
        """
        if any(argument.startswith("--after-cursor") for argument in sys.argv):
            sys.stderr.write("Failed to seek to cursor: Invalid argument\\n")
            sys.exit(1)
        entry("followed from now on", "s=new;i=1")
        time.sleep(60)
        """,
    )
    forwarder = _forwarder(JOURNAL, data_dir)
    arguments = []
    _plays(forwarder, argv, seen=arguments)

    async def no_wait(seconds):
        pass

    monkeypatch.setattr(forwarder, "_restart_pause", no_wait)
    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await forwarder.start()
        try:
            assert await _messages(forwarder, 1) == ["followed from now on"]
        finally:
            await forwarder.stop()

    assert [argument[-1] for argument in arguments] == [
        "--after-cursor=s=gone;i=9",
        "--after-cursor=s=gone;i=9",
        "--after-cursor=s=gone;i=9",
        "--lines=0",
    ]
    assert "the cursor is given up" in caplog.text
    assert "Entries logged in between are not read" in caplog.text


# -- the unified log --------------------------------------------------------


@pytest.mark.asyncio
async def test_the_unified_log_is_read_one_object_per_line(tmp_path):
    argv = _script(
        tmp_path,
        """
        print("Filtering the log data using \\"\\"")
        sys.stdout.write(json.dumps({"eventMessage": "one", "processID": 1}) + "\\n")
        sys.stdout.write(json.dumps({"eventMessage": "L" * (2 * %d)}) + "\\n")
        sys.stdout.write(json.dumps({"eventMessage": "three"}) + "\\n")
        sys.stdout.flush()
        time.sleep(60)
        """ % MAX_ENTRY_BYTES,
    )
    forwarder = _forwarder(UNIFIED)
    arguments = []
    _plays(forwarder, argv, source=UNIFIED, seen=arguments)

    await forwarder.start()
    try:
        events = [await _event(forwarder) for _ in range(3)]
        status = _status(forwarder)
    finally:
        await forwarder.stop()

    (one, handle), (cut, _), (three, _) = events
    # --style json prints one array over many lines, of which none is an
    # entry: main's reader forwarded nothing at all.
    assert arguments == [["stream", "--style", "ndjson"]]
    assert LogForwarder._unified_log_command()[0] == "log"
    # The source's name, as the README says of every source.
    assert one["type"] == "log.unified"
    assert one["data"] == {"eventMessage": "one", "processID": 1}
    assert one["metadata"] == {"log_source": "unified", "format": "json"}
    assert cut["metadata"]["truncated"] is True
    assert three["data"]["eventMessage"] == "three"
    # log stream cannot be asked for an entry again: nothing to settle.
    assert handle is None and DELIVERY_KEY not in one
    assert status["state"] == "running"
    assert status["entries_forwarded"] == 3
    assert status["entries_unparsed"] == 1  # the line it begins with
    assert "accepted_cursor" not in status


# -- the status -------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_source_this_platform_does_not_have_is_reported_as_skipped(
    monkeypatch,
):
    monkeypatch.setattr(log_forwarder, "is_linux", lambda: False)
    forwarder = _forwarder(JOURNAL)

    await forwarder.start()
    status = _status(forwarder)
    await forwarder.stop()

    assert status == {
        "name": "journal",
        "type": "journald",
        "enabled": True,
        "state": "skipped",
        "restarts": 0,
        "last_exit": None,
        "last_error": "the systemd journal is read on Linux only",
        "entries_forwarded": 0,
        "entries_truncated": 0,
        "entries_unparsed": 0,
        "accepted_cursor": None,
    }
    assert _status(forwarder)["state"] == "skipped"
