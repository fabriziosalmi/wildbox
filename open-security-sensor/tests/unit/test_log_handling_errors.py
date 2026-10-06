"""An error in the handling of one line is that line's, not its chunk's (#788).

A source is read a chunk at a time: 64 KiB of a file or of a command's
output, an answer of a Windows event log. When the handling of one line
raised, the error left the loop over the chunk:

* a command (``journalctl``, ``log stream``) was ended and started again, and
  the entries after that one in the same read were passed over, for good for
  the unified log, which cannot be asked for an entry again;
* a file's position was already beyond the chunk, so the lines after that
  one were never forwarded;
* the reader of a Windows event log ended, and that log was silent until the
  sensor was started again.

The error is raised here by the queue, for one event out of ten that the
reader gets at once: after the line has its place in the order of its source
(``pending``), which is where an error must not leave it. Nothing is timed.
"""

import asyncio
import json
import logging
import sys
import textwrap
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import log_forwarder  # noqa: E402
from sensor.collectors.log_forwarder import LogForwarder  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    LogSourceConfig,
    SensorConfig,
)
from sensor.pipeline.delivery import take_delivery  # noqa: E402

READ_AT_ONCE = 10
AT_FAULT = 4
THE_OTHERS = [index for index in range(READ_AT_ONCE) if index != AT_FAULT]
# What the error says: never in the log, it may hold what the line does.
ERROR_TEXT = "the text of the error, which names line 4"


class Refusing(asyncio.Queue):
    """A queue whose ``put()`` raises for the events ``refused`` picks."""

    def __init__(self, refused):
        super().__init__()
        self.refused = refused
        self.raised = 0

    async def put(self, event):
        if self.refused(event):
            self.raised += 1
            raise RuntimeError(ERROR_TEXT)
        await super().put(event)


def _forwarder(source, refused, data_dir=None):
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        collection=CollectionConfig(log_forwarding=True),
        log_sources=[source],
        data_dir=str(data_dir) if data_dir else None,
    )
    return LogForwarder(config, Refusing(refused))


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


async def _events(forwarder, count):
    """The next ``count`` events, and that no more comes."""
    received = []
    for _ in range(count):
        event = await asyncio.wait_for(forwarder.event_queue.get(), timeout=10)
        received.append((event, take_delivery(event)))
    for _ in range(20):
        await asyncio.sleep(0.005)
    assert forwarder.event_queue.empty()
    return received


def _said(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.ERROR
    ]


def _status(forwarder):
    (status,) = forwarder.get_status()["log_sources"]
    return status


# -- commands ----------------------------------------------------------------


def _command(tmp_path, monkeypatch, kind):
    """journalctl or log, played by a script that writes READ_AT_ONCE entries
    at once, which is one read, and stays."""
    script = tmp_path / "command.py"
    script.write_text(textwrap.dedent("""
            import json, sys, time
            sys.stdout.write("".join(
                json.dumps({"__CURSOR": "s=1;i=%%d" %% index, "MESSAGE": index}) + "\\n"
                for index in range(%d)
            ))
            sys.stdout.flush()
            time.sleep(60)
            """ % READ_AT_ONCE))
    argv = [sys.executable, str(script)]
    if kind == "journald":
        monkeypatch.setattr(log_forwarder, "is_linux", lambda: True)
        monkeypatch.setattr(
            LogForwarder, "_journal_command", lambda self, runtime: argv
        )
    else:
        monkeypatch.setattr(log_forwarder, "is_macos", lambda: True)
        monkeypatch.setattr(
            LogForwarder, "_unified_log_command", staticmethod(lambda: argv)
        )
    return LogSourceConfig(name=kind, type=kind, format="json")


@pytest.mark.parametrize("kind", ["journald", "unified_log"])
@pytest.mark.asyncio
async def test_an_entry_whose_handling_raises_does_not_take_its_read_with_it(
    tmp_path, monkeypatch, caplog, kind
):
    source = _command(tmp_path, monkeypatch, kind)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    forwarder = _forwarder(
        source, lambda event: event["data"]["MESSAGE"] == AT_FAULT, data_dir
    )

    with caplog.at_level(logging.ERROR, logger=log_forwarder.__name__):
        await forwarder.start()
        try:
            received = await _events(forwarder, len(THE_OTHERS))
            status = _status(forwarder)
            for _, delivery in received:
                if delivery is not None:
                    delivery.settle()
            after = _status(forwarder)
        finally:
            await forwarder.stop()

    # main: 0 to 3, then the command was ended and started again. The
    # stand-in then writes all ten again; `log stream` would go on from the
    # moment of its start, and entries 5 to 9 were lost.
    assert [event["data"]["MESSAGE"] for event, _ in received] == THE_OTHERS
    assert status["restarts"] == 0 and status["state"] == "running"
    assert status["entries_forwarded"] == len(THE_OTHERS)
    # Counted once, as an error.
    assert status["entries_failed"] == 1 and forwarder.event_queue.raised == 1
    assert _said(caplog) == [
        f"Log source {kind!r}: an entry could not be handled (RuntimeError). "
        "It is counted (entries_failed) and passed over, and what was read "
        "with it is handled. This is said once for each kind of error"
    ]
    assert ERROR_TEXT not in caplog.text
    if kind == "journald":
        # The entry at fault does not hold the saved cursor where it was.
        assert after["accepted_cursor"] == f"s=1;i={READ_AT_ONCE - 1}"


@pytest.mark.asyncio
async def test_an_entry_that_raises_before_it_has_a_place_is_passed_over_too(
    tmp_path, monkeypatch
):
    # Earlier in the handling: nothing is known of the entry yet.
    source = _command(tmp_path, monkeypatch, "journald")
    forwarder = _forwarder(source, lambda event: False)
    real = LogForwarder._entry_data

    def entry_data(raw, cut):
        if b'"MESSAGE": %d}' % AT_FAULT in raw:
            raise KeyError(ERROR_TEXT)
        return real(raw, cut)

    forwarder._entry_data = entry_data

    await forwarder.start()
    try:
        received = await _events(forwarder, len(THE_OTHERS))
        for _, delivery in received:
            delivery.settle()
        status = _status(forwarder)
    finally:
        await forwarder.stop()

    assert [event["data"]["MESSAGE"] for event, _ in received] == THE_OTHERS
    assert (status["entries_failed"], status["restarts"]) == (1, 0)
    assert status["accepted_cursor"] == f"s=1;i={READ_AT_ONCE - 1}"


@pytest.mark.asyncio
async def test_the_same_kind_of_error_is_logged_once_and_counted_each_time(
    tmp_path, monkeypatch, caplog
):
    source = _command(tmp_path, monkeypatch, "unified_log")
    forwarder = _forwarder(source, lambda event: event["data"]["MESSAGE"] % 2 == 1)

    with caplog.at_level(logging.ERROR, logger=log_forwarder.__name__):
        await forwarder.start()
        try:
            received = await _events(forwarder, READ_AT_ONCE // 2)
            status = _status(forwarder)
        finally:
            await forwarder.stop()

    assert [event["data"]["MESSAGE"] for event, _ in received] == [0, 2, 4, 6, 8]
    assert status["entries_failed"] == READ_AT_ONCE // 2
    assert len(_said(caplog)) == 1


# -- files -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_line_whose_handling_raises_does_not_take_its_chunk_with_it(
    tmp_path, monkeypatch, caplog
):
    monkeypatch.setattr(log_forwarder, "POLL_INTERVAL", 0.01)
    log = tmp_path / "app.log"
    log.write_text("".join(f"line {index}\n" for index in range(READ_AT_ONCE)))
    source = LogSourceConfig(
        name="app", path=str(log), format="raw", read_from="beginning"
    )
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    forwarder = _forwarder(
        source,
        lambda event: event["data"]["raw_message"] == f"line {AT_FAULT}",
        data_dir,
    )

    with caplog.at_level(logging.ERROR, logger=log_forwarder.__name__):
        await forwarder.start()
        try:
            received = await _events(forwarder, len(THE_OTHERS))
            for _, delivery in received:
                delivery.settle()
            positions = _status(forwarder)["positions"][str(log)]
            stats = forwarder.get_status()["stats"]
        finally:
            await forwarder.stop()

    # main: lines 0 to 3 and an "Error reading log source" in the log. The
    # file had been read to its end, so lines 5 to 9 were never forwarded.
    assert [event["data"]["raw_message"] for event, _ in received] == [
        f"line {index}" for index in THE_OTHERS
    ]
    assert stats == {
        "lines_forwarded": len(THE_OTHERS),
        "lines_truncated": 0,
        "lines_failed": 1,
    }
    assert _said(caplog) == [
        "Log source 'app': a line could not be handled (RuntimeError). It is "
        "counted (lines_failed) and passed over, and what was read with it "
        "is handled. This is said once for each kind of error"
    ]
    assert ERROR_TEXT not in caplog.text
    # The line at fault does not hold the saved offset where it was: a
    # restart goes on from the end of the file, not from line 4 for ever.
    assert positions == {
        "read": log.stat().st_size,
        "accepted": log.stat().st_size,
        "behind": 0,
    }


# -- a Windows event log -----------------------------------------------------


@pytest.mark.parametrize("early", [False, True])
@pytest.mark.asyncio
async def test_an_event_whose_handling_raises_does_not_end_the_reader_of_its_log(
    tmp_path, monkeypatch, caplog, early
):
    # ``early``: the error comes before anything is known of the event,
    # and not from the queue.
    asked = []

    def query(argv):
        after = int(argv[-1].split("EventRecordID > ")[1].split("]")[0])
        asked.append(after)
        events = [
            {"RecordId": record, "Id": 4624, "Message": f"event {record}"}
            for record in range(1, READ_AT_ONCE + 1)
            if len(asked) > 1 and record > after
        ]
        newest = READ_AT_ONCE if len(asked) > 1 else 0
        return json.dumps({"newest": newest, "events": events})

    monkeypatch.setattr(log_forwarder, "is_windows", lambda: True)
    monkeypatch.setattr(log_forwarder, "WINDOWS_POLL_INTERVAL", 0.01)
    monkeypatch.setattr(LogForwarder, "_run_windows_query", staticmethod(query))
    source = LogSourceConfig(
        name="security",
        type="windows_event",
        log_name="Security",
        format="windows_event",
    )
    # The last event of the answer: nothing after it moves the record id
    # the log is asked from, and it must not be asked for again.
    forwarder = _forwarder(
        source,
        lambda event: not early and event["data"]["RecordId"] == READ_AT_ONCE,
    )
    real = forwarder._windows_event
    raised = []

    async def windows_event(runtime, data):
        if early and data["RecordId"] == READ_AT_ONCE:
            raised.append(data)
            raise RuntimeError(ERROR_TEXT)
        await real(runtime, data)

    forwarder._windows_event = windows_event

    with caplog.at_level(logging.ERROR, logger=log_forwarder.__name__):
        await forwarder.start()
        try:
            received = await _events(forwarder, READ_AT_ONCE - 1)
            for _, delivery in received:
                delivery.settle()
            polls = len(asked)
            await _until(lambda: len(asked) >= polls + 3)
            status = _status(forwarder)
        finally:
            await forwarder.stop()

    # main: the reader's task ended with the error, which nobody saw before
    # the stop, and the log was not asked again.
    assert [event["data"]["RecordId"] for event, _ in received] == list(
        range(1, READ_AT_ONCE)
    )
    assert status["state"] == "running"
    assert status["entries_failed"] == 1
    assert forwarder.event_queue.raised + len(raised) == 1
    assert status["read_record_id"] == READ_AT_ONCE
    # An event that had its place in the order does not hold the saved
    # record id. One that failed before it had one was never in the order:
    # the saved id is that of the last event accepted, and after a restart
    # the event at fault is asked for once more.
    assert status["accepted_record_id"] == READ_AT_ONCE - (1 if early else 0)
    assert asked[-1] == READ_AT_ONCE
    assert len(_said(caplog)) == 1 and ERROR_TEXT not in caplog.text
