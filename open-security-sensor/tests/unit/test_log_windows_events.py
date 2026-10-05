"""The Windows event log is read once, in order, and not from the event loop (#725).

The reader asked PowerShell for the ten newest events of a log every 30
seconds and forwarded all ten each time: the same events again and again,
anything beyond ten in 30 seconds never, and the event loop stopped for as
long as PowerShell ran.

There is no Windows here. The query itself, ``_run_windows_query``, is
replaced by a stand-in that answers as the PowerShell command is written to
answer; everything around it is the real code. What that leaves untested, on
a real host, is said in the README: the PowerShell text and what
``Get-WinEvent`` returns.
"""

import asyncio
import json
import logging
import sys
import threading
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import log_forwarder  # noqa: E402
from sensor.collectors.log_forwarder import (  # noqa: E402
    MAX_LINE_BYTES,
    WINDOWS_MAX_EVENTS,
    WINDOWS_POLL_INTERVAL,
    LogForwarder,
)
from sensor.collectors.position_store import STATE_FILE  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    LogSourceConfig,
    SensorConfig,
)
from sensor.pipeline.delivery import take_delivery  # noqa: E402

SECURITY = LogSourceConfig(
    name="security", type="windows_event", log_name="Security", format="windows_event"
)


def _record(record_id, message=None):
    return {
        "RecordId": record_id,
        "Id": 4624,
        "Level": "Information",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "MachineName": "WIN-1",
        "TimeCreated": "2026-10-05T10:00:00.0000000Z",
        "Message": message or f"An account was successfully logged on ({record_id})",
    }


class EventLog:
    """A Windows event log, and the query asked of it."""

    def __init__(self, *record_ids):
        self.records = [_record(record_id) for record_id in record_ids]
        self.asked = []  # the record id each query asked for events after
        self.answer = None  # a fixed answer instead of the log's, or an error

    def add(self, *record_ids):
        self.records += [_record(record_id) for record_id in record_ids]

    def query(self, argv):
        script = argv[-1]
        after = int(script.split("EventRecordID > ")[1].split("]")[0])
        self.asked.append(after)
        if isinstance(self.answer, Exception):
            raise self.answer
        if self.answer is not None:
            return self.answer
        newest = max((record["RecordId"] for record in self.records), default=0)
        found = [] if after < 0 else [r for r in self.records if r["RecordId"] > after]
        found.sort(key=lambda record: record["RecordId"])
        return json.dumps({"newest": newest, "events": found[:WINDOWS_MAX_EVENTS]})


class Reader:
    """The forwarder following one event log, a poll at a time."""

    def __init__(self, monkeypatch, log, data_dir=None, source=SECURITY):
        monkeypatch.setattr(log_forwarder, "is_windows", lambda: True)
        config = SensorConfig(
            data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
            collection=CollectionConfig(log_forwarding=True),
            log_sources=[source],
            data_dir=str(data_dir) if data_dir else None,
        )
        self.forwarder = LogForwarder(config, asyncio.Queue())
        self.forwarder._run_windows_query = log.query
        self.pauses = []
        self.polled = asyncio.Event()
        self.go = asyncio.Event()
        self.forwarder._windows_pause = self._pause
        self.unsettled = []

    async def _pause(self, seconds):
        """Between two polls: the test decides when the next one happens."""
        self.pauses.append(seconds)
        if seconds:
            self.polled.set()
            await self.go.wait()
            self.go.clear()

    async def poll(self):
        """Let one poll happen (and those that follow it at once); the
        record ids forwarded."""
        if self.forwarder.running:
            self.polled.clear()
            self.go.set()
        else:
            await self.forwarder.start()
        await asyncio.wait_for(self.polled.wait(), timeout=10)
        records = []
        while not self.forwarder.event_queue.empty():
            event = self.forwarder.event_queue.get_nowait()
            self.unsettled.append((event["data"]["RecordId"], take_delivery(event)))
            records.append(event)
        return [event["data"]["RecordId"] for event in records], records

    def accept(self, *record_ids):
        for record_id, delivery in list(self.unsettled):
            if record_id in record_ids:
                self.unsettled.remove((record_id, delivery))
                delivery.settle()

    def status(self):
        (status,) = self.forwarder.get_status()["log_sources"]
        return status

    async def stop(self):
        await self.forwarder.stop()


# -- once, and in order -----------------------------------------------------


@pytest.mark.asyncio
async def test_an_event_is_forwarded_once(monkeypatch):
    log = EventLog(101, 102, 103)
    reader = Reader(monkeypatch, log)
    try:
        first, _ = await reader.poll()
        log.add(104, 105)
        second, events = await reader.poll()
        third, _ = await reader.poll()
        log.add(106)
        fourth, _ = await reader.poll()
    finally:
        await reader.stop()

    # No data directory: an event unsent at a stop will not be read again.
    assert [delivery.replayable for _, delivery in reader.unsettled] == [False] * 3

    # The first look follows the log from its newest event on, like a file
    # read from its end. main: [103, 102, 101] at this poll and at every
    # other, ten at a time.
    assert first == []
    assert second == [104, 105]
    assert third == []
    assert fourth == [106]
    # Each query asks for what comes after the last event read.
    assert log.asked == [-1, 103, 105, 105]
    assert reader.pauses == [WINDOWS_POLL_INTERVAL] * 4

    event = events[0]
    assert event["source"] == "log_forwarder"
    assert event["type"] == "log.security"
    assert event["data"] == _record(104)
    assert event["metadata"] == {
        "log_source": "security",
        "log_name": "Security",
        "format": "windows_event",
    }


@pytest.mark.asyncio
async def test_more_events_than_a_query_returns_are_read_without_waiting(monkeypatch):
    log = EventLog(1)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        log.add(*range(2, 2 + 2 * WINDOWS_MAX_EVENTS + 7))
        forwarded, _ = await reader.poll()
    finally:
        await reader.stop()

    # main asked for the ten newest: the rest of a burst was never read.
    assert forwarded == list(range(2, 2 + 2 * WINDOWS_MAX_EVENTS + 7))
    # Two full answers, each followed at once by the next query.
    assert reader.pauses == [WINDOWS_POLL_INTERVAL, 0, 0, WINDOWS_POLL_INTERVAL]


@pytest.mark.asyncio
async def test_events_are_forwarded_oldest_first_and_never_twice_whatever_is_answered(
    monkeypatch,
):
    log = EventLog(10)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        # Newest first, with events at and before the last one read, as a
        # query that ignored its filter would answer.
        log.answer = json.dumps(
            {"newest": 13, "events": [_record(n) for n in (13, 11, 10, 12, 9)]}
        )
        forwarded, _ = await reader.poll()
        again, _ = await reader.poll()
    finally:
        await reader.stop()

    assert forwarded == [11, 12, 13]
    assert again == []


@pytest.mark.asyncio
async def test_one_event_arrives_as_powershell_writes_a_list_of_one(monkeypatch):
    log = EventLog(10)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        log.answer = json.dumps({"newest": 11, "events": _record(11)})
        forwarded, _ = await reader.poll()
        log.answer = json.dumps({"newest": 11, "events": None})
        nothing, _ = await reader.poll()
    finally:
        await reader.stop()

    assert forwarded == [11]
    assert nothing == []


@pytest.mark.asyncio
async def test_a_long_message_is_cut_and_marked(monkeypatch):
    log = EventLog(1)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        log.records.append(_record(2, message="M" * (MAX_LINE_BYTES + 500)))
        _, (event,) = await reader.poll()
    finally:
        await reader.stop()

    assert event["data"]["Message"] == "M" * MAX_LINE_BYTES
    assert event["metadata"]["truncated"] is True
    assert reader.status()["entries_truncated"] == 1


# -- off the event loop -----------------------------------------------------


@pytest.mark.asyncio
async def test_the_query_does_not_stop_the_event_loop(monkeypatch):
    log = EventLog(1, 2)
    reader = Reader(monkeypatch, log)
    in_query, release = threading.Event(), threading.Event()
    threads = []

    def slow_query(argv):
        threads.append(threading.current_thread())
        in_query.set()
        # PowerShell takes seconds to start. Run in the event loop, this
        # wait would stop the loop, and nothing below could release it.
        assert release.wait(timeout=10), "the event loop never ran meanwhile"
        return log.query(argv)

    reader.forwarder._run_windows_query = slow_query
    loop_thread = threading.current_thread()

    await reader.forwarder.start()
    try:
        await asyncio.wait_for(asyncio.to_thread(in_query.wait, 10), timeout=10)
        # The query is in progress and the loop is running: this is it.
        ticks = 0
        for _ in range(5):
            await asyncio.sleep(0.01)
            ticks += 1
        release.set()
        await asyncio.wait_for(reader.polled.wait(), timeout=10)
    finally:
        release.set()
        await reader.stop()

    assert ticks == 5
    assert threads and threads[0] is not loop_thread


# -- the record id kept -----------------------------------------------------


@pytest.mark.asyncio
async def test_the_record_id_saved_is_the_last_event_accepted_and_a_restart_uses_it(
    monkeypatch, tmp_path
):
    log = EventLog(500)
    reader = Reader(monkeypatch, log, data_dir=tmp_path)
    try:
        await reader.poll()
        log.add(501, 502, 503)
        assert (await reader.poll())[0] == [501, 502, 503]
        assert reader.unsettled[0][1].replayable is True
        reader.accept(502)  # before 501: the saved id does not move
        assert reader.status()["accepted_record_id"] == 500
        reader.accept(501)
        assert reader.status()["accepted_record_id"] == 502
        assert reader.status()["read_record_id"] == 503
    finally:
        await reader.stop()  # 503 is still in the sensor

    saved = json.loads((tmp_path / STATE_FILE).read_text())["sources"]
    assert saved == {
        "security": {"type": "windows_event", "log_name": "Security", "record_id": 502}
    }

    # The sensor starts again: 503, read and not delivered, is read again,
    # with what was logged while it was down.
    log.add(504)
    log.asked.clear()
    again = Reader(monkeypatch, log, data_dir=tmp_path)
    try:
        forwarded, _ = await again.poll()
    finally:
        await again.stop()

    assert forwarded == [503, 504]
    assert log.asked == [502]


@pytest.mark.asyncio
async def test_the_first_look_is_saved_so_that_a_restart_does_not_skip(
    monkeypatch, tmp_path
):
    log = EventLog(40, 41)
    reader = Reader(monkeypatch, log, data_dir=tmp_path)
    try:
        await reader.poll()
    finally:
        await reader.stop()
    log.add(42)  # logged while the sensor was down, before it read anything

    again = Reader(monkeypatch, log, data_dir=tmp_path)
    try:
        forwarded, _ = await again.poll()
    finally:
        await again.stop()

    assert forwarded == [42]


@pytest.mark.asyncio
async def test_a_source_pointed_at_another_log_starts_from_its_newest_event(
    monkeypatch, tmp_path
):
    log = EventLog(900)
    reader = Reader(monkeypatch, log, data_dir=tmp_path)
    try:
        await reader.poll()
    finally:
        await reader.stop()

    # Same name, another log: record 900 of Security says nothing about
    # where System is.
    system = LogSourceConfig(
        name="security", type="windows_event", log_name="System", format="windows_event"
    )
    other = EventLog(5, 6, 7)
    again = Reader(monkeypatch, other, data_dir=tmp_path, source=system)
    try:
        forwarded, _ = await again.poll()
    finally:
        await again.stop()

    assert forwarded == []
    assert other.asked == [-1]
    assert again.status()["read_record_id"] == 7


@pytest.mark.asyncio
async def test_a_cleared_log_is_read_from_its_beginning(monkeypatch, caplog):
    log = EventLog(7000, 7001)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        # Cleared: record ids start again. Waiting for them to pass 7001
        # would hide everything logged after someone cleared the log.
        log.records = [_record(1), _record(2)]
        with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
            forwarded, _ = await reader.poll()
    finally:
        await reader.stop()

    assert forwarded == [1, 2]
    assert log.asked == [-1, 7001, 0]
    assert (
        "Log source 'security': the event log Security was cleared (its newest "
        "record is 2, the last one read was 7001); it is read from its beginning"
    ) in caplog.text


@pytest.mark.asyncio
async def test_an_event_from_before_the_log_was_cleared_does_not_move_the_saved_id(
    monkeypatch,
):
    log = EventLog(7000)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        log.add(7001)
        assert (await reader.poll())[0] == [7001]  # in the sensor, not accepted
        log.records = [_record(1), _record(2)]
        assert (await reader.poll())[0] == [1, 2]

        reader.accept(7001)  # accepted late: its id means nothing any more
        assert reader.status()["accepted_record_id"] == 0
        reader.accept(1)
        assert reader.status()["accepted_record_id"] == 1
    finally:
        await reader.stop()


# -- when the query fails ---------------------------------------------------


@pytest.mark.asyncio
async def test_a_query_that_fails_is_reported_once_and_asked_again(monkeypatch, caplog):
    log = EventLog(1)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        log.add(2)
        log.answer = RuntimeError(
            "PowerShell ended with exit status 1: Get-WinEvent : Attempted to "
            "perform an unauthorized operation."
        )
        with caplog.at_level(logging.INFO, logger=log_forwarder.__name__):
            assert (await reader.poll())[0] == []
            failing = reader.status()
            assert (await reader.poll())[0] == []
            log.answer = None
            forwarded, _ = await reader.poll()
            recovered = reader.status()
    finally:
        await reader.stop()

    assert failing["state"] == "failing"
    assert "unauthorized operation" in failing["last_error"]
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "data_dir is not set" not in r.getMessage()
    ]
    assert len(warnings) == 1 and "cannot be read" in warnings[0]
    # Nothing was skipped while it failed.
    assert forwarded == [2]
    assert recovered["state"] == "running"
    assert recovered["last_error"] is None
    assert "the event log Security is read again" in caplog.text


@pytest.mark.parametrize(
    "answer",
    [
        "",
        "Get-WinEvent : The term is not recognized",
        "[]",
        '{"events": []}',
        '{"newest": "12", "events": []}',
        '{"newest": true, "events": []}',
        '{"newest": 12, "events": "none"}',
        '{"newest": 12, "events": [{"Message": "an event with no record id"}]}',
        '{"newest": 12, "events": [{"RecordId": "12"}]}',
        '{"newest": 12, "events": [{"RecordId": 12}, "text"]}',
    ],
)
@pytest.mark.asyncio
async def test_an_answer_that_is_not_the_querys_forwards_nothing(monkeypatch, answer):
    log = EventLog(1)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        log.answer = answer
        forwarded, _ = await reader.poll()
        status = reader.status()
    finally:
        await reader.stop()

    assert forwarded == []
    assert status["state"] == "failing"
    assert status["read_record_id"] == 1


@pytest.mark.asyncio
async def test_powershell_missing_is_said_once_and_not_retried(monkeypatch, caplog):
    log = EventLog()
    log.answer = FileNotFoundError(2, "No such file or directory", "powershell")
    reader = Reader(monkeypatch, log)

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await reader.forwarder.start()
        (task,) = reader.forwarder._tasks
        await asyncio.wait_for(asyncio.shield(task), timeout=5)
        status = reader.status()
        await reader.stop()

    assert status["state"] == "unavailable"
    assert status["last_error"] == "powershell is not installed"
    assert log.asked == [-1]


# -- the command ------------------------------------------------------------


def test_the_query_names_the_log_and_the_record_id_and_nothing_else():
    argv = LogForwarder._windows_events_command("Security", 4711)

    assert argv[:4] == ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
    assert len(argv) == 5
    script = argv[4]
    assert "$log = 'Security'" in script
    assert "-FilterXPath '*[System[EventRecordID > 4711]]'" in script
    assert f"-MaxEvents {WINDOWS_MAX_EVENTS} -Oldest" in script
    # No double quote: the text reaches PowerShell as one argument whatever
    # the quoting rules of the process that starts it.
    assert '"' not in script
    # The first look asks for the newest record id only.
    assert "if (-1 -ge 0)" in LogForwarder._windows_events_command("System", None)[4]


@pytest.mark.parametrize(
    "log_name",
    ["Security'; Remove-Item C:\\ -Recurse; '", "", "Sec`urity", "$(whoami)", None, 5],
)
def test_a_log_name_that_could_change_the_command_is_refused(log_name):
    with pytest.raises(ValueError, match="not a Windows event log name"):
        LogForwarder._windows_events_command(log_name, 1)


@pytest.mark.parametrize("after", ["1", "1]]; Remove-Item", 1.5, True, -2])
def test_a_record_id_that_is_not_a_whole_number_is_refused(after):
    with pytest.raises(ValueError, match="not a record id"):
        LogForwarder._windows_events_command("Security", after)


def test_the_query_fails_on_a_nonzero_exit_and_bounds_its_time(monkeypatch):
    calls = []

    class Result:
        returncode = 1
        stdout = ""
        stderr = "Get-WinEvent : Attempted to perform an unauthorized operation.\n"

    def run(argv, **options):
        calls.append(options)
        return Result()

    monkeypatch.setattr(log_forwarder.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="exit status 1: Get-WinEvent"):
        LogForwarder._run_windows_query(["powershell"])

    (options,) = calls
    assert options["timeout"] == log_forwarder.WINDOWS_QUERY_TIMEOUT
    assert options["encoding"] == "utf-8"
    assert options["capture_output"] is True


@pytest.mark.asyncio
async def test_the_status_reports_the_log_and_both_record_ids(monkeypatch):
    log = EventLog(8)
    reader = Reader(monkeypatch, log)
    try:
        await reader.poll()
        log.add(9)
        await reader.poll()
        status = reader.status()
    finally:
        await reader.stop()

    assert status == {
        "name": "security",
        "type": "windows_event",
        "enabled": True,
        "state": "running",
        "restarts": 0,
        "last_exit": None,
        "last_error": None,
        "entries_forwarded": 1,
        "entries_truncated": 0,
        "entries_unparsed": 0,
        "log_name": "Security",
        "read_record_id": 9,
        "accepted_record_id": 8,
    }
