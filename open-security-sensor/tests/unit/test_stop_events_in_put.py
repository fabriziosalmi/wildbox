"""An event a collector is waiting to queue when the sensor stops is counted
(#765).

A collector hands an event over with ``await queue.put(event)``, which waits
while the queue is full: that wait is how a gateway that takes nothing slows
the collectors down. A collector stopped there held an event that was in no
queue, no counter and no log line. The sensor's last lines said how many
events had not reached the sender, and that one was not among them. With a
saved position or baseline it was read again after the restart; without
``data_dir``, and for the macOS ``log stream`` source, it was lost without a
word.

The queue answers for it now, from the moment ``put()`` is called. The tests
fill a real agent from the gateway backwards (the sender's buffer and its
hand, the processed queue, the worker, the collectors' queue) until the real
collector waits in ``put()``, and stop it there. Nothing is timed: each test
waits for the state it needs.

Behind that event there were more (#777). ``journalctl`` and ``log stream``
are read a chunk at a time, and a chunk is many entries: the reader that
waits in ``put()`` with one of them holds the rest of its chunk, which are
not events yet and were counted by nobody. The forwarder counts them now,
and the agent's last lines include them: every entry the command wrote and
the sensor read is at the sender, on its way, in ``put()`` or behind it.

A file and a Windows event log are read the same way, a chunk of lines and
an answer of events at a time, and theirs were left out of that count (#788):
the two tests of a file source below asked for four lines when the sensor had
read ten, and now ask for seven.
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

from sensor.collectors import file_monitor, log_forwarder  # noqa: E402
from sensor.core import agent as agent_module  # noqa: E402
from sensor.core.agent import CountingQueue, SecuritySensorAgent  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    FIMConfig,
    LogSourceConfig,
    NetworkConfig,
    PerformanceConfig,
    SensorConfig,
)
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import RETRY, SENT, DataForwarder  # noqa: E402
from sensor.pipeline.delivery import DELIVERY_KEY, Delivery  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# What a sensor holds when the gateway takes nothing and everything behind it
# is full, with the sizes the agents below are given: two events in the
# sender's buffer and one in its hand, which have reached the sender; one on
# the processed queue, one in the worker's hand and one on the collectors'
# queue, which have not; and the one a collector is waiting to put.
AT_THE_SENDER = 3
ON_THEIR_WAY = 3
IN_PUT = 1
# The entries a command writes at once in the tests below, which the reader
# gets in one read, and how many of them are then behind the one in put().
WRITTEN_AT_ONCE = 10
BEHIND_IT = WRITTEN_AT_ONCE - AT_THE_SENDER - ON_THEIR_WAY - IN_PUT


class Gateway:
    """What the sender's requests are answered, and what was accepted."""

    def __init__(self):
        self.answer = RETRY
        self.accepted = []


@pytest.fixture
def gateway(monkeypatch):
    gateway = Gateway()

    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    async def send(self, body):
        if gateway.answer == SENT:
            gateway.accepted.extend(
                event["event_data"] for event in json.loads(body)["events"]
            )
        return gateway.answer

    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    monkeypatch.setattr(log_forwarder, "POLL_INTERVAL", 0.01)
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 3600)
    # The drain and the last batches wait for a gateway that takes nothing:
    # not for long, here.
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 0.1)
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.3)
    return gateway


class Watched(CountingQueue):
    """The collectors' queue, which also says how many puts are waiting."""

    waiting = 0

    async def put(self, item):
        self.waiting += 1
        try:
            await super().put(item)
        finally:
            self.waiting -= 1


def _agent(data_dir=None, sources=None, watched=None, tight=True):
    """An agent with one collector. ``tight``: every stage holds as little
    as it can, so that a handful of events fills the sensor."""
    agent = SecuritySensorAgent(
        SensorConfig(
            data_lake=DataLakeConfig(
                endpoint="https://gateway.example",
                api_key=API_KEY,
                batch_size=2 if tight else 100,
                buffer_max_events=2 if tight else 1000,
                flush_interval=1,
            ),
            collection=CollectionConfig(
                process_events=False,
                network_connections=False,
                file_monitoring=watched is not None,
                user_events=False,
                system_inventory=False,
                log_forwarding=sources is not None,
            ),
            fim=FIMConfig(
                enabled=watched is not None, paths=[str(watched)] if watched else []
            ),
            network=NetworkConfig(enable_api=False),
            performance=PerformanceConfig(worker_threads=1),
            log_sources=sources,
            data_dir=str(data_dir) if data_dir else None,
        )
    )
    if tight:
        agent.event_queue = Watched(maxsize=1)
        agent.processed_queue = asyncio.Queue(maxsize=1)
    return agent


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


async def _full_to_the_collector(agent):
    """Wait until the agent holds all it can and its collector waits in
    ``put()`` with one event more."""
    agent.data_forwarder.min_request_interval = 0.002
    await _until(lambda: agent.data_forwarder.get_status()["buffer"]["full"])
    await _until(lambda: agent.data_forwarder.held == AT_THE_SENDER)
    await _until(lambda: agent.processed_queue.full())
    await _until(lambda: agent.data_processor.in_flight == 1)
    await _until(lambda: agent.event_queue.full())
    await _until(lambda: agent.event_queue.waiting == IN_PUT)
    # And it stays so: nothing moves any more.
    for _ in range(50):
        await asyncio.sleep(0)
    assert agent.event_queue.waiting == IN_PUT


async def _stop(agent, caplog):
    with caplog.at_level(logging.WARNING):
        await asyncio.wait_for(agent.stop(), timeout=30)
    return [record.getMessage() for record in caplog.records]


def _line(dropped, returned):
    return (
        f"Stopped with {dropped + returned} events still on their way to the "
        f"sender: {dropped} are dropped, {returned} will be read again from "
        f"their log source after the restart"
    )


# -- the queue ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_put_that_is_cancelled_while_it_waits_keeps_its_event():
    queue = CountingQueue(maxsize=1)
    queue.put_nowait("on the queue")
    waiting = asyncio.ensure_future(queue.put("in put"))
    await asyncio.sleep(0)
    assert not waiting.done()

    waiting.cancel()
    await asyncio.gather(waiting, return_exceptions=True)

    assert waiting.cancelled()
    # main: it was nowhere.
    assert queue.turned_away == ["in put"]
    assert queue.qsize() == 1 and queue.total == 1


@pytest.mark.asyncio
async def test_a_put_that_finds_room_is_on_the_queue_and_nowhere_else():
    queue = CountingQueue(maxsize=1)

    await queue.put("first")
    waiting = asyncio.ensure_future(queue.put("second"))
    await asyncio.sleep(0)
    assert queue.get_nowait() == "first"
    await asyncio.wait_for(waiting, timeout=5)

    assert queue.get_nowait() == "second"
    assert queue.turned_away == [] and queue.total == 2


@pytest.mark.parametrize("room_first", [True, False])
@pytest.mark.parametrize("turns", range(4))
@pytest.mark.asyncio
async def test_a_put_cancelled_as_room_is_made_is_in_exactly_one_place(
    room_first, turns
):
    # The stop cancels a collector in the very turn of the event loop in
    # which a worker takes an event and makes room for the collector's, or
    # a turn or two apart, in either order. Whichever wins, the event is
    # on the queue or turned away: not both, and not neither, which is
    # what #754 was between a queue and its reader.
    queue = CountingQueue(maxsize=1)
    queue.put_nowait("on the queue")
    waiting = asyncio.ensure_future(queue.put("in put"))
    await asyncio.sleep(0)

    first, second = (
        (queue.get_nowait, waiting.cancel)
        if room_first
        else (waiting.cancel, queue.get_nowait)
    )
    first()
    for _ in range(turns):
        await asyncio.sleep(0)
    second()
    await asyncio.gather(waiting, return_exceptions=True)

    queued = []
    while not queue.empty():
        queued.append(queue.get_nowait())
    assert queued + queue.turned_away == ["in put"]
    assert queue.total == 1 + len(queued)


# -- the collectors ----------------------------------------------------------


def _log(tmp_path, lines=WRITTEN_AT_ONCE, junk=False, unfinished=b""):
    """A log of ``lines`` lines, which the forwarder gets in one read.
    ``junk``: with lines between them that are none. ``unfinished``: what
    the file ends with, after its last newline."""
    log = tmp_path / "app.log"
    between = "\n   \n\t\n" if junk else "\n"
    text = "".join(f"line {index}{between}" for index in range(lines))
    log.write_bytes(text.encode() + unfinished)
    assert log.stat().st_size <= log_forwarder.READ_CHUNK
    source = LogSourceConfig(
        name="app", path=str(log), format="raw", read_from="beginning"
    )
    return log, source


@pytest.mark.parametrize("junk", [False, True])
@pytest.mark.asyncio
async def test_a_log_line_waiting_for_room_is_counted_and_read_again(
    tmp_path, gateway, caplog, junk
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _, source = _log(tmp_path, junk=junk)
    agent = _agent(data_dir, [source])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    # Before #765: 3, the line in put() was in no count. Before #788: 4, the
    # three lines read with it and behind it were in none, and this test
    # asked for four. A line that is blank is no event, and is not counted.
    assert _line(dropped=0, returned=ON_THEIR_WAY + IN_PUT + BEHIND_IT) in said
    stats = agent.data_forwarder.stats
    assert stats["events_received"] == AT_THE_SENDER
    assert stats["events_returned_to_source"] == AT_THE_SENDER
    # Every line the sensor read is in one count or the other.
    assert AT_THE_SENDER + ON_THEIR_WAY + IN_PUT + BEHIND_IT == WRITTEN_AT_ONCE
    # Counted once: a second stop has nothing left to say.
    assert agent.event_queue.turned_away == []
    assert agent.log_forwarder.interrupted == []
    assert agent.event_queue.empty() and agent.processed_queue.empty()

    # Returned to its collector: no line was accepted, so the position is
    # where it was, and a sensor that starts again delivers every line once.
    gateway.answer = SENT
    again = _agent(data_dir, [source], tight=False)
    await again.start()
    try:
        await _until(lambda: len(gateway.accepted) >= 10)
        await asyncio.sleep(0.1)
    finally:
        await asyncio.wait_for(again.stop(), timeout=30)
    assert [event["data"]["raw_message"] for event in gateway.accepted] == [
        f"line {index}" for index in range(10)
    ]


@pytest.mark.asyncio
async def test_without_a_saved_position_the_line_in_put_is_counted_as_dropped(
    tmp_path, gateway, caplog
):
    _, source = _log(tmp_path)
    agent = _agent(None, [source])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    # Nothing keeps the position: the lines are not read again, and the
    # sensor says so for all seven. It said three before #765 and four
    # before #788, which is what this test asked for.
    assert _line(dropped=ON_THEIR_WAY + IN_PUT + BEHIND_IT, returned=0) in said
    assert agent.data_forwarder.stats["events_dropped_shutdown"] == AT_THE_SENDER


@pytest.mark.asyncio
async def test_a_long_line_without_its_newline_behind_the_one_in_put_is_counted(
    tmp_path, gateway, caplog
):
    # What the read ends with is forwarded at once, cut, when it is longer
    # than a line may be: it is an event of this read too.
    unfinished = b"x" * (log_forwarder.MAX_LINE_BYTES + 1)
    _, source = _log(tmp_path, unfinished=unfinished)
    agent = _agent(None, [source])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    assert _line(dropped=ON_THEIR_WAY + IN_PUT + BEHIND_IT + 1, returned=0) in said


@pytest.mark.asyncio
async def test_the_beginning_of_a_line_behind_the_one_in_put_is_not_counted(
    tmp_path, gateway, caplog
):
    # No newline yet and not too long: it is no line until its newline is
    # written, and the sensor has made nothing of it.
    _, source = _log(tmp_path, unfinished=b"the beginning of a line")
    agent = _agent(None, [source])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    assert _line(dropped=ON_THEIR_WAY + IN_PUT + BEHIND_IT, returned=0) in said


@pytest.mark.asyncio
async def test_a_file_reader_stopped_at_the_end_of_its_file_holds_nothing(
    tmp_path, gateway, caplog
):
    _, source = _log(tmp_path)
    agent = _agent(None, [source], tight=False)
    gateway.answer = SENT

    await agent.start()
    await _until(lambda: len(gateway.accepted) == WRITTEN_AT_ONCE)
    forwarder = agent.log_forwarder
    said = await _stop(agent, caplog)

    assert forwarder.interrupted == []
    assert [line for line in said if line.startswith("Stopped with")] == []


def _event_log(monkeypatch):
    """A Windows event log that is empty when the sensor first looks at it
    and has WRITTEN_AT_ONCE events at the next look, which is one answer.
    The query is a stand-in, as in test_log_windows_events.py."""
    asked = []

    def query(argv):
        after = int(argv[-1].split("EventRecordID > ")[1].split("]")[0])
        asked.append(after)
        events = [
            {"RecordId": record, "Id": 4624, "Message": f"event {record}"}
            for record in range(1, WRITTEN_AT_ONCE + 1)
            if len(asked) > 1 and record > after
        ]
        newest = WRITTEN_AT_ONCE if len(asked) > 1 else 0
        return json.dumps({"newest": newest, "events": events})

    monkeypatch.setattr(log_forwarder, "is_windows", lambda: True)
    monkeypatch.setattr(log_forwarder, "WINDOWS_POLL_INTERVAL", 0.01)
    monkeypatch.setattr(
        log_forwarder.LogForwarder, "_run_windows_query", staticmethod(query)
    )
    return LogSourceConfig(
        name="security",
        type="windows_event",
        log_name="Security",
        format="windows_event",
    )


@pytest.mark.asyncio
async def test_the_windows_events_behind_the_one_in_put_are_counted_and_read_again(
    tmp_path, gateway, caplog, monkeypatch
):
    # The saved record id is that of the last event accepted, which is
    # before all of these: the log is asked for them again.
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    agent = _agent(data_dir, [_event_log(monkeypatch)])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    # main: 4 of them.
    assert _line(dropped=0, returned=ON_THEIR_WAY + IN_PUT + BEHIND_IT) in said
    assert agent.data_forwarder.stats["events_returned_to_source"] == AT_THE_SENDER
    assert agent.log_forwarder.interrupted == []

    gateway.answer = SENT
    again = _agent(data_dir, [_event_log(monkeypatch)], tight=False)
    await again.start()
    try:
        await _until(lambda: len(gateway.accepted) >= WRITTEN_AT_ONCE)
        await asyncio.sleep(0.1)
    finally:
        await asyncio.wait_for(again.stop(), timeout=30)
    assert [event["data"]["RecordId"] for event in gateway.accepted] == list(
        range(1, WRITTEN_AT_ONCE + 1)
    )


@pytest.mark.asyncio
async def test_without_a_saved_record_id_the_windows_events_behind_it_are_dropped(
    tmp_path, gateway, caplog, monkeypatch
):
    agent = _agent(None, [_event_log(monkeypatch)])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    # Nothing keeps the record id: the log is followed from the restart on.
    assert _line(dropped=ON_THEIR_WAY + IN_PUT + BEHIND_IT, returned=0) in said


@pytest.mark.asyncio
async def test_an_entry_of_a_source_that_cannot_be_read_again_is_counted_as_dropped(
    tmp_path, gateway, caplog, monkeypatch
):
    # The macOS unified log: `log stream` cannot be asked for an entry
    # again, with or without data_dir, so its events carry no Delivery. The
    # command is played by a script, as in test_log_system_sources.py.
    _plays(monkeypatch, tmp_path, "unified_log")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    source = LogSourceConfig(name="unified", type="unified_log", format="json")
    agent = _agent(data_dir, [source])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    # This test asked for ON_THEIR_WAY + IN_PUT, four, when the command had
    # written ten and three were at the sender: the three entries behind
    # the one in put() were in no count (#777).
    assert _line(dropped=ON_THEIR_WAY + IN_PUT + BEHIND_IT, returned=0) in said
    assert agent.data_forwarder.stats["events_dropped_shutdown"] == AT_THE_SENDER
    # Every entry the command wrote is in one count or the other.
    assert AT_THE_SENDER + ON_THEIR_WAY + IN_PUT + BEHIND_IT == WRITTEN_AT_ONCE
    # Counted once: a second stop has nothing left to say.
    assert agent.log_forwarder.interrupted == []


def _plays(monkeypatch, tmp_path, kind, junk=False):
    """journalctl or log, played by a script that writes WRITTEN_AT_ONCE
    entries at once, which is one read, and stays. ``junk``: with lines
    between them that are no entries."""
    script = tmp_path / "command.py"
    script.write_text(
        textwrap.dedent(
            """
            import json, sys, time
            lines = []
            for index in range(%d):
                lines.append(json.dumps(
                    {"__CURSOR": "s=1;i=%%d" %% index, "MESSAGE": "entry %%d" %% index}
                ))
                if %r:
                    lines.extend(["", "not an entry", "[1, 2]"])
            sys.stdout.write("\\n".join(lines) + "\\n")
            sys.stdout.flush()
            time.sleep(60)
            """
            % (WRITTEN_AT_ONCE, junk)
        )
    )
    argv = [sys.executable, str(script)]
    if kind == "journald":
        monkeypatch.setattr(log_forwarder, "is_linux", lambda: True)
        monkeypatch.setattr(
            log_forwarder.LogForwarder, "_journal_command", lambda self, runtime: argv
        )
    else:
        monkeypatch.setattr(log_forwarder, "is_macos", lambda: True)
        monkeypatch.setattr(
            log_forwarder.LogForwarder,
            "_unified_log_command",
            staticmethod(lambda: argv),
        )


@pytest.mark.parametrize("junk", [False, True])
@pytest.mark.asyncio
async def test_the_journal_entries_behind_the_one_in_put_are_counted_and_read_again(
    tmp_path, gateway, caplog, monkeypatch, junk
):
    # The journal is read again from the saved cursor, which is that of the
    # last entry accepted: before all of these.
    _plays(monkeypatch, tmp_path, "journald", junk)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    source = LogSourceConfig(name="journal", type="journald", format="json")
    agent = _agent(data_dir, [source])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    # main: 4 of them. A line that is no entry (blank, not JSON, not an
    # object) is no event either way, and is not counted as one.
    assert _line(dropped=0, returned=ON_THEIR_WAY + IN_PUT + BEHIND_IT) in said
    assert agent.data_forwarder.stats["events_returned_to_source"] == AT_THE_SENDER
    assert agent.log_forwarder.interrupted == []


@pytest.mark.asyncio
async def test_without_a_saved_cursor_the_journal_entries_behind_it_are_dropped(
    tmp_path, gateway, caplog, monkeypatch
):
    _plays(monkeypatch, tmp_path, "journald")
    source = LogSourceConfig(name="journal", type="journald", format="json")
    agent = _agent(None, [source])

    await agent.start()
    await _full_to_the_collector(agent)
    said = await _stop(agent, caplog)

    # Nothing keeps the cursor: the journal is followed from the restart on.
    assert _line(dropped=ON_THEIR_WAY + IN_PUT + BEHIND_IT, returned=0) in said


@pytest.mark.asyncio
async def test_a_reader_stopped_while_it_waits_for_the_command_holds_nothing(
    tmp_path, gateway, caplog, monkeypatch
):
    # Every entry was handled: the reader is waiting for the command's next
    # output, not in put().
    _plays(monkeypatch, tmp_path, "journald")
    source = LogSourceConfig(name="journal", type="journald", format="json")
    agent = _agent(None, [source], tight=False)
    gateway.answer = SENT

    await agent.start()
    await _until(lambda: len(gateway.accepted) == WRITTEN_AT_ONCE)
    forwarder = agent.log_forwarder
    said = await _stop(agent, caplog)

    assert forwarder.interrupted == []
    assert [line for line in said if line.startswith("Stopped with")] == []


@pytest.mark.asyncio
async def test_a_file_change_waiting_for_room_is_counted_and_found_again(
    tmp_path, gateway, caplog
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    watched = tmp_path / "etc"
    watched.mkdir()
    names = [f"file{index}" for index in range(9)]
    for name in names:
        (watched / name).write_text("as it was\n")
    # A first life of the sensor, to take the baseline.
    first = _agent(data_dir, watched=watched, tight=False)
    await first.start()
    await asyncio.wait_for(first.stop(), timeout=30)
    for name in names:
        (watched / name).write_text("changed while the sensor was stopped\n")
    agent = _agent(data_dir, watched=watched)

    await agent.start()
    await _full_to_the_collector(agent)
    status = agent.file_monitor.get_status()["baseline"]
    assert status["changes_not_delivered"] == len(names)
    said = await _stop(agent, caplog)

    # Seven events exist: three at the sender, three on their way, and the
    # one the monitor was waiting to queue, which main did not count.
    assert _line(dropped=0, returned=ON_THEIR_WAY + IN_PUT) in said
    assert agent.data_forwarder.stats["events_returned_to_source"] == AT_THE_SENDER
    # The two changes behind it have no event yet, and are said as what
    # they are.
    left = len(names) - AT_THE_SENDER - ON_THEIR_WAY - IN_PUT
    assert (
        f"File integrity monitoring: stopped with {left} changes found and "
        "not queued yet: they are not in the saved baseline, and are found "
        "again when the sensor starts"
    ) in said

    # None was accepted, none is in the saved baseline: all nine are found
    # again.
    gateway.answer = SENT
    again = _agent(data_dir, watched=watched, tight=False)
    await again.start()
    try:
        await _until(lambda: len(gateway.accepted) >= len(names))
    finally:
        await asyncio.wait_for(again.stop(), timeout=30)
    assert sorted(event["data"]["path"] for event in gateway.accepted) == [
        str(watched / name) for name in names
    ]
    assert {event["type"] for event in gateway.accepted} == {"file_modified"}


@pytest.mark.asyncio
async def test_what_was_turned_away_is_not_settled(gateway, caplog):
    # Settling is what moves a position or a baseline past an event: an
    # event that never got on the queue must leave them where they are.
    agent = _agent()
    settled = []

    await agent.start()
    agent.data_forwarder.min_request_interval = 0.002

    def event(name):
        return {
            "type": "log.app",
            "source": "log_forwarder",
            "data": {"raw_message": name},
            DELIVERY_KEY: Delivery(lambda: settled.append(name), replayable=True),
        }

    async def collector():
        for index in range(10):
            await agent.event_queue.put(event(f"line {index}"))

    collecting = asyncio.ensure_future(collector())
    await _full_to_the_collector(agent)
    collecting.cancel()
    await asyncio.gather(collecting, return_exceptions=True)
    assert len(agent.event_queue.turned_away) == IN_PUT
    said = await _stop(agent, caplog)

    assert _line(dropped=0, returned=ON_THEIR_WAY + IN_PUT) in said
    assert settled == []
