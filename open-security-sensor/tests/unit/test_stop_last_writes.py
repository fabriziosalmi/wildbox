"""A write of the sensor's state that does not return cannot hold its stop
(#777).

The log positions and the file monitor's baseline are written while the
sensor runs, each in a worker thread, under its store's lock. With a data
directory that stops answering (a network mount, a disk that hangs) such a
write stays in its thread and keeps the lock. The stop wrote both once more
with a plain call in the event loop: the call waited for the lock, the loop
with it, and so did every limit the stop has, which are the loop's timers.
The one limit that is not, the thread that ends the process, was armed only
after those writes. The sensor was killed when its grace period ran out,
having logged nothing since "Stopping".

Every write is made in a worker thread now, and whoever asks for one at the
stop waits a limited time for it. The stores here are the real ones, on a
directory that stops answering when the test says so: the store's file write
does not return until the test is over. Nothing is timed. A test waits for
the write to be in its thread, and a write asked for from the event loop's
own thread fails the test on the spot instead of hanging it.
"""

import asyncio
import errno
import json
import logging
import sys
import threading
from pathlib import Path

import pytest
import pytest_asyncio

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import file_monitor, log_forwarder  # noqa: E402
from sensor.collectors.baseline_store import BASELINE_FILE  # noqa: E402
from sensor.collectors.log_forwarder import LogForwarder  # noqa: E402
from sensor.collectors.position_store import STATE_FILE  # noqa: E402
from sensor.core import agent as agent_module  # noqa: E402
from sensor.core.agent import SecuritySensorAgent  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    FIMConfig,
    LogSourceConfig,
    NetworkConfig,
    SensorConfig,
)
from sensor.pipeline.data_forwarder import SENT, DataForwarder  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class Disk:
    """The data directory, as the stores see it."""

    def __init__(self):
        self._loop_thread = threading.get_ident()
        self.released = threading.Event()
        # The stores a write was asked of from the event loop's own thread.
        self.written_on_the_loop = []
        # The threads the writes were made in.
        self.writers = set()

    def watch(self, store):
        """Refuse a write of ``store`` made in the event loop's thread."""
        save = store.save

        def watched(*args):
            if threading.get_ident() == self._loop_thread:
                self.written_on_the_loop.append(type(store).__name__)
                raise AssertionError(
                    f"{type(store).__name__}.save() was called in the event "
                    "loop's thread, which waits there for the store's lock"
                )
            self.writers.add(threading.get_ident())
            return save(*args)

        store.save = watched

    def stops_answering(self, store) -> threading.Event:
        """From now on a write of ``store``'s file does not return. The
        event is set when one is waiting."""
        waiting = threading.Event()

        def write(payload):
            waiting.set()
            self.released.wait()

        store._file.write = write
        return waiting

    def is_full(self, store):
        """From now on a write of ``store``'s file fails."""

        def write(payload):
            raise OSError(errno.ENOSPC, "No space left on device")

        store._file.write = write


@pytest_asyncio.fixture
async def disk():
    # Asynchronous, so that it is over before the loop is closed: closing
    # waits for the worker threads, and they wait for this.
    disk = Disk()
    yield disk
    disk.released.set()


@pytest.fixture
def gateway(monkeypatch):
    """A gateway that accepts every batch; the intervals of the collectors
    and the limits of the stop are short."""

    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    async def send(self, body):
        accepted.extend(event["event_data"] for event in json.loads(body)["events"])
        return SENT

    accepted = []
    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    monkeypatch.setattr(log_forwarder, "POLL_INTERVAL", 0.01)
    monkeypatch.setattr(log_forwarder, "POSITION_SAVE_INTERVAL", 0.01)
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 0.01)
    monkeypatch.setattr(file_monitor, "BASELINE_SAVE_INTERVAL", 0.01)
    # What a stop waits for a write that does not return: not for long,
    # here. The limits themselves are in test_stop_time_limits.py.
    monkeypatch.setattr(log_forwarder, "STATE_WRITE_SECONDS", 0.05)
    monkeypatch.setattr(file_monitor, "STATE_WRITE_SECONDS", 0.05)
    monkeypatch.setattr(agent_module, "LAST_WRITES_SECONDS", 0.05)
    return accepted


@pytest.fixture
def host(tmp_path):
    """A data directory, a log with one line and a watched directory with
    one file."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    log = tmp_path / "app.log"
    log.write_text("one\n")
    watched = tmp_path / "etc"
    watched.mkdir()
    (watched / "hosts").write_text("127.0.0.1 localhost\n")
    return data_dir, log, watched


def _config(host, logs=True, files=True):
    data_dir, log, watched = host
    return SensorConfig(
        data_lake=DataLakeConfig(
            endpoint="https://gateway.example",
            api_key=API_KEY,
            batch_size=1,
            flush_interval=1,
        ),
        collection=CollectionConfig(
            process_events=False,
            network_connections=False,
            file_monitoring=files,
            user_events=False,
            system_inventory=False,
            log_forwarding=logs,
        ),
        fim=FIMConfig(enabled=files, paths=[str(watched)] if files else []),
        network=NetworkConfig(enable_api=False),
        log_sources=(
            [
                LogSourceConfig(
                    name="app", path=str(log), format="raw", read_from="beginning"
                )
            ]
            if logs
            else None
        ),
        data_dir=str(data_dir),
    )


async def _until(condition, timeout=20):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


def _said(caplog, beginning):
    return [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith(beginning)
    ]


# -- the log forwarder by itself ----------------------------------------------


@pytest.mark.asyncio
async def test_the_forwarder_stops_while_a_write_of_its_positions_does_not_return(
    host, gateway, disk, caplog
):
    forwarder = LogForwarder(_config(host, files=False), asyncio.Queue())
    disk.watch(forwarder.positions)
    stuck = disk.stops_answering(forwarder.positions)

    await forwarder.start()
    # The periodic write is in its thread, with the store's lock.
    await _until(stuck.is_set)
    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        # main: the stop asked for the lock in the event loop, and never
        # came back.
        await asyncio.wait_for(forwarder.stop(), timeout=30)

    assert disk.written_on_the_loop == []
    assert _said(caplog, "The log positions were not written within") == [
        "The log positions were not written within 0 seconds of the log "
        f"forwarder's stop: a write to {host[0]} has not ended"
    ]
    # Still to be written: whoever asks next writes them.
    assert forwarder._positions_dirty is True
    assert forwarder.running is False


@pytest.mark.asyncio
async def test_the_positions_are_written_in_a_worker_thread_at_the_stop_too(
    host, gateway, disk
):
    forwarder = LogForwarder(_config(host, files=False), asyncio.Queue())
    disk.watch(forwarder.positions)

    await forwarder.start()
    await asyncio.wait_for(forwarder.stop(), timeout=30)

    # Written, and by a thread that is not the loop's.
    saved = json.loads((host[0] / STATE_FILE).read_text())
    assert list(saved["sources"]) == ["app"]
    assert disk.writers and disk.written_on_the_loop == []


# -- the agent's last writes --------------------------------------------------


async def _delivering_agent(host, gateway, disk):
    """A started agent whose two collectors have each had an event
    accepted, with both stores watched."""
    data_dir, log, watched = host
    agent = SecuritySensorAgent(_config(host))
    asked = []
    agent.before_last_writes = lambda: asked.append(
        (agent.log_forwarder.running, agent.data_forwarder.running)
    )
    await agent.start()
    disk.watch(agent.log_forwarder.positions)
    disk.watch(agent.file_monitor.baseline)
    await _until(lambda: (data_dir / BASELINE_FILE).exists())
    (watched / "hosts").write_text("203.0.113.9 localhost\n")
    await _until(
        lambda: {event["type"] for event in gateway} >= {"log.app", "file_modified"}
    )
    return agent, asked


@pytest.mark.asyncio
async def test_the_agent_stops_and_says_what_was_not_written(
    host, gateway, disk, caplog
):
    agent, asked = await _delivering_agent(host, gateway, disk)
    positions = disk.stops_answering(agent.log_forwarder.positions)
    baseline = disk.stops_answering(agent.file_monitor.baseline)
    # Something more to write, for each: the periodic writes go to their
    # threads and stay there.
    with host[1].open("a") as log:
        log.write("two\n")
    (host[2] / "hosts").write_text("198.51.100.7 localhost\n")
    await _until(lambda: positions.is_set() and baseline.is_set())

    with caplog.at_level(logging.WARNING):
        # main: never; the loop itself waited for the lock.
        await asyncio.wait_for(agent.stop(), timeout=30)

    assert disk.written_on_the_loop == []
    # Said once by each collector as it stopped, and then by the agent,
    # last, with what it means.
    assert len(_said(caplog, "The log positions were not written within")) == 1
    assert len(_said(caplog, "The file monitor's baseline was not written")) == 1
    assert [record.getMessage() for record in caplog.records][-2:] == [
        "Stopped without writing the log positions: the write had not ended "
        "after 0 seconds, and is left to its thread. If that stays so, after "
        "the restart the log sources are read from the positions last saved, "
        "and what was delivered since is sent again",
        "Stopped without writing the file monitor's baseline: the write had "
        "not ended after 0 seconds, and is left to its thread. If that stays "
        "so, after the restart the watched files are compared with the "
        "baseline last saved, and the changes delivered since are reported "
        "again",
    ]
    # The exit limit was asked for once, when everything else had stopped.
    assert asked == [(False, False)]


@pytest.mark.asyncio
async def test_a_write_that_fails_at_the_stop_is_said_with_its_reason(
    host, gateway, disk, caplog
):
    agent, _ = await _delivering_agent(host, gateway, disk)
    disk.is_full(agent.log_forwarder.positions)
    with host[1].open("a") as log:
        log.write("two\n")
    # The periodic write fails, and says so once, as it always did.
    await _until(lambda: agent.log_forwarder.positions.problem is not None)

    with caplog.at_level(logging.WARNING):
        await asyncio.wait_for(agent.stop(), timeout=30)

    # main: nothing at the stop; the one error was wherever in the log the
    # disk had filled up.
    assert _said(caplog, "Stopped without writing") == [
        "Stopped without writing the log positions: the log positions cannot "
        f"be saved in {host[0]}: No space left on device. If that stays so, "
        "after the restart the log sources are read from the positions last "
        "saved, and what was delivered since is sent again"
    ]


@pytest.mark.asyncio
async def test_a_stop_that_writes_both_says_nothing_and_leaves_them_on_disk(
    host, gateway, disk, caplog
):
    agent, asked = await _delivering_agent(host, gateway, disk)
    log_size = host[1].stat().st_size

    with caplog.at_level(logging.WARNING):
        await asyncio.wait_for(agent.stop(), timeout=30)

    assert _said(caplog, "Stopped without writing") == []
    assert disk.written_on_the_loop == [] and disk.writers
    assert asked == [(False, False)]
    positions = json.loads((host[0] / STATE_FILE).read_text())["sources"]["app"]
    assert [entry["offset"] for entry in positions["files"]] == [log_size]
    baseline = json.loads((host[0] / BASELINE_FILE).read_text())
    assert [Path(path).name for path in baseline["files"]] == ["hosts"]


@pytest.mark.asyncio
async def test_an_agent_with_nothing_to_write_does_not_ask_for_the_limit(gateway):
    agent = SecuritySensorAgent(
        SensorConfig(
            data_lake=DataLakeConfig(
                endpoint="https://gateway.example", api_key=API_KEY
            ),
            collection=CollectionConfig(
                process_events=False,
                network_connections=False,
                file_monitoring=False,
                user_events=False,
                system_inventory=False,
                log_forwarding=False,
            ),
            fim=FIMConfig(enabled=False),
            network=NetworkConfig(enable_api=False),
        )
    )
    asked = []
    agent.before_last_writes = lambda: asked.append(True)

    await agent.start()
    await asyncio.wait_for(agent.stop(), timeout=30)

    assert asked == []
