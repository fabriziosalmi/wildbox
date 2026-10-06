"""A change a scan found is not forgotten before its event is queued (#765).

A scan brings the monitor's own view of the files up to date and then queues
one event per change. The changes were in the scan's list and nowhere else:
when the queueing ended early, the rest of the list was gone, and no later
scan saw a difference, because the monitor's view was already past them. An
error on one change did that, and so did a stop while a change waited for
room in the queue: the changes behind it were in no count and no log line,
and were reported only by a sensor with ``data_dir``, after its restart.

Real directories and files; the scans are the monitor's own, one at a time
or from its monitoring task.
"""

import asyncio
import logging
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import file_monitor  # noqa: E402
from sensor.collectors.file_monitor import FileMonitor  # noqa: E402
from sensor.core.agent import CountingQueue  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    FIMConfig,
    SensorConfig,
)
from sensor.pipeline.delivery import take_delivery  # noqa: E402

NAMES = ("hosts", "motd", "passwd")


def _monitor(data_dir, watched, queue=None):
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        collection=CollectionConfig(file_monitoring=True),
        fim=FIMConfig(enabled=True, paths=[str(watched)]),
        data_dir=str(data_dir) if data_dir else None,
    )
    return FileMonitor(config, queue if queue is not None else asyncio.Queue())


def _take(monitor, settle=False):
    """The paths of the queued events, in the order they were queued."""
    paths = []
    while not monitor.event_queue.empty():
        event = monitor.event_queue.get_nowait()
        delivery = take_delivery(event)
        if settle:
            delivery.settle()
        paths.append(Path(event["data"]["path"]).name)
    return paths


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


def _not_delivered(monitor):
    return monitor.get_status()["baseline"]["changes_not_delivered"]


class Watched(CountingQueue):
    """A queue that says how many puts are waiting for room."""

    waiting = 0

    async def put(self, item):
        self.waiting += 1
        try:
            await super().put(item)
        finally:
            self.waiting -= 1


@pytest.fixture(autouse=True)
def by_hand(monkeypatch):
    """No scan and no save but those a test asks for."""
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 3600)
    monkeypatch.setattr(file_monitor, "BASELINE_SAVE_INTERVAL", 3600)


@pytest.fixture
def data_dir(tmp_path):
    directory = tmp_path / "data"
    directory.mkdir()
    return directory


@pytest.fixture
def etc(tmp_path):
    directory = tmp_path / "etc"
    directory.mkdir()
    for name in NAMES:
        (directory / name).write_text("as it was\n")
    return directory


def _change(etc, names=NAMES):
    for name in names:
        (etc / name).write_text("changed\n")


def _no_event_for_motd(monkeypatch):
    """The event of one file's change cannot be made; what made it before."""
    modified = FileMonitor._modified_event

    def failing(self, path, old, new, changes):
        if path.endswith("motd"):
            raise RuntimeError("no event for this one")
        return modified(self, path, old, new, changes)

    monkeypatch.setattr(FileMonitor, "_modified_event", failing)
    return modified


@pytest.fixture
def no_event_for_motd(monkeypatch):
    _no_event_for_motd(monkeypatch)


# -- an error on one change ---------------------------------------------------


@pytest.mark.asyncio
async def test_an_error_on_one_change_does_not_forget_the_changes_behind_it(
    data_dir, etc, no_event_for_motd, caplog
):
    monitor = _monitor(data_dir, etc)
    await monitor.start()
    _change(etc)

    try:
        with caplog.at_level(logging.ERROR, logger=file_monitor.__name__):
            # main: the error left the scan here, with passwd still to queue.
            assert await monitor._scan_once() == 3
        # Sorted by path: hosts, then motd, which fails, then passwd, which
        # main never reported, at this scan or at any later one.
        assert _take(monitor) == ["hosts", "passwd"]
        assert await monitor._scan_once() == 0
        assert _take(monitor) == []
    finally:
        await monitor.stop()

    assert monitor.changes_failed == 1
    assert monitor.get_status()["changes_failed"] == 1
    (said,) = [record.getMessage() for record in caplog.records]
    assert said == (
        f"File integrity monitoring: the change of {etc / 'motd'} (modified) "
        "could not be made into an event and is not reported: RuntimeError: "
        "no event for this one"
    )


@pytest.mark.asyncio
async def test_a_change_that_failed_stays_out_of_the_saved_baseline(
    data_dir, etc, monkeypatch
):
    # The baseline is what the data service has been told. It was not told
    # of this change, so a sensor that starts again finds it again.
    monitor = _monitor(data_dir, etc)
    await monitor.start()
    _change(etc)
    modified = _no_event_for_motd(monkeypatch)
    await monitor._scan_once()
    assert _take(monitor, settle=True) == ["hosts", "passwd"]
    await monitor.stop()
    monkeypatch.setattr(FileMonitor, "_modified_event", modified)

    again = _monitor(data_dir, etc)
    await again.start()
    try:
        assert _take(again, settle=True) == ["motd"]
    finally:
        await again.stop()


@pytest.mark.asyncio
async def test_the_monitoring_task_goes_on_after_a_change_that_failed(
    data_dir, etc, no_event_for_motd, monkeypatch
):
    # The whole loop, as the sensor runs it: main logged "Error in file
    # monitoring loop", slept 30 seconds, and passwd was gone for good.
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 0.02)
    monitor = _monitor(data_dir, etc)
    await monitor.start()
    try:
        _change(etc)
        await _until(lambda: monitor.event_queue.qsize() == 2, timeout=5)
        assert _take(monitor) == ["hosts", "passwd"]
        (etc / "hosts").write_text("changed again, and longer\n")
        await _until(lambda: monitor.event_queue.qsize() == 1, timeout=5)
        assert _take(monitor) == ["hosts"]
    finally:
        await monitor.stop()


# -- a stop while a change waits for room -------------------------------------


async def _stopped_while_queueing(data_dir, etc, monkeypatch, caplog):
    """A monitor whose scan found three changes while the queue had room
    for one, stopped there; what it said when it stopped."""
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 0.02)
    monitor = _monitor(data_dir, etc, Watched(maxsize=1))
    await monitor.start()
    _change(etc)
    await _until(lambda: monitor.event_queue.waiting == 1, timeout=5)
    for _ in range(50):
        await asyncio.sleep(0)

    # One event on the queue, one waiting for room, one change with no
    # event yet. main: 2, the third was in the scan's list and nowhere else.
    assert _not_delivered(monitor) == 3
    with caplog.at_level(logging.WARNING, logger=file_monitor.__name__):
        await asyncio.wait_for(monitor.stop(), timeout=5)
    return monitor, [record.getMessage() for record in caplog.records]


@pytest.mark.asyncio
async def test_a_stop_while_a_change_waits_for_room_says_what_was_behind_it(
    data_dir, etc, monkeypatch, caplog
):
    monitor, said = await _stopped_while_queueing(data_dir, etc, monkeypatch, caplog)

    assert _take(monitor) == ["hosts"]
    # The one in put() is the queue's: the agent counts it with the events
    # that had not reached the sender.
    (turned_away,) = monitor.event_queue.turned_away
    assert turned_away["data"]["path"] == str(etc / "motd")
    # The one behind it never became an event, and is said as what it is.
    assert said == [
        "File integrity monitoring: stopped with 1 changes found and not "
        "queued yet: they are not in the saved baseline, and are found again "
        "when the sensor starts"
    ]

    # And they are: none of the three was delivered.
    again = _monitor(data_dir, etc)
    await again.start()
    try:
        assert sorted(_take(again, settle=True)) == sorted(NAMES)
    finally:
        await again.stop()


@pytest.mark.asyncio
async def test_without_data_dir_the_changes_behind_it_are_said_to_be_lost(
    etc, monkeypatch, caplog
):
    monitor, said = await _stopped_while_queueing(None, etc, monkeypatch, caplog)

    assert len(monitor.event_queue.turned_away) == 1
    assert said == [
        "File integrity monitoring: stopped with 1 changes found and not "
        "queued yet: they are not reported. data_dir is not set, so the next "
        "start takes what it finds as its baseline"
    ]
