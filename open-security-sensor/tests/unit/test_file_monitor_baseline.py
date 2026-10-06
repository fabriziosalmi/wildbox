"""The file monitor's baseline outlives the sensor (#745).

The baseline was in memory only. A sensor that started took whatever it
found as normal: a file changed, added or removed while it was stopped (an
upgrade, a crash, a host reboot, someone who stops it first) was never
reported.

It is now saved under ``data_dir``, and it is what the data service has
been told, not what the monitor last saw: a change that was found and not
delivered is found again.

Real directories and files, a real baseline file; the monitor is driven one
scan at a time, and the pipeline tests run the real processor and sender
against a stand-in for the gateway.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import baseline_store, file_monitor  # noqa: E402
from sensor.collectors.baseline_store import BASELINE_FILE  # noqa: E402
from sensor.collectors.file_monitor import FileMonitor  # noqa: E402
from sensor.core.agent import SecuritySensorAgent  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    FIMConfig,
    SensorConfig,
)
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import RETRY, SENT, DataForwarder  # noqa: E402
from sensor.pipeline.data_processor import DataProcessor  # noqa: E402
from sensor.pipeline.delivery import take_delivery  # noqa: E402
from sensor.utils import state_file  # noqa: E402

API_KEY = "wsk_test.0123456789abcdef"


def _config(data_dir, *paths, api_key="", **fim):
    return SensorConfig(
        data_lake=DataLakeConfig(
            endpoint="https://gateway.example",
            api_key=api_key,
            batch_size=100,
            flush_interval=1,
        ),
        collection=CollectionConfig(
            process_events=False,
            network_connections=False,
            file_monitoring=True,
            user_events=False,
            system_inventory=False,
            log_forwarding=False,
        ),
        fim=FIMConfig(enabled=True, paths=[str(path) for path in paths], **fim),
        data_dir=str(data_dir) if data_dir else None,
    )


def _monitor(data_dir, *paths, **fim):
    return FileMonitor(_config(data_dir, *paths, **fim), asyncio.Queue())


def _take(monitor):
    """The queued events, oldest first, each with its Delivery."""
    taken = []
    while not monitor.event_queue.empty():
        event = monitor.event_queue.get_nowait()
        taken.append(
            (event["type"], event["data"]["path"], take_delivery(event), event)
        )
    return taken


def _kinds(taken):
    return sorted((kind, path) for kind, path, _, _ in taken)


def _saved(data_dir):
    return json.loads((data_dir / BASELINE_FILE).read_text())


async def _run(data_dir, *paths, settle=True, **fim):
    """One life of the sensor: start, take what the first scan reports,
    stop. Its events are accepted, unless ``settle`` is False."""
    monitor = _monitor(data_dir, *paths, **fim)
    await monitor.start()
    taken = _take(monitor)
    if settle:
        for _, _, delivery, _ in taken:
            delivery.settle()
    await monitor.stop()
    return monitor, taken


@pytest.fixture(autouse=True)
def no_background_scan(monkeypatch):
    """The tests scan, and save, by hand."""
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
    (directory / "hosts").write_text("127.0.0.1 localhost\n")
    (directory / "passwd").write_text("root:x:0:0\n")
    (directory / "motd").write_text("welcome\n")
    return directory


@pytest.mark.asyncio
async def test_the_first_start_takes_what_it_finds_and_saves_it(data_dir, etc):
    monitor, taken = await _run(data_dir, etc)

    assert taken == []
    saved = _saved(data_dir)
    assert saved["roots"] == [str(etc)]
    assert sorted(saved["files"]) == sorted(
        str(etc / name) for name in ("hosts", "motd", "passwd")
    )
    assert saved["watch"] == {
        "exclude_patterns": ["*.tmp", "*.log", "*.cache", "*.pid"],
        "max_depth": 10,
        "max_files": 50000,
    }
    # Sizes, times, modes, owners and digests: no content.
    assert "root:x:0:0" not in (data_dir / BASELINE_FILE).read_text()
    status = monitor.get_status()["baseline"]
    assert status["persisted"] is True
    assert status["file"] == str(data_dir / BASELINE_FILE)
    assert status["loaded"] == "none was saved yet"
    assert status["last_saved"] == saved["saved_at"]
    assert status["problem"] is None
    assert status["changes_not_delivered"] == 0


@pytest.mark.asyncio
async def test_the_first_baseline_is_on_disk_when_the_monitor_has_started(
    data_dir, etc
):
    monitor = _monitor(data_dir, etc)

    await monitor.start()
    try:
        # Not five seconds later: a sensor killed meanwhile has one.
        assert len(_saved(data_dir)["files"]) == 3
    finally:
        await monitor.stop()


@pytest.mark.asyncio
async def test_what_changed_while_the_sensor_was_stopped_is_reported_at_start(
    data_dir, etc, caplog
):
    first, _ = await _run(data_dir, etc)
    saved_at = _saved(data_dir)["saved_at"]

    # The sensor is not running.
    (etc / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")
    (etc / "cron.d").mkdir()
    (etc / "cron.d" / "job").write_text("* * * * * root true\n")
    os.unlink(etc / "motd")

    with caplog.at_level(logging.INFO, logger=file_monitor.__name__):
        second, taken = await _run(data_dir, etc)

    # main: nothing. What it found was the new normal.
    assert _kinds(taken) == [
        ("file_created", str(etc / "cron.d" / "job")),
        ("file_deleted", str(etc / "motd")),
        ("file_modified", str(etc / "passwd")),
    ]
    modified = [event for kind, _, _, event in taken if kind == "file_modified"][0]
    assert modified["data"]["changes"] == ["size", "mtime", "content"]
    assert (
        modified["data"]["old_hash"] == first.file_states[str(etc / "passwd")]["hash"]
    )
    assert modified["metadata"]["severity"] == "high"
    assert (
        f"comparing {etc} with the baseline saved at {saved_at} (3 files)"
        in caplog.text
    )
    assert "3 changes since the saved baseline" in caplog.text
    assert second.get_status()["baseline"]["loaded"] == f"saved at {saved_at}"

    # Told once: the third start has nothing to say.
    _, again = await _run(data_dir, etc)
    assert again == []


@pytest.mark.asyncio
async def test_a_change_that_was_not_delivered_is_reported_again(data_dir, etc):
    monitor = _monitor(data_dir, etc)
    await monitor.start()
    (etc / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")
    (etc / "hosts").write_text("127.0.0.1 localhost\n203.0.113.9 update\n")
    assert await monitor._scan_once() == 2
    taken = _take(monitor)
    assert monitor.get_status()["baseline"]["changes_not_delivered"] == 2
    # The gateway took the first, and the sensor stops before it takes the
    # second.
    by_path = {path: delivery for _, path, delivery, _ in taken}
    by_path[str(etc / "hosts")].settle()
    assert monitor.get_status()["baseline"]["changes_not_delivered"] == 1
    await monitor.stop()

    _, taken = await _run(data_dir, etc)

    assert _kinds(taken) == [("file_modified", str(etc / "passwd"))]
    # Within one life of the sensor a change is reported once, delivered
    # or not: only the saved baseline waits for the gateway.
    monitor = _monitor(data_dir, etc)
    await monitor.start()
    (etc / "motd").write_text("changed\n")
    assert await monitor._scan_once() == 1
    assert await monitor._scan_once() == 0
    await monitor.stop()


@pytest.mark.asyncio
async def test_a_full_queue_does_not_keep_the_sensor_from_starting(
    data_dir, etc, caplog
):
    # The first scan reports what changed while the sensor was stopped. With
    # the gateway away and the queue full, waiting for room in start() would
    # leave the whole sensor "starting" for as long as that lasts.
    await _run(data_dir, etc)
    for name in ("hosts", "motd", "passwd"):
        (etc / name).write_text("changed while stopped\n")
    (etc / "added").write_text("new\n")
    monitor = FileMonitor(_config(data_dir, etc), asyncio.Queue(maxsize=2))

    with caplog.at_level(logging.WARNING, logger=file_monitor.__name__):
        await asyncio.wait_for(monitor.start(), timeout=5)
    try:
        assert monitor.event_queue.qsize() == 2
        assert monitor.get_status()["baseline"]["changes_not_delivered"] == 4
        assert (
            "the queue is full: 2 of these changes are reported as it empties"
            in caplog.text
        )
        # The others follow as room is made.
        paths = []
        for _ in range(4):
            event = await asyncio.wait_for(monitor.event_queue.get(), timeout=5)
            paths.append(event["data"]["path"])
            take_delivery(event).settle()
        await asyncio.sleep(0.05)
        assert monitor.event_queue.empty()
    finally:
        await monitor.stop()

    assert sorted(paths) == [
        str(etc / name) for name in ("added", "hosts", "motd", "passwd")
    ]
    assert monitor.get_status()["baseline"]["changes_not_delivered"] == 0
    _, again = await _run(data_dir, etc)
    assert again == []


@pytest.mark.asyncio
async def test_changes_left_for_later_when_the_sensor_stops_are_found_again(
    data_dir, etc
):
    await _run(data_dir, etc)
    for name in ("hosts", "motd", "passwd"):
        (etc / name).write_text("changed while stopped\n")
    monitor = FileMonitor(_config(data_dir, etc), asyncio.Queue(maxsize=1))

    await asyncio.wait_for(monitor.start(), timeout=5)
    await asyncio.wait_for(monitor.stop(), timeout=5)

    # One was queued and not delivered, two never left the monitor.
    assert monitor.event_queue.qsize() == 1
    _, taken = await _run(data_dir, etc)
    assert _kinds(taken) == [
        ("file_modified", str(etc / name)) for name in ("hosts", "motd", "passwd")
    ]


@pytest.mark.asyncio
async def test_events_can_be_read_again_only_with_a_saved_baseline(data_dir, etc):
    for directory, replayable in ((data_dir, True), (None, False)):
        monitor = _monitor(directory, etc)
        await monitor.start()
        (etc / "motd").write_text(f"changed {replayable}\n")
        await monitor._scan_once()
        ((_, _, delivery, event),) = _take(monitor)
        await monitor.stop()

        # What the sender counts at stop: returned to its source, or lost.
        assert delivery.replayable is replayable
        assert "_delivery" not in event


@pytest.mark.asyncio
async def test_two_changes_of_one_file_settled_in_either_order(data_dir, etc):
    for order in ((0, 1), (1, 0)):
        monitor = _monitor(data_dir, etc)
        await monitor.start()
        _take(monitor)
        (etc / "motd").write_text(f"first {order}\n")
        await monitor._scan_once()
        (etc / "motd").write_text(f"second, and longer {order}\n")
        await monitor._scan_once()
        taken = _take(monitor)
        assert [kind for kind, _, _, _ in taken] == ["file_modified"] * 2
        for index in order:
            taken[index][2].settle()
        assert monitor.get_status()["baseline"]["changes_not_delivered"] == 0
        await monitor.stop()

        # The baseline is the later state, whichever was accepted last.
        assert _saved(data_dir)["files"][str(etc / "motd")]["size"] == len(
            f"second, and longer {order}\n"
        )
        _, again = await _run(data_dir, etc)
        assert again == []


@pytest.mark.asyncio
async def test_only_the_first_of_two_changes_delivered_the_second_is_reported_again(
    data_dir, etc
):
    monitor = _monitor(data_dir, etc)
    await monitor.start()
    (etc / "motd").write_text("first\n")
    await monitor._scan_once()
    (etc / "motd").write_text("second, and longer\n")
    await monitor._scan_once()
    first, second = _take(monitor)
    first[2].settle()
    await monitor.stop()

    _, taken = await _run(data_dir, etc)

    ((kind, path, _, event),) = taken
    assert (kind, path) == ("file_modified", str(etc / "motd"))
    # From what the data service knows, to what is there.
    assert event["data"]["old_size"] == len("first\n")
    assert event["data"]["new_size"] == len("second, and longer\n")


@pytest.mark.asyncio
async def test_a_deletion_and_a_creation_move_the_baseline_when_they_are_delivered(
    data_dir, etc
):
    monitor = _monitor(data_dir, etc)
    await monitor.start()
    os.unlink(etc / "motd")
    (etc / "new").write_text("new\n")
    await monitor._scan_once()
    taken = _take(monitor)
    monitor.save_baseline()
    undelivered = sorted(_saved(data_dir)["files"])
    for _, _, delivery, _ in taken:
        delivery.settle()
    assert monitor.save_baseline() is True
    assert monitor.save_baseline() is False  # nothing has moved since
    await monitor.stop()

    names = [str(etc / name) for name in ("hosts", "motd", "new", "passwd")]
    assert undelivered == [names[0], names[1], names[3]]
    assert sorted(_saved(data_dir)["files"]) == [names[0], names[2], names[3]]


@pytest.mark.asyncio
async def test_the_baseline_is_saved_while_the_monitor_runs(data_dir, etc, monkeypatch):
    monkeypatch.setattr(file_monitor, "BASELINE_SAVE_INTERVAL", 0.02)
    monitor = _monitor(data_dir, etc)
    await monitor.start()
    try:
        (etc / "motd").write_text("changed, and longer\n")
        await monitor._scan_once()
        ((_, _, delivery, _),) = _take(monitor)
        delivery.settle()
        deadline = asyncio.get_running_loop().time() + 10
        while _saved(data_dir)["files"][str(etc / "motd")]["size"] != 20:
            assert asyncio.get_running_loop().time() < deadline, "timed out"
            await asyncio.sleep(0.01)
    finally:
        await monitor.stop()


NOT_USABLE = {
    "not JSON": lambda document: "{",
    "another version": lambda document: dict(document, version=2),
    "a file under no root": lambda document: dict(
        document, files=dict(document["files"], **{"/root/.ssh/id": {}})
    ),
    "a root that is not a path": lambda document: dict(document, roots=[5]),
}


@pytest.mark.parametrize("what", sorted(NOT_USABLE))
@pytest.mark.asyncio
async def test_a_baseline_that_cannot_be_used_is_ignored_and_replaced(
    data_dir, etc, caplog, what
):
    await _run(data_dir, etc)
    broken = NOT_USABLE[what](_saved(data_dir))
    (data_dir / BASELINE_FILE).write_text(
        broken if isinstance(broken, str) else json.dumps(broken)
    )
    (etc / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")

    with caplog.at_level(logging.WARNING, logger=baseline_store.__name__):
        monitor, taken = await _run(data_dir, etc)

    # As before there was a file: what is found is the baseline. It is
    # said, because what changed meanwhile is not reported.
    assert taken == []
    (warning,) = [r.getMessage() for r in caplog.records]
    assert "is ignored" in warning
    assert monitor.get_status()["baseline"]["loaded"].startswith("ignored: ")
    saved = _saved(data_dir)
    assert saved["version"] == 1
    assert sorted(saved["files"]) == sorted(
        str(etc / name) for name in ("hosts", "motd", "passwd")
    )


@pytest.mark.asyncio
async def test_other_settings_and_the_baseline_is_taken_again(data_dir, etc, caplog):
    await _run(data_dir, etc)
    (etc / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")

    with caplog.at_level(logging.WARNING, logger=baseline_store.__name__):
        _, taken = await _run(data_dir, etc, exclude_patterns=["motd"])

    # Compared with the old baseline, motd would be a deletion that never
    # happened.
    assert taken == []
    assert "was taken with other fim settings" in caplog.text
    assert sorted(_saved(data_dir)["files"]) == [
        str(etc / "hosts"),
        str(etc / "passwd"),
    ]


@pytest.mark.asyncio
async def test_a_path_added_to_the_configuration_is_a_baseline_the_others_are_compared(
    data_dir, etc, tmp_path
):
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "tool").write_text("#!/bin/sh\n")
    await _run(data_dir, etc)
    (etc / "hosts").write_text("127.0.0.1 localhost\n203.0.113.9 update\n")

    _, taken = await _run(data_dir, etc, opt)

    assert _kinds(taken) == [("file_modified", str(etc / "hosts"))]
    saved = _saved(data_dir)
    assert saved["roots"] == sorted([str(etc), str(opt)])
    assert str(opt / "tool") in saved["files"]


@pytest.mark.asyncio
async def test_a_path_removed_from_the_configuration_leaves_the_baseline(
    data_dir, etc, tmp_path
):
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "tool").write_text("#!/bin/sh\n")
    await _run(data_dir, etc, opt)

    monitor, taken = await _run(data_dir, opt)

    assert taken == []
    assert sorted(monitor.file_states) == [str(opt / "tool")]
    # Nothing has moved, so the file is as it was; it is rewritten, without
    # the path that is gone, when something does.
    monitor = _monitor(data_dir, opt)
    await monitor.start()
    (opt / "tool").write_text("#!/bin/sh\nexit 0\n")
    await monitor._scan_once()
    for _, _, delivery, _ in _take(monitor):
        delivery.settle()
    await monitor.stop()
    saved = _saved(data_dir)
    assert saved["roots"] == [str(opt)]
    assert sorted(saved["files"]) == [str(opt / "tool")]

    # And when it is configured again it is a new path, not one compared
    # with what it held then.
    (etc / "hosts").write_text("changed\n")
    _, taken = await _run(data_dir, etc, opt)
    assert taken == []


@pytest.mark.asyncio
async def test_a_path_that_is_missing_at_start_is_compared_when_it_is_back(
    data_dir, etc, tmp_path, caplog
):
    await _run(data_dir, etc)
    # The mount is not there when the sensor starts, and comes back changed.
    os.rename(etc, tmp_path / "unmounted")

    monitor = _monitor(data_dir, etc)
    await monitor.start()
    assert _take(monitor) == []
    assert monitor.get_status()["watching"] is False
    (tmp_path / "unmounted" / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")
    os.rename(tmp_path / "unmounted", etc)
    with caplog.at_level(logging.INFO, logger=file_monitor.__name__):
        changes = await monitor._scan_once()
    taken = _take(monitor)
    await monitor.stop()

    assert changes == 1
    assert _kinds(taken) == [("file_modified", str(etc / "passwd"))]
    assert f"{etc} exists now and is watched (3 files)" in caplog.text
    # Its files stayed in the saved baseline while it was away.
    assert len(_saved(data_dir)["files"]) == 3


@pytest.mark.asyncio
async def test_without_data_dir_the_baseline_is_in_memory_and_the_status_says_so(etc):
    monitor, _ = await _run(None, etc)
    status = monitor.get_status()["baseline"]

    assert status["persisted"] is False
    assert status["file"] is None
    assert status["loaded"] == "data_dir is not set"
    assert status["problem"] == (
        "data_dir is not set: the baseline is kept in memory only, and what "
        "changes while the sensor is stopped is not reported"
    )

    (etc / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")
    _, taken = await _run(None, etc)
    assert taken == []


@pytest.mark.asyncio
async def test_a_baseline_that_cannot_be_saved_is_said_and_tried_again(
    data_dir, etc, monkeypatch, caplog
):
    real_replace = os.replace

    def no_rename(source, target):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(state_file.os, "replace", no_rename)
    monitor = _monitor(data_dir, etc)
    with caplog.at_level(logging.ERROR, logger=baseline_store.__name__):
        await monitor.start()
        assert monitor.save_baseline() is False
        assert monitor.save_baseline() is False
        failed = monitor.get_status()["baseline"]
        monkeypatch.setattr(state_file.os, "replace", real_replace)
        assert monitor.save_baseline() is True
        await monitor.stop()

    assert len(caplog.records) == 1
    assert failed["persisted"] is False
    assert failed["problem"].endswith("No space left on device")
    assert monitor.get_status()["baseline"]["persisted"] is True
    assert len(_saved(data_dir)["files"]) == 3


@pytest.mark.asyncio
async def test_a_monitor_that_did_not_start_does_not_empty_the_baseline(data_dir, etc):
    await _run(data_dir, etc)
    before = (data_dir / BASELINE_FILE).read_bytes()

    disabled = _monitor(data_dir, etc)
    disabled.config.fim.enabled = False
    await disabled.start()
    await disabled.stop()
    assert disabled.save_baseline() is False
    # Constructed and never started, as when another component fails first.
    await _monitor(data_dir, etc).stop()

    assert (data_dir / BASELINE_FILE).read_bytes() == before


# -- with the pipeline ------------------------------------------------------


class Pipeline:
    """The monitor, the processor and the sender, started as the agent
    starts them; the gateway is ``answer``."""

    def __init__(self, data_dir, *paths):
        self.config = _config(data_dir, *paths, api_key=API_KEY)
        self.accepted = []
        self.answer = SENT
        collected, processed = asyncio.Queue(maxsize=50), asyncio.Queue(maxsize=50)
        self.monitor = FileMonitor(self.config, collected)
        self.processor = DataProcessor(self.config, collected, processed)
        self.sender = DataForwarder(self.config, processed)
        self.sender.min_request_interval = 0.002

        async def no_session():
            self.sender.session = None

        async def send(body):
            if self.answer == SENT:
                self.accepted += [
                    (event["event_data"]["type"], event["event_data"]["data"]["path"])
                    for event in json.loads(body)["events"]
                ]
            return self.answer

        self.sender._init_session = no_session
        self.sender._send = send

    async def start(self):
        await self.processor.start()
        await self.sender.start()
        await self.monitor.start()

    async def stop(self):
        await self.monitor.stop()
        await self.processor.stop()
        await self.sender.stop()
        self.monitor.save_baseline()


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


@pytest.mark.asyncio
async def test_the_baseline_follows_what_the_gateway_accepts(
    data_dir, etc, monkeypatch
):
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.5)
    pipeline = Pipeline(data_dir, etc)
    await pipeline.start()
    try:
        (etc / "motd").write_text("changed\n")
        await pipeline.monitor._scan_once()
        await _until(
            lambda: pipeline.accepted == [("file_modified", str(etc / "motd"))]
        )

        # The gateway stops answering: the next change is found, waits in
        # the sender's buffer, and stays out of the baseline.
        pipeline.answer = RETRY
        (etc / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")
        await pipeline.monitor._scan_once()
        await _until(lambda: len(pipeline.sender.buffer) == 1)
        await _until(lambda: pipeline.sender.failures >= 1)
        assert pipeline.monitor.get_status()["baseline"]["changes_not_delivered"] == 1
    finally:
        await pipeline.stop()

    saved = _saved(data_dir)["files"]
    assert saved[str(etc / "motd")]["size"] == len("changed\n")
    assert saved[str(etc / "passwd")]["size"] == len("root:x:0:0\n")
    # Unsent, but not lost: the monitor finds it again.
    assert pipeline.sender.stats["events_returned_to_source"] == 1
    assert pipeline.sender.stats["events_dropped"] == 0

    # The sensor starts again and the gateway is back.
    again = Pipeline(data_dir, etc)
    await again.start()
    try:
        await _until(lambda: again.accepted == [("file_modified", str(etc / "passwd"))])
    finally:
        await again.stop()

    assert _saved(data_dir)["files"][str(etc / "passwd")]["size"] == len(
        "root:x:0:0\nintruder:x:0:0\n"
    )
    # Each change reached the data service once.
    assert pipeline.accepted + again.accepted == [
        ("file_modified", str(etc / "motd")),
        ("file_modified", str(etc / "passwd")),
    ]


@pytest.mark.asyncio
async def test_the_agent_saves_what_its_last_batches_delivered(
    data_dir, etc, monkeypatch
):
    # Stopping: the collectors first, then the sender's last batches, then
    # the baseline once more. Saved before those batches, the changes they
    # deliver would be reported again after the restart.
    accepted = []

    async def send(self, body):
        accepted.extend(
            event["event_data"]["data"]["path"] for event in json.loads(body)["events"]
        )
        return SENT

    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    config = _config(data_dir, etc, api_key=API_KEY)
    config.data_lake.flush_interval = 3600
    config.network.enable_api = False
    agent = SecuritySensorAgent(config)

    await agent.start()
    try:
        (etc / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")
        await agent.file_monitor._scan_once()
        await _until(lambda: len(agent.data_forwarder.buffer) == 1)
        assert accepted == []
    finally:
        await agent.stop()

    assert accepted == [str(etc / "passwd")]
    assert _saved(data_dir)["files"][str(etc / "passwd")]["size"] == len(
        "root:x:0:0\nintruder:x:0:0\n"
    )
    # And a sensor that starts again has nothing to report.
    _, taken = await _run(data_dir, etc)
    assert taken == []
