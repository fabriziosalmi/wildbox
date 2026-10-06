"""The file monitor says what it watches, and when that is nothing (#725).

The shipped container configuration lists ``/host/etc``, ``/host/bin``,
``/host/usr/bin`` and ``/host/opt``, and no compose file mounts them. The
monitor logged a debug-level skip for each, "started successfully" and a
status of ``running: true`` over an empty list: file-integrity monitoring
that watched nothing and looked healthy.

Real directories and files; the monitor is driven one scan at a time.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import file_monitor  # noqa: E402
from sensor.collectors.file_monitor import FileMonitor  # noqa: E402
from sensor.core.config import DataLakeConfig, FIMConfig, SensorConfig  # noqa: E402


def _config(*paths):
    return SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        fim=FIMConfig(enabled=True, paths=[str(path) for path in paths]),
    )


def _monitor(*paths):
    return FileMonitor(_config(*paths), asyncio.Queue())


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
    """start() launches the periodic scan; the tests scan by hand."""
    monkeypatch.setattr(file_monitor, "SCAN_INTERVAL", 3600)


@pytest.mark.asyncio
async def test_no_configured_path_exists_the_monitor_says_it_watches_nothing(
    tmp_path, caplog
):
    paths = [tmp_path / "host" / name for name in ("etc", "bin", "usr/bin", "opt")]
    monitor = _monitor(*paths)

    with caplog.at_level(logging.INFO, logger=file_monitor.__name__):
        await monitor.start()
        status = monitor.get_status()
        await monitor.stop()

    warnings = _warnings(caplog)
    # Each missing path, by name, and then the sum of it.
    for path in paths:
        assert any(
            message.startswith(
                f"File integrity monitoring: {path} does not exist and is not watched"
            )
            for message in warnings
        )
    assert warnings[-1] == (
        "File integrity monitoring is enabled and none of the 4 paths in "
        "fim.paths exists: it is watching nothing"
    )
    assert len(warnings) == 5
    # main: "File integrity monitor started successfully".
    assert "File integrity monitor started: watching nothing" in caplog.text
    assert "started successfully" not in caplog.text
    assert status["running"] is True
    assert status["watching"] is False
    assert status["monitored_paths"] == []
    assert status["missing_paths"] == [str(path) for path in paths]
    assert status["configured_paths"] == [str(path) for path in paths]
    assert status["tracked_files"] == 0


@pytest.mark.asyncio
async def test_a_missing_path_among_existing_ones_is_named_and_the_rest_is_watched(
    tmp_path, caplog
):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "passwd").write_text("root:x:0:0\n")
    absent = tmp_path / "opt"
    monitor = _monitor(etc, absent)

    with caplog.at_level(logging.INFO, logger=file_monitor.__name__):
        await monitor.start()
        (etc / "passwd").write_text("root:x:0:0\nintruder:x:0:0\n")
        (etc / "cron.d").mkdir()
        (etc / "cron.d" / "job").write_text("* * * * * root true\n")
        changes = await monitor._scan_once()
        status = monitor.get_status()
        await monitor.stop()

    (warning,) = _warnings(caplog)
    assert warning.startswith(f"File integrity monitoring: {absent} does not exist")
    assert f"File integrity monitor started: watching {etc}" in caplog.text
    assert changes == 2
    assert _events(monitor) == [
        ("file_created", str(etc / "cron.d" / "job")),
        ("file_modified", str(etc / "passwd")),
    ]
    assert status["watching"] is True
    assert status["monitored_paths"] == [str(etc)]
    assert status["missing_paths"] == [str(absent)]
    assert status["tracked_files"] == 2
    assert status["scan_count"] == 1


@pytest.mark.asyncio
async def test_a_path_that_appears_is_watched_from_then_on_without_a_flood(
    tmp_path, caplog
):
    late = tmp_path / "host" / "etc"
    monitor = _monitor(late)
    await monitor.start()
    assert monitor.get_status()["watching"] is False

    # The directory is mounted while the sensor runs, with what it holds.
    late.mkdir(parents=True)
    for index in range(50):
        (late / f"file-{index}").write_text(str(index))
    with caplog.at_level(logging.INFO, logger=file_monitor.__name__):
        first = await monitor._scan_once()
    status = monitor.get_status()
    (late / "file-7").write_text("changed")
    (late / "new").write_text("new")
    second = await monitor._scan_once()
    await monitor.stop()

    # Its files are the baseline, not fifty creations.
    assert first == 0
    assert f"{late} exists now and is watched (50 files)" in caplog.text
    assert status["watching"] is True
    assert status["missing_paths"] == []
    assert status["monitored_paths"] == [str(late)]
    assert second == 2
    assert _events(monitor) == [
        ("file_created", str(late / "new")),
        ("file_modified", str(late / "file-7")),
    ]


@pytest.mark.asyncio
async def test_a_watched_path_that_goes_is_reported_until_it_is_back(tmp_path, caplog):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "hosts").write_text("127.0.0.1 localhost\n")
    monitor = _monitor(etc)
    await monitor.start()

    os.rename(etc, tmp_path / "moved")
    with caplog.at_level(logging.INFO, logger=file_monitor.__name__):
        await monitor._scan_once()
        await monitor._scan_once()
        gone = monitor.get_status()
        os.rename(tmp_path / "moved", etc)
        (etc / "hosts").write_text("127.0.0.1 localhost\n203.0.113.9 update.example\n")
        changes = await monitor._scan_once()
    await monitor.stop()

    assert gone["watching"] is False
    assert gone["missing_paths"] == [str(etc)]
    assert gone["monitored_paths"] == []
    # Said once, not at every scan.
    assert _warnings(caplog) == [
        f"File integrity monitoring: {etc} no longer exists: nothing under it "
        f"is watched until it is back"
    ]
    assert f"{etc} is back" in caplog.text
    # And what changed meanwhile is a change, not a new baseline.
    assert changes == 1
    assert _events(monitor) == [("file_modified", str(etc / "hosts"))]
    assert monitor.get_status()["missing_paths"] == []


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="root reads a file whatever its mode",
)
@pytest.mark.asyncio
async def test_a_file_the_sensor_cannot_read_is_watched_without_a_hash_and_counted(
    tmp_path,
):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "hosts").write_text("readable\n")
    shadow = etc / "shadow"
    shadow.write_text("root:$6$hash\n")
    shadow.chmod(0o000)
    monitor = _monitor(etc)
    try:
        await monitor.start()
        status = monitor.get_status()
        # Its mode changes: seen, without reading it.
        shadow.chmod(0o200)
        changes = await monitor._scan_once()
    finally:
        shadow.chmod(0o600)
        await monitor.stop()

    assert status["tracked_files"] == 2
    assert status["unhashed_files"] == 1
    assert monitor.file_states[str(shadow)]["hash"] is None
    assert monitor.file_states[str(etc / "hosts")]["hash"]
    assert changes == 1
    (event,) = [e for e in _events(monitor)]
    assert event == ("file_modified", str(shadow))


def test_a_path_listed_twice_is_one_path(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    monitor = _monitor(etc, etc, tmp_path / "absent", tmp_path / "absent")

    status = monitor.get_status()

    assert status["configured_paths"] == [str(etc), str(tmp_path / "absent")]
    assert status["missing_paths"] == [str(tmp_path / "absent")]


@pytest.mark.parametrize(
    "paths", ["/etc", ["etc"], ["/etc", 5], [None], {"/etc": True}, None]
)
def test_fim_paths_must_be_a_list_of_absolute_paths(paths):
    config = _config()
    config.fim.paths = paths

    (error,) = config.validate()

    # A string would be watched one character at a time: "/", "e", "t", "c".
    assert error.startswith("fim.paths must be a list of absolute paths")


def test_an_empty_list_is_still_refused_and_a_missing_path_is_not_an_error(tmp_path):
    config = _config()
    assert config.validate() == ["fim.paths cannot be empty when FIM is enabled"]
    config.fim.enabled = False
    assert config.validate() == []
    # Whether a path exists changes while the sensor runs: the monitor
    # reports it, the configuration does not refuse it.
    assert _config(tmp_path / "not" / "mounted").validate() == []


def test_the_container_configuration_and_the_documents_agree_about_what_is_mounted():
    """The shipped paths are under /host, which nothing mounts by default:
    the configuration, the compose file and the README must all say so, and
    the README must show the mount that makes them real."""
    for name in ("config.yaml.example", "config.docker.yaml"):
        text = (SERVICE_ROOT / name).read_text()
        paths = yaml.safe_load(text)["fim"]["paths"]
        assert paths and all(path.startswith("/host/") for path in paths), name
        comments = " ".join(text.replace("#", " ").split())
        assert "no compose file mounts them" in comments, name

    mounted = []
    for compose in (
        SERVICE_ROOT / "docker-compose.yml",
        SERVICE_ROOT.parent / "docker-compose.yml",
    ):
        sensor = yaml.safe_load(compose.read_text())["services"]["sensor"]
        mounted += [
            volume.split(":")[1]
            for volume in sensor["volumes"]
            if isinstance(volume, str) and volume.split(":")[1].startswith("/host")
        ]
    # Host metrics only: none of the file monitor's paths, nor a parent.
    assert sorted(set(mounted)) == [
        "/host/proc/loadavg",
        "/host/proc/meminfo",
        "/host/proc/stat",
        "/host/sys/class/net",
    ]

    readme = (SERVICE_ROOT / "README.md").read_text()
    assert "## File integrity monitoring" in readme
    assert "- /etc:/host/etc:ro" in readme
    assert "it is watching nothing" in readme
