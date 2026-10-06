"""What the osquery manager runs is what answers (#745).

Three of its queries read osquery's event tables through ``osqueryi``. In the
sensor's image each answers ``[]`` and says, on standard error::

    Table process_events is event-based but events are disabled

so the sensor ran them at every cycle for nothing. And it started an
``osqueryd`` whose results nothing read, reported as ``process_alive``.

``osqueryi`` and ``osqueryd`` are played by scripts of those names put first
on ``PATH``: real child processes, which record that they ran.
"""

import asyncio
import json
import os
import re
import stat
import sys
import time
import types
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import osquery_manager  # noqa: E402
from sensor.collectors.osquery_manager import OsqueryManager  # noqa: E402
from sensor.core.agent import CountingQueue  # noqa: E402
from sensor.core.config import (  # noqa: E402
    DataLakeConfig,
    PerformanceConfig,
    SensorConfig,
    load_config,
)

OSQUERYI = """#!{python}
import json, os, sys, time

query = sys.argv[-1]
with open(os.environ["OSQUERY_RECORD"], "a") as handle:
    handle.write(json.dumps({{"program": "osqueryi", "pid": os.getpid(), "query": query}}) + "\\n")
if os.path.exists(os.environ["OSQUERY_BROKEN"]):
    sys.stderr.write("Error: cannot open the database\\n")
    sys.exit(1)
failing = os.environ["OSQUERY_FAILING"]
if os.path.exists(failing) and open(failing).read().strip() in query:
    sys.stderr.write("Error: no such table\\n")
    sys.exit(1)
if os.path.exists(os.environ["OSQUERY_SLOW"]):
    time.sleep(60)
if "osquery_info" in query:
    print(json.dumps([{{"version": "5.10.2"}}]))
else:
    print(json.dumps([{{"answer": "a row"}}]))
"""

OSQUERYD = """#!{python}
import json, os, time

with open(os.environ["OSQUERY_RECORD"], "a") as handle:
    handle.write(json.dumps({{"program": "osqueryd", "pid": os.getpid()}}) + "\\n")
time.sleep(60)
"""

LINUX_PACKS = {
    "process_events": ["process_tree"],
    "network": ["process_open_sockets"],
    "user_events": ["logged_in_users", "sudoers"],
    "system_inventory": [
        "installed_applications",
        "kernel_info",
        "kernel_modules",
        "os_version",
        "startup_items",
        "system_info",
        "system_services",
    ],
}


@pytest.fixture
def osquery(tmp_path, monkeypatch):
    """A manager on a Linux whose osquery is the scripts above."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in (("osqueryi", OSQUERYI), ("osqueryd", OSQUERYD)):
        script = bin_dir / name
        script.write_text(text.format(python=sys.executable))
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    record = tmp_path / "record.jsonl"
    record.write_text("")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("OSQUERY_RECORD", str(record))
    monkeypatch.setenv("OSQUERY_BROKEN", str(tmp_path / "broken"))
    monkeypatch.setenv("OSQUERY_SLOW", str(tmp_path / "slow"))
    monkeypatch.setenv("OSQUERY_FAILING", str(tmp_path / "failing"))
    manager = _manager_on(monkeypatch, "linux", query_interval=3600)
    return manager, record, tmp_path


def _manager_on(monkeypatch, platform, **performance):
    """A manager that takes the host for ``platform``."""
    for name in ("linux", "windows", "macos"):
        monkeypatch.setattr(
            osquery_manager, f"is_{name}", lambda answer=(name == platform): answer
        )
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        performance=PerformanceConfig(**performance),
    )
    return OsqueryManager(config, asyncio.Queue())


def _recorded(record):
    return [json.loads(line) for line in record.read_text().splitlines()]


def _gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


async def _until(condition, seconds=10):
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.01)


def _tables(query):
    return set(re.findall(r"\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_]*)", query, re.I))


def test_the_packs_are_the_queries_that_answer(osquery):
    manager, _, _ = osquery

    packs = {
        name: sorted(pack["queries"]) for name, pack in manager.query_packs.items()
    }

    # main: also process_events.process_events, network.socket_events and
    # user_events.user_events.
    assert packs == LINUX_PACKS
    assert manager.get_status()["total_queries"] == 11


@pytest.mark.parametrize("platform", ["linux", "windows", "macos"])
def test_no_query_reads_an_event_table(monkeypatch, platform):
    # main, on Windows: user_events.logon_events read windows_events, an
    # event table as the three others were, and filtered on a column it does
    # not have (#754).
    manager = _manager_on(monkeypatch, platform)

    for pack in manager.query_packs.values():
        for name, query in pack["queries"].items():
            tables = _tables(query["query"])
            assert tables, name
            assert not {table for table in tables if table.endswith("_events")}, name


def test_on_windows_the_users_pack_is_the_users_logged_in(monkeypatch):
    manager = _manager_on(monkeypatch, "windows")

    assert sorted(manager.query_packs["user_events"]["queries"]) == ["logged_in_users"]


def test_a_query_has_no_interval_of_its_own(osquery):
    # Each had one, for the schedule of the osqueryd that is gone, and the
    # sensor's cycle never looked at it. The inventory pack has one now,
    # which the cycle does look at (#754); the queries still have none.
    manager, _, _ = osquery

    for pack in manager.query_packs.values():
        for name, query in pack["queries"].items():
            assert set(query) == {"query", "description"}, name
    assert {name: pack.get("interval") for name, pack in manager.query_packs.items()} == {
        "process_events": None,
        "network": None,
        "user_events": None,
        "system_inventory": 3600,
    }


def _asked(record, table):
    """How many times the cycle asked the query that reads ``table``."""
    return sum(
        1
        for entry in _recorded(record)
        if re.search(rf"\bFROM {table}\b", entry["query"])
    )


# Seconds the cycle tests below wait for: each query is a process to start,
# a few dozen in a test, and a loaded host starts two or three a second.
PATIENCE = 90

INVENTORY_TABLES = (
    "system_info",
    "os_version",
    "deb_packages",
    "startup_items",
    "systemd_units",
    "kernel_info",
    "kernel_modules",
)


@pytest.mark.asyncio
async def test_the_inventory_is_not_asked_at_every_cycle(osquery):
    # main: all eleven queries at every cycle, the inventory's seven among
    # them, which answer the same thing for hours.
    manager, record, _ = osquery
    manager.config.performance.query_interval = 0.01

    await manager.start()
    try:
        # The last query of the packs that have no interval.
        await _until(lambda: _asked(record, "sudoers") >= 3, PATIENCE)
    finally:
        await manager.stop()

    assert _asked(record, "processes p") >= 3
    assert _asked(record, "process_open_sockets s") >= 3
    assert _asked(record, "logged_in_users") >= 3
    assert {table: _asked(record, table) for table in INVENTORY_TABLES} == dict.fromkeys(
        INVENTORY_TABLES, 1
    )
    # Its first answers are events like the others'.
    types = set()
    while not manager.event_queue.empty():
        types.add(manager.event_queue.get_nowait()["type"])
    assert {f"system_inventory.{query}" for query in LINUX_PACKS["system_inventory"]} <= types


@pytest.mark.asyncio
async def test_the_inventory_is_asked_again_when_its_interval_has_passed(
    monkeypatch, osquery
):
    _, record, _ = osquery
    manager = _manager_on(
        monkeypatch, "linux", query_interval=0.01, inventory_interval=900
    )
    # The manager's clock, moved by the test.
    now = [5000.0]
    monkeypatch.setattr(
        osquery_manager, "time", types.SimpleNamespace(monotonic=lambda: now[0])
    )

    async def two_more_cycles():
        # Two ends of a cycle: the second cycle began after this was called.
        asked = _asked(record, "sudoers")
        await _until(lambda: _asked(record, "sudoers") >= asked + 2, PATIENCE)

    await manager.start()
    try:
        await _until(lambda: _asked(record, "kernel_modules") == 1, PATIENCE)
        now[0] += 899
        await two_more_cycles()
        assert _asked(record, "kernel_info") == 1
        now[0] += 1
        await _until(lambda: _asked(record, "kernel_modules") == 2, PATIENCE)
        # Counted again from those answers: not at the next cycles.
        await two_more_cycles()
    finally:
        await manager.stop()

    assert {table: _asked(record, table) for table in INVENTORY_TABLES} == dict.fromkeys(
        INVENTORY_TABLES, 2
    )


@pytest.mark.asyncio
async def test_an_interval_of_zero_asks_the_inventory_at_every_cycle(monkeypatch, osquery):
    _, record, _ = osquery
    manager = _manager_on(monkeypatch, "linux", query_interval=0.01, inventory_interval=0)

    await manager.start()
    try:
        await _until(lambda: _asked(record, "kernel_modules") >= 2, PATIENCE)
    finally:
        await manager.stop()

    assert {table: _asked(record, table) >= 2 for table in INVENTORY_TABLES} == (
        dict.fromkeys(INVENTORY_TABLES, True)
    )


@pytest.mark.asyncio
async def test_an_inventory_query_that_fails_is_asked_again_at_the_next_cycle(osquery):
    # Not an interval later: an hour without the inventory for one osqueryi
    # that did not answer.
    manager, record, tmp_path = osquery
    manager.config.performance.query_interval = 0.01
    (tmp_path / "failing").write_text("kernel_modules")

    await manager.start()
    try:
        await _until(lambda: manager.get_status()["queries_failed"] >= 2, PATIENCE)
        assert _asked(record, "kernel_modules") >= 2
        assert _asked(record, "kernel_info") == 1
        (tmp_path / "failing").unlink()

        types = set()

        def answered():
            while not manager.event_queue.empty():
                types.add(manager.event_queue.get_nowait()["type"])
            return "system_inventory.kernel_modules" in types

        await _until(answered, PATIENCE)
        asked = _asked(record, "kernel_modules")
        cycles = _asked(record, "sudoers")
        await _until(lambda: _asked(record, "sudoers") >= cycles + 2, PATIENCE)
    finally:
        await manager.stop()

    # It answered: from then on it waits like the others.
    assert _asked(record, "kernel_modules") == asked


@pytest.mark.parametrize(
    "written, expected",
    [({}, 3600), ({"inventory_interval": 900}, 900), ({"inventory_interval": 0}, 0)],
)
def test_the_inventory_interval_is_a_setting(tmp_path, written, expected):
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "data_lake": {"endpoint": "https://gateway.example", "api_key": ""},
                "fim": {"enabled": False, "paths": ["/etc"]},
                "performance": written,
            }
        )
    )

    assert load_config(str(path)).performance.inventory_interval == expected


@pytest.mark.parametrize("value", [-1, "hourly", True, None, 8 * 24 * 3600])
def test_an_inventory_interval_that_is_not_one_stops_the_sensor(tmp_path, value):
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "data_lake": {"endpoint": "https://gateway.example", "api_key": ""},
                "fim": {"enabled": False, "paths": ["/etc"]},
                "performance": {"inventory_interval": value},
            }
        )
    )

    with pytest.raises(ValueError, match="performance.inventory_interval must be"):
        load_config(str(path))


@pytest.mark.asyncio
async def test_the_manager_starts_no_osqueryd_and_says_what_osqueryi_it_found(osquery):
    manager, record, tmp_path = osquery

    await manager.start()
    try:
        await _until(lambda: manager.event_queue.qsize() == 11)
        status = manager.get_status()
    finally:
        await manager.stop()

    ran = _recorded(record)
    # main: an osqueryd, running every query a second time for a log file
    # nothing read.
    assert {entry["program"] for entry in ran} == {"osqueryi"}
    assert status["running"] is True
    assert status["osqueryi"] == str(tmp_path / "bin" / "osqueryi")
    assert status["osquery_version"] == "5.10.2"
    # The daemon is gone, and so is the word for it.
    assert "process_alive" not in status
    # The question asked at the start, then each query of each pack, once.
    assert ran[0]["query"] == "SELECT version FROM osquery_info;"
    assert len(ran) == 12
    assert status["queries_run"] == 12
    assert status["queries_failed"] == 0
    assert status["last_error"] is None
    types = []
    while not manager.event_queue.empty():
        event = manager.event_queue.get_nowait()
        assert event["source"] == "osquery"
        assert event["data"] == [{"answer": "a row"}]
        types.append(event["type"])
    assert sorted(types) == sorted(
        f"{pack}.{query}" for pack, queries in LINUX_PACKS.items() for query in queries
    )


@pytest.mark.asyncio
async def test_without_osqueryi_the_manager_does_not_start(osquery, monkeypatch):
    manager, record, _ = osquery
    monkeypatch.setenv("PATH", "/nonexistent-directory")

    with pytest.raises(RuntimeError, match="osquery not found"):
        await manager.start()

    assert manager.get_status()["running"] is False
    assert manager.get_status()["osqueryi"] is None
    assert _recorded(record) == []


@pytest.mark.asyncio
async def test_an_osqueryi_that_does_not_answer_is_said_at_the_start(osquery):
    manager, record, tmp_path = osquery
    (tmp_path / "broken").write_text("")

    with pytest.raises(RuntimeError) as refused:
        await manager.start()

    assert str(refused.value) == (
        "osqueryi does not answer a query: osquery query failed: "
        "Error: cannot open the database"
    )
    status = manager.get_status()
    assert status["running"] is False
    assert status["queries_run"] == 1
    assert status["queries_failed"] == 1
    assert status["last_error"] == (
        "osquery query failed: Error: cannot open the database"
    )
    # One question, and no cycle after it.
    assert len(_recorded(record)) == 1


@pytest.mark.asyncio
async def test_failed_queries_are_counted_and_the_last_reason_kept(osquery):
    manager, _, tmp_path = osquery
    manager.running = True

    assert await manager.execute_query("SELECT 1") == [{"answer": "a row"}]
    (tmp_path / "broken").write_text("")
    assert await manager.execute_query("SELECT 2") == []
    (tmp_path / "broken").unlink()
    assert await manager.execute_query("SELECT 3") == [{"answer": "a row"}]

    status = manager.get_status()
    assert status["queries_run"] == 3
    assert status["queries_failed"] == 1
    assert status["last_error"] == (
        "osquery query failed: Error: cannot open the database"
    )


@pytest.mark.asyncio
async def test_a_manager_that_is_not_running_runs_no_query(osquery):
    manager, record, _ = osquery

    with pytest.raises(RuntimeError, match="osquery manager is not running"):
        await manager.execute_query("SELECT 1")

    await manager.start()
    await manager.stop()
    asked = len(_recorded(record))
    with pytest.raises(RuntimeError, match="osquery manager is not running"):
        await manager.execute_query("SELECT 1")
    assert len(_recorded(record)) == asked


@pytest.mark.asyncio
async def test_stopping_ends_the_cycle_and_the_query_it_is_in(osquery):
    manager, record, tmp_path = osquery
    manager.config.performance.query_interval = 0.01

    await manager.start()
    await _until(lambda: manager.event_queue.qsize() >= 11)
    # The next query does not return.
    (tmp_path / "slow").write_text("")
    asked = len(_recorded(record))
    await _until(lambda: len(_recorded(record)) > asked)
    await asyncio.sleep(0.2)
    stuck = _recorded(record)

    started = time.monotonic()
    await manager.stop()
    took = time.monotonic() - started

    assert took < 5
    assert _gone(stuck[-1]["pid"])
    assert manager.get_status()["running"] is False
    await asyncio.sleep(0.3)
    # main: the cycle was a task nobody kept, and nothing ended it.
    assert len(_recorded(record)) == len(stuck)


@pytest.mark.asyncio
async def test_a_cycle_that_waits_for_the_queue_is_ended_by_stop(osquery):
    # With a full queue the cycle waits to hand over an event, as every
    # collector does; stop does not wait with it.
    manager, record, _ = osquery
    # The agent's queue, which answers for an event from the moment put()
    # is called with it.
    manager.event_queue = CountingQueue(maxsize=2)

    await manager.start()
    # The version, two queries whose events are in the queue, and a third
    # whose event waits for room.
    await _until(lambda: len(_recorded(record)) == 4)
    await asyncio.sleep(0.3)

    await asyncio.wait_for(manager.stop(), timeout=5)
    await asyncio.sleep(0.2)

    assert manager.event_queue.qsize() == 2
    assert len(_recorded(record)) == 4
    # The third answer is not lost from sight (#765): osquery cannot be
    # asked for it again, and the agent's stop counts it as dropped. main:
    # it was in no queue and no count.
    (waiting,) = manager.event_queue.turned_away
    assert waiting["source"] == "osquery" and waiting["data"] == [{"answer": "a row"}]


def test_the_image_links_the_one_binary_the_sensor_runs():
    dockerfile = (SERVICE_ROOT / "Dockerfile").read_text()

    assert "/usr/local/bin/osqueryi" in dockerfile
    assert "/usr/local/bin/osqueryd" not in dockerfile
    # What ran osquery as a daemon is taken out of the image (#765), and the
    # build checks that the name is off PATH. The binary itself stays: it is
    # the one osqueryi is a link to.
    removed = dockerfile.split("rm -f /usr/bin/osqueryd", 1)[1].split("&&", 1)[0]
    for path in (
        "/usr/bin/osqueryctl",
        "/opt/osquery/bin/osqueryctl",
        "/etc/init.d/osqueryd",
        "/etc/default/osqueryd",
        "/usr/lib/systemd/system/osqueryd.service",
    ):
        assert path in removed
    assert "/opt/osquery/bin/osqueryd" not in removed
    assert "! command -v osqueryd" in dockerfile
    assert "test -x /opt/osquery/bin/osqueryd" in dockerfile
