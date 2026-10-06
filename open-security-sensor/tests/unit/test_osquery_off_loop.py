"""An osquery query does not stop the sensor while it runs (#745).

Every query was a ``subprocess.run`` of up to 30 seconds in the event loop.
For that long nothing else ran: no batch was sent, no log was read, the local
API did not answer. The collection cycle issues a dozen of them in a row.

``osqueryi`` is played by a script of the same name put first on ``PATH``: a
real child process, with real pipes, a real exit status and a real kill.
"""

import asyncio
import json
import logging
import os
import stat
import sys
import time
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import osquery_manager  # noqa: E402
from sensor.collectors.osquery_manager import OsqueryManager  # noqa: E402
from sensor.core.config import DataLakeConfig, SensorConfig  # noqa: E402

OSQUERYI = """#!{python}
import json, os, sys, time

query = sys.argv[-1]
record = os.environ["OSQUERYI_RECORD"]
with open(record, "a") as handle:
    handle.write(json.dumps({{"pid": os.getpid(), "argv": sys.argv[1:], "start": time.time()}}) + "\\n")
if "sleeps" in query:
    time.sleep(float(query.split("sleeps ")[1].split()[0]))
if "litters" in query:
    # A process of its own, which keeps the output open after it.
    import subprocess
    left = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    with open(record, "a") as handle:
        handle.write(json.dumps({{"left": left.pid}}) + "\\n")
    time.sleep(60)
if "floods" in query:
    block = "x" * 65536
    for _ in range(64):
        sys.stdout.write(block)
        sys.stdout.flush()
    time.sleep(30)
if "complains" in query:
    sys.stderr.write("x" * 300000)
if "fails" in query:
    sys.stderr.write("Error: no such table: nope\\n")
    sys.exit(1)
if "babbles" in query:
    print("not json at all")
    sys.exit(0)
if "an object" in query:
    print(json.dumps({{"rows": 1}}))
    sys.exit(0)
with open(record, "a") as handle:
    handle.write(json.dumps({{"pid": os.getpid(), "end": time.time()}}) + "\\n")
print(json.dumps([{{"pid": "1", "name": "init", "query": query}}]))
"""


@pytest.fixture
def osqueryi(tmp_path, monkeypatch):
    """A manager whose osqueryi is the script above; the file it records in."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "osqueryi"
    script.write_text(OSQUERYI.format(python=sys.executable))
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    record = tmp_path / "record.jsonl"
    record.write_text("")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("OSQUERYI_RECORD", str(record))
    monkeypatch.setattr(osquery_manager, "is_windows", lambda: False)
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key="")
    )
    manager = OsqueryManager(config, asyncio.Queue())
    manager.running = True
    return manager, record


def _recorded(record):
    return [json.loads(line) for line in record.read_text().splitlines()]


def _open_descriptors():
    return len(os.listdir("/dev/fd"))


def _gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


@pytest.mark.asyncio
async def test_a_query_returns_its_rows_and_is_one_argument(osqueryi):
    manager, record = osqueryi
    query = "SELECT pid, name FROM processes WHERE name = 'a b'; rm -rf / #"

    rows = await manager.execute_query(query)

    assert rows == [{"pid": "1", "name": "init", "query": query}]
    # Never a shell: the query, whatever it holds, is the last argument.
    assert _recorded(record)[0]["argv"] == ["--json", query]


@pytest.mark.asyncio
async def test_the_event_loop_runs_while_a_query_does(osqueryi):
    manager, _ = osqueryi
    ticks = 0

    async def everything_else():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    others = asyncio.ensure_future(everything_else())
    try:
        started = time.monotonic()
        rows = await manager.execute_query("SELECT 1; -- sleeps 0.6 seconds")
        took = time.monotonic() - started
        during = ticks
    finally:
        others.cancel()

    assert rows and took >= 0.6
    # main: 0. The loop was inside subprocess.run for the whole query.
    assert during >= 20


@pytest.mark.asyncio
async def test_a_query_that_takes_too_long_is_killed_and_yields_nothing(
    osqueryi, monkeypatch, caplog
):
    manager, record = osqueryi
    # Long enough for the child to have started, on a busy machine too.
    monkeypatch.setattr(osquery_manager, "QUERY_TIMEOUT", 2)

    started = time.monotonic()
    with caplog.at_level(logging.ERROR, logger=osquery_manager.__name__):
        rows = await manager.execute_query("SELECT 1; -- sleeps 60 seconds")
    took = time.monotonic() - started

    assert rows == []
    assert 2 <= took < 10
    assert "osquery query timed out" in caplog.text
    assert _gone(_recorded(record)[0]["pid"])


@pytest.mark.asyncio
async def test_a_query_that_prints_too_much_is_killed_and_yields_nothing(
    osqueryi, monkeypatch, caplog
):
    # It prints four megabytes and then stays: the sensor holds no more
    # than the bound, and does not wait for it.
    manager, record = osqueryi
    monkeypatch.setattr(osquery_manager, "MAX_QUERY_OUTPUT", 100_000)

    started = time.monotonic()
    with caplog.at_level(logging.ERROR, logger=osquery_manager.__name__):
        rows = await manager.execute_query("SELECT 1; -- floods")
    took = time.monotonic() - started

    assert rows == []
    assert took < 10
    assert "printed more than 100000 bytes" in caplog.text
    assert _gone(_recorded(record)[0]["pid"])


@pytest.mark.asyncio
async def test_a_killed_query_whose_output_stays_open_is_not_waited_for(
    osqueryi, monkeypatch, caplog
):
    # asyncio (3.11) reports a child's exit once its pipes are closed, and
    # a process the child started can hold them for as long as it lives.
    manager, record = osqueryi
    # Long enough for the child to have started the other process.
    monkeypatch.setattr(osquery_manager, "QUERY_TIMEOUT", 3)
    monkeypatch.setattr(osquery_manager, "KILL_WAIT", 0.5)

    held = _open_descriptors()
    started = time.monotonic()
    try:
        with caplog.at_level(logging.ERROR, logger=osquery_manager.__name__):
            rows = await asyncio.wait_for(
                manager.execute_query("SELECT 1; -- litters"), timeout=20
            )
        took = time.monotonic() - started
        ran = _recorded(record)
        await asyncio.sleep(0.2)
        # Its two pipes are not left open on the sensor's side for as long
        # as the other process lives.
        still_held = _open_descriptors()
        # The next query is not held up by the one that was given up.
        after = await asyncio.wait_for(manager.execute_query("SELECT 2"), timeout=20)
    finally:
        for entry in _recorded(record):
            if "left" in entry:
                os.kill(entry["left"], 9)

    assert rows == []
    assert took < 10
    assert still_held <= held
    assert "osquery query timed out" in caplog.text
    assert "its output did not end within 0.5 seconds: it is closed" in caplog.text
    deadline = time.monotonic() + 5
    while not _gone(ran[0]["pid"]) and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    assert _gone(ran[0]["pid"])
    assert after and after[0]["query"] == "SELECT 2"


@pytest.mark.asyncio
async def test_a_query_that_fails_says_why_and_yields_nothing(osqueryi, caplog):
    manager, _ = osqueryi

    with caplog.at_level(logging.ERROR, logger=osquery_manager.__name__):
        rows = await manager.execute_query("SELECT * FROM nope; -- fails")

    assert rows == []
    assert "osquery query failed: Error: no such table: nope" in caplog.text


@pytest.mark.asyncio
async def test_a_lot_of_standard_error_does_not_block_the_query(osqueryi, caplog):
    # More than a pipe holds: unread, osqueryi would wait on it for ever.
    manager, _ = osqueryi

    with caplog.at_level(logging.ERROR, logger=osquery_manager.__name__):
        rows = await asyncio.wait_for(
            manager.execute_query("SELECT 1; -- complains fails"), timeout=20
        )

    assert rows == []
    (message,) = [r.getMessage() for r in caplog.records]
    assert message.endswith("Error: no such table: nope")
    assert len(message) < osquery_manager.QUERY_STDERR_KEPT + 100


@pytest.mark.asyncio
async def test_output_that_is_not_json_yields_nothing(osqueryi, caplog):
    manager, _ = osqueryi

    with caplog.at_level(logging.ERROR, logger=osquery_manager.__name__):
        assert await manager.execute_query("SELECT 1; -- babbles") == []

    assert "Failed to parse osquery results" in caplog.text


@pytest.mark.asyncio
async def test_output_that_is_not_a_list_of_rows_yields_nothing(osqueryi):
    manager, _ = osqueryi

    assert await manager.execute_query("SELECT 1; -- an object") == []


@pytest.mark.asyncio
async def test_queries_run_one_at_a_time(osqueryi):
    manager, record = osqueryi

    results = await asyncio.gather(
        *(manager.execute_query(f"SELECT {n}; -- sleeps 0.2 seconds") for n in range(3))
    )

    assert all(results)
    spans = {}
    for entry in _recorded(record):
        spans.setdefault(entry["pid"], {}).update(entry)
    spans = sorted(spans.values(), key=lambda span: span["start"])
    assert len(spans) == 3
    # None starts before the one before it has ended.
    for earlier, later in zip(spans, spans[1:]):
        assert earlier["end"] <= later["start"]


@pytest.mark.asyncio
async def test_without_osqueryi_a_query_yields_nothing(osqueryi, monkeypatch, caplog):
    manager, _ = osqueryi
    monkeypatch.setenv("PATH", "/nonexistent-directory")

    with caplog.at_level(logging.ERROR, logger=osquery_manager.__name__):
        assert await manager.execute_query("SELECT 1") == []

    assert "Error executing osquery" in caplog.text


def test_no_blocking_subprocess_call_is_left_in_the_collector():
    source = (SERVICE_ROOT / "sensor/collectors/osquery_manager.py").read_text()

    # subprocess.run waits in the calling thread, which is the event loop's.
    assert "subprocess.run(" not in source
    # And the second one was in a method nothing called.
    assert "_validate_query" not in source
