"""The sensor's stop ends inside the time it is given (#765, #777).

Whoever stops the sensor gives it a time to end in and kills it after that:
``stop_grace_period`` in the Compose files, 30 seconds. The stop had three
waits of its own, of up to 15, 2 and 15 seconds: 32, so a stop that used
them was killed before it had written its log positions and said what it
left behind. Nothing compared the two numbers; the one test there was asked
for 25 seconds.

The worst case is not added up by hand here, it is run: the real daemon and
the real agent, stopped while starting, with a start that does not end when
it is abandoned, collectors and a pipeline whose ``stop()`` never returns,
an event that never leaves the queue and last writes that never end. The
clock is the event loop's, made to leap to the next timer instead of waiting
for it, so the test takes milliseconds and measures what the limits add up
to. A wait added to the stop without a limit would never end here; one added
with a limit moves the measure, and the Compose files are held against it.

The last writes were such a wait (#777): they had no limit, and this test
gave them four seconds of room it could not hold them to. They have a limit
now and are in the measure. And what a collector waits for when it stops
(a child process, a request to the local API, its own write) had limits of
its own that added up to more than the agent gives the collectors: the real
collectors are run here too, each with everything it waits for never
ending, and each must stop before the agent stops waiting.
"""

import asyncio
import gc
import json
import logging
import re
import signal
import socket
import sys
import threading
import types
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
sys.path.insert(0, str(SERVICE_ROOT))

import main as sensor_main  # noqa: E402
from sensor.api.local_api import LocalAPI  # noqa: E402
from sensor.collectors import file_monitor, log_forwarder  # noqa: E402
from sensor.collectors.file_monitor import FileMonitor  # noqa: E402
from sensor.collectors.log_forwarder import LogForwarder  # noqa: E402
from sensor.collectors.osquery_manager import OsqueryManager  # noqa: E402
from sensor.core import agent as agent_module  # noqa: E402
from sensor.core import stop_limits  # noqa: E402
from sensor.core.agent import SecuritySensorAgent  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    FIMConfig,
    LogSourceConfig,
    NetworkConfig,
    SensorConfig,
)
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import DataForwarder  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
LOCAL_KEY = "local-api-key-0123456789abcdef"

# Seconds the time the sensor is given must leave beyond its limits, for what
# has none: Docker notices the exit. It was four seconds, of which the last
# writes took what they took, and then two, of which the exit limit's last
# log line took what it took: that line has a limit of its own now
# (main.EXIT_LOG_SECONDS, #788).
ROOM_FOR_THE_EXIT = 1.0

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the event loop used here is the selector's"
)


class Leaping(asyncio.SelectorEventLoop):
    """An event loop whose clock leaps to the next timer when nothing else
    is ready, instead of waiting for it."""

    def __init__(self):
        super().__init__()
        self.leapt = 0.0
        select = self._selector.select

        def leap(timeout=None):
            ready = select(0)
            if ready or timeout is None:
                return ready if ready else select(timeout)
            self.leapt += max(timeout, 0)
            return ready

        self._selector.select = leap

    def time(self):
        return super().time() + self.leapt


@pytest.fixture
def leaping():
    """A leaping loop, and the process's signal handlers as they were."""
    handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    loop = Leaping()
    try:
        yield loop
    finally:
        loop.close()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


class Stuck:
    """A component whose stop never returns, and whose last write never
    ends (or, ``writes``, ends at once)."""

    interrupted = ()

    def __init__(self, clock=None, writes=False, stops=False):
        self._clock = clock
        self._writes = writes
        self._stops = stops
        self.write_began = None

    async def stop(self):
        if not self._stops:
            await asyncio.Event().wait()

    async def _write(self):
        if self._clock is not None:
            self.write_began = self._clock()
        if not self._writes:
            await asyncio.Event().wait()

    write_positions = write_baseline = _write


class Armed:
    """What stands in for the exit limit: when it was armed, and how."""

    def __init__(self, clock):
        self._clock = clock
        self.calls = []
        self.cancelled = []
        # When the stop was asked for.
        self.asked = None

    def __call__(self, seconds, code, stopped=True):
        call = (self._clock(), seconds, code, stopped)
        self.calls.append(call)
        return types.SimpleNamespace(cancel=lambda: self.cancelled.append(call))


def _worst_stop(loop, tmp_path, monkeypatch, armed=None):
    """Stop a daemon in which everything takes all the time it is allowed.
    The exit status, the seconds from the request to the moment the last
    write began, and to the end."""
    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "data_lake": {"endpoint": "https://gateway.example"},
                "fim": {"enabled": False},
                "network": {"enable_api": False},
            }
        )
    )
    collector = Stuck(loop.time)
    starting = asyncio.Event()

    async def start(agent):
        agent.log_forwarder = collector
        agent.data_processor = Stuck()
        agent.data_forwarder = Stuck()
        # Never taken: the drain waits for it for as long as it may.
        agent.event_queue.put_nowait({"type": "log.app", "data": {}})
        starting.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            # Abandoned, and it does not end for that.
            await asyncio.Event().wait()

    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    monkeypatch.setattr(sensor_main, "setup_logging", lambda settings: None)
    # The exit limit ends the process, which here is the test's: its
    # arming is noted instead.
    armed = armed if armed is not None else Armed(loop.time)
    monkeypatch.setattr(sensor_main, "_leave_within", armed)
    daemon = sensor_main.SensorDaemon(str(config))

    async def scenario():
        running = asyncio.ensure_future(daemon.start())
        await starting.wait()
        asked = armed.asked = loop.time()
        await daemon.stop()
        # On the leaping clock: a stop that waits without a limit ends
        # here, as a failure, and not never.
        code = await asyncio.wait_for(running, timeout=3600)
        return code, collector.write_began - asked, loop.time() - asked

    code, write_began, ended = loop.run_until_complete(scenario())
    # To the tenth of a second: the leaps are exact, and the few
    # milliseconds the test really takes are on the clock too.
    return code, round(write_began, 1), round(ended, 1)


def _limits():
    return (
        sensor_main.START_ABORT_SECONDS,
        agent_module.COLLECTORS_STOP_SECONDS,
        agent_module.QUEUE_DRAIN_SECONDS,
        agent_module.PIPELINE_STOP_SECONDS,
        agent_module.LAST_WRITES_SECONDS,
    )


def test_a_stop_in_which_everything_takes_its_whole_limit_ends_at_their_sum(
    leaping, tmp_path, monkeypatch
):
    code, write_began, ended = _worst_stop(leaping, tmp_path, monkeypatch)

    assert code == 0
    # Each wait was used to its end, and there is no other. main: the last
    # write had no limit, and with one that does not end the stop did not.
    assert ended == sum(_limits())
    # The positions are written last, after every other wait: that is what
    # the limits are for.
    assert write_began == ended - agent_module.LAST_WRITES_SECONDS


def test_the_exit_limit_is_armed_as_the_last_writes_begin_and_not_after_them(
    leaping, tmp_path, monkeypatch
):
    armed = Armed(leaping.time)

    _, write_began, _ = _worst_stop(leaping, tmp_path, monkeypatch, armed)

    # main: armed by _run() when the daemon had returned, which a write
    # that does not return never let it do.
    ((at, seconds, code, stopped),) = armed.calls
    assert round(at - armed.asked, 1) == write_began
    # For the writes' own limit and the process's end after it: the moment
    # the sensor is gone by, whatever the writes do.
    assert seconds == agent_module.LAST_WRITES_SECONDS + sensor_main.EXIT_SECONDS
    assert (code, stopped) == (0, False)
    # And it is the daemon's while it stops: _run() arms the one after it.
    assert armed.cancelled == armed.calls


# -- the Compose files -------------------------------------------------------


class _Compose(yaml.SafeLoader):
    """Compose's own tags (!override, !reset) around plain YAML."""


def _tagged(loader, suffix, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_Compose.add_multi_constructor("!", _tagged)


def _compose_files():
    """Every Compose file of the repository that names the sensor."""
    candidates = sorted(
        set(REPO_ROOT.glob("docker-compose*.y*ml"))
        | set(SERVICE_ROOT.glob("docker-compose*.y*ml"))
        | set((REPO_ROOT / ".github").glob("*compose*.y*ml"))
    )
    found = []
    for path in candidates:
        services = yaml.load(path.read_text(), Loader=_Compose).get("services") or {}
        if "sensor" in services:
            found.append((path, services["sensor"]))
    return found


def _seconds(duration):
    """A Compose duration ("30s", "1m30s") in seconds."""
    parts = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m(?!s))?(?:(\d+)s)?", str(duration))
    assert parts and any(parts.groups()), f"not a duration: {duration!r}"
    hours, minutes, seconds = (int(part or 0) for part in parts.groups())
    return hours * 3600 + minutes * 60 + seconds


def test_the_files_that_run_the_sensor_are_the_ones_this_test_knows():
    # The two that start it, and the two overlays of the root file. A file
    # that begins to name the sensor is held to the same limits below
    # without being listed here; this says that the search finds them.
    names = {str(path.relative_to(REPO_ROOT)) for path, _ in _compose_files()}

    assert {"docker-compose.yml", "open-security-sensor/docker-compose.yml"} <= names


def test_every_compose_file_gives_the_sensor_the_time_its_stop_can_take(
    leaping, tmp_path, monkeypatch
):
    _, _, ended = _worst_stop(leaping, tmp_path, monkeypatch)
    # What the stop itself can take, as measured, and then the process's
    # own end, which has its limit too, and the last line of that limit,
    # which has one as well.
    limits = ended + sensor_main.EXIT_SECONDS + sensor_main.EXIT_LOG_SECONDS
    needed = limits + ROOM_FOR_THE_EXIT

    checked = 0
    for path, sensor in _compose_files():
        name = path.relative_to(REPO_ROOT)
        grace = sensor.get("stop_grace_period")
        if grace is None:
            # An overlay may leave it to the file it overlays. A file that
            # says what the sensor's image is, or is built from, is no
            # overlay: without the key Docker gives the container 10
            # seconds.
            build = sensor.get("build")
            context = build.get("context") if isinstance(build, dict) else build
            assert (
                "image" not in sensor and context is None
            ), f"{name} starts the sensor without a stop_grace_period"
            continue
        checked += 1
        # #765: 32 seconds of limits against the 30 of both files.
        assert _seconds(grace) >= needed, (
            f"{name} gives the sensor {grace} to stop; its limits add up to "
            f"{limits:.0f} seconds and its exit needs "
            f"{ROOM_FOR_THE_EXIT:.0f} more to be noticed"
        )
    assert checked >= 2


@pytest.mark.parametrize(
    "duration, seconds", [("30s", 30), ("1m30s", 90), ("2m", 120), ("1h", 3600)]
)
def test_a_compose_duration_is_read_as_compose_reads_it(duration, seconds):
    assert _seconds(duration) == seconds


# -- each limit by itself ------------------------------------------------------


def _agent():
    return SecuritySensorAgent(
        SensorConfig(
            data_lake=DataLakeConfig(
                endpoint="https://gateway.example", api_key=API_KEY
            )
        )
    )


def test_collectors_that_do_not_stop_cost_their_limit_and_no_more(leaping, caplog):
    agent = _agent()
    agent.log_forwarder = collector = Stuck(leaping.time, writes=True)
    agent.file_monitor = Stuck(writes=True)

    began = leaping.time()
    leaping.run_until_complete(asyncio.wait_for(agent.stop(), timeout=3600))

    assert leaping.time() - began == pytest.approx(
        agent_module.COLLECTORS_STOP_SECONDS, abs=0.5
    )
    assert collector.write_began is not None
    # It names what was stopped, and the time it was given. main said
    # "Some components did not stop within timeout".
    assert (
        "Some of Stuck, Stuck did not stop within 8 seconds: the stop goes on "
        "without waiting for them"
    ) in caplog.text


def test_the_sender_spends_less_on_its_last_batches_than_the_pipeline_is_given(
    leaping, monkeypatch
):
    assert data_forwarder.STOP_FLUSH_SECONDS < agent_module.PIPELINE_STOP_SECONDS

    # And it keeps to it with a gateway that never answers: a batch is on
    # its way when the stop comes, and the one after it is not begun.
    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    async def send(self, body):
        await asyncio.Event().wait()

    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    # The sender reads the time for its deadline from the time module: it
    # is given the loop's.
    clock = types.SimpleNamespace(monotonic=leaping.time, time=leaping.time)
    monkeypatch.setattr(data_forwarder, "time", clock)
    config = SensorConfig(
        data_lake=DataLakeConfig(
            endpoint="https://gateway.example",
            api_key=API_KEY,
            batch_size=1,
            flush_interval=1,
        )
    )

    async def scenario():
        forwarder = DataForwarder(config, asyncio.Queue())
        await forwarder.start()
        for index in range(3):
            forwarder.accept({"type": "log.app", "data": {"raw_message": str(index)}})
        await asyncio.sleep(1)  # a batch is being sent, and is not answered
        began = leaping.time()
        await asyncio.wait_for(forwarder.stop(), timeout=3600)
        return forwarder, leaping.time() - began

    forwarder, took = leaping.run_until_complete(scenario())

    assert took == pytest.approx(data_forwarder.STOP_FLUSH_SECONDS, abs=0.5)
    assert forwarder.stats["events_dropped_shutdown"] == 3
    assert forwarder.session.closed is True


def test_last_writes_that_do_not_end_cost_their_limit_once_and_are_said(
    leaping, caplog
):
    agent = _agent()
    agent.log_forwarder = Stuck(leaping.time, stops=True)
    agent.file_monitor = Stuck(leaping.time, stops=True)
    began = leaping.time()

    with caplog.at_level(logging.WARNING):
        leaping.run_until_complete(asyncio.wait_for(agent.stop(), timeout=3600))

    # Side by side: the limit once, not once for each. main: no limit, and
    # the stop did not end.
    assert leaping.time() - began == pytest.approx(
        agent_module.LAST_WRITES_SECONDS, abs=0.5
    )
    said = [record.getMessage() for record in caplog.records]
    assert said == [
        "Stopped without writing the log positions: the write had not ended "
        "after 2 seconds, and is left to its thread. If that stays so, after "
        "the restart the log sources are read from the positions last saved, "
        "and what was delivered since is sent again",
        "Stopped without writing the file monitor's baseline: the write had "
        "not ended after 2 seconds, and is left to its thread. If that stays "
        "so, after the restart the watched files are compared with the "
        "baseline last saved, and the changes delivered since are reported "
        "again",
    ]


def test_last_writes_that_end_are_not_waited_for_and_nothing_is_said(leaping, caplog):
    agent = _agent()
    agent.log_forwarder = Stuck(leaping.time, stops=True, writes=True)
    agent.file_monitor = Stuck(leaping.time, stops=True, writes=True)
    began = leaping.time()

    with caplog.at_level(logging.WARNING):
        leaping.run_until_complete(asyncio.wait_for(agent.stop(), timeout=3600))

    assert leaping.time() - began == pytest.approx(0, abs=0.5)
    assert caplog.records == []


# -- what a collector waits for, inside the collectors' limit (#777) ----------
#
# The real collectors, each with everything it waits for never ending. The
# agent gives them COLLECTORS_STOP_SECONDS together and then goes on without
# them: a collector that needs longer is cut short wherever it is, with a
# command still running or a pipe still open.


class Stream:
    """A pipe nothing more comes out of, and that does not close."""

    async def read(self, size):
        await asyncio.Event().wait()


class NeverEnds:
    """A child process that ends for nothing, and keeps its output open."""

    returncode = None
    pid = 4242

    def __init__(self):
        self.stdout, self.stderr = Stream(), Stream()
        # What was done to it, in order.
        self.done = []
        self._transport = types.SimpleNamespace(
            close=lambda: self.done.append("pipes closed")
        )

    def terminate(self):
        self.done.append("asked to end")

    def kill(self):
        self.done.append("killed")

    async def wait(self):
        await asyncio.Event().wait()


@pytest.fixture
def children(monkeypatch):
    """Every child process the sensor starts is one that never ends."""
    started = []

    async def spawn(*argv, **kwargs):
        started.append(NeverEnds())
        return started[-1]

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    return started


class Disk:
    """A data directory that stops answering: a write of a held store's
    file does not return before the test is over."""

    def __init__(self):
        # Set when a write is waiting for it.
        self.waited_for = threading.Event()
        self.released = threading.Event()

    def hold(self, store):
        def write(payload):
            self.waited_for.set()
            self.released.wait()

        store._file.write = write


@pytest.fixture
def disk(leaping):
    # After the loop in the fixtures' order, so released before it closes.
    disk = Disk()
    yield disk
    disk.released.set()


async def _spin_until(condition):
    """Wait for ``condition`` without a timer, which the clock would leap."""
    for _ in range(100_000):
        if condition():
            return
        await asyncio.sleep(0)
    raise AssertionError("it did not happen")


def _collector_config(tmp_path, **settings):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        data_dir=str(data_dir),
        **settings,
    )


def test_the_log_forwarder_stops_in_time_with_a_command_and_a_write_that_never_end(
    leaping, tmp_path, monkeypatch, children, disk, caplog
):
    monkeypatch.setattr(log_forwarder, "is_linux", lambda: True)
    log = tmp_path / "app.log"
    log.write_text("one\n")
    config = _collector_config(
        tmp_path,
        collection=CollectionConfig(log_forwarding=True),
        log_sources=[
            LogSourceConfig(name="journal", type="journald", format="json"),
            # A file source, known from its first look: positions to write.
            LogSourceConfig(name="app", path=str(log), format="raw"),
        ],
    )

    async def scenario():
        forwarder = LogForwarder(config, asyncio.Queue())
        disk.hold(forwarder.positions)
        await forwarder.start()
        await _spin_until(lambda: children)
        # The periodic write is in its thread, and does not come back.
        await leaping.run_in_executor(None, disk.waited_for.wait)
        began = leaping.time()
        await asyncio.wait_for(forwarder.stop(), timeout=3600)
        return leaping.time() - began

    with caplog.at_level(logging.WARNING):
        took = leaping.run_until_complete(scenario())
        # What asyncio says of a future nobody asked for its outcome, when
        # the future is collected.
        gc.collect()

    # Asked to end, killed, given up; then its own write, given up too.
    # main: asked, killed after 5 seconds, and then waited for without a
    # limit.
    (journalctl,) = children
    assert journalctl.done == ["asked to end", "killed", "pipes closed"]
    assert took == pytest.approx(
        stop_limits.CHILD_TERM_SECONDS
        + stop_limits.CHILD_KILL_SECONDS
        + stop_limits.STATE_WRITE_SECONDS,
        abs=0.5,
    )
    assert took < agent_module.COLLECTORS_STOP_SECONDS
    said = [record.getMessage() for record in caplog.records]
    assert (
        "Log source 'journal': journalctl (pid 4242) was killed and was not "
        "gone within 2 seconds: its output is closed"
    ) in said
    assert (
        "The log positions were not written within 2 seconds of the log "
        f"forwarder's stop: a write to {config.data_dir} has not ended"
    ) in said
    # And the wait that was given up leaves nothing behind for asyncio to
    # report ("exception was never retrieved").
    assert [record for record in caplog.records if record.name == "asyncio"] == []


def test_the_file_monitor_stops_in_time_with_a_write_that_never_ends(
    leaping, tmp_path, disk, caplog
):
    watched = tmp_path / "etc"
    watched.mkdir()
    (watched / "hosts").write_text("127.0.0.1 localhost\n")
    config = _collector_config(
        tmp_path,
        collection=CollectionConfig(file_monitoring=True),
        fim=FIMConfig(enabled=True, paths=[str(watched)]),
    )

    async def scenario():
        monitor = FileMonitor(config, asyncio.Queue())
        await monitor.start()  # the first baseline is written
        disk.hold(monitor.baseline)
        # As an accepted change leaves it: the periodic write is made.
        monitor._baseline_dirty = True
        await leaping.run_in_executor(None, disk.waited_for.wait)
        began = leaping.time()
        await asyncio.wait_for(monitor.stop(), timeout=3600)
        return leaping.time() - began

    with caplog.at_level(logging.WARNING, logger=file_monitor.__name__):
        took = leaping.run_until_complete(scenario())

    # main: until the agent stopped waiting for the collectors.
    assert took == pytest.approx(stop_limits.STATE_WRITE_SECONDS, abs=0.5)
    assert took < agent_module.COLLECTORS_STOP_SECONDS
    assert [record.getMessage() for record in caplog.records] == [
        "The file monitor's baseline was not written within 2 seconds of the "
        f"monitor's stop: a write to {config.data_dir} has not ended"
    ]


def test_the_osquery_manager_stops_in_time_with_a_query_that_never_ends(
    leaping, tmp_path, children, caplog
):
    config = _collector_config(tmp_path)

    async def scenario():
        manager = OsqueryManager(config, asyncio.Queue())
        manager.running = True
        manager._task = asyncio.ensure_future(manager._collect_results())
        await _spin_until(lambda: children)
        began = leaping.time()
        await asyncio.wait_for(manager.stop(), timeout=3600)
        return leaping.time() - began

    with caplog.at_level(logging.ERROR):
        took = leaping.run_until_complete(scenario())

    (osqueryi,) = children
    assert osqueryi.done == ["killed", "pipes closed"]
    # main: 10 seconds, against the 8 the collectors have.
    assert took == pytest.approx(stop_limits.CHILD_KILL_SECONDS, abs=0.5)
    assert took < agent_module.COLLECTORS_STOP_SECONDS
    assert "was killed and its output did not end within 2.0 seconds" in caplog.text


class Asked:
    """An agent whose query never answers."""

    running = True

    def __init__(self):
        self.asked = asyncio.Event()

    async def execute_query(self, query):
        self.asked.set()
        await asyncio.Event().wait()


def test_the_local_api_stops_in_time_with_a_request_that_never_finishes(leaping):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        network=NetworkConfig(
            enable_api=True,
            bind_address="127.0.0.1",
            bind_port=port,
            api_key=LOCAL_KEY,
        ),
    )
    body = json.dumps({"query": "SELECT 1"}).encode()
    request = (
        b"POST /api/v1/query HTTP/1.1\r\nHost: sensor\r\n"
        b"X-API-Key: %s\r\nContent-Type: application/json\r\n"
        b"Content-Length: %d\r\n\r\n%s" % (LOCAL_KEY.encode(), len(body), body)
    )

    async def scenario():
        agent = Asked()
        api = LocalAPI(config, agent=agent)
        await api.start()
        # A client without timers of its own, which the clock would leap.
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(request)
            await writer.drain()
            await agent.asked.wait()
            began = leaping.time()
            await asyncio.wait_for(api.stop(), timeout=3600)
            took = leaping.time() - began
            # The request was given up, not answered.
            answer = await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()
        return took, answer

    took, answer = leaping.run_until_complete(scenario())

    # The time to finish, then as long again once cancelled. main: 60 and
    # 60, of which the agent waited 8.
    assert took == pytest.approx(2 * stop_limits.API_SHUTDOWN_SECONDS, abs=0.5)
    assert took < agent_module.COLLECTORS_STOP_SECONDS
    assert answer == b""


def test_what_a_collector_waits_for_is_a_part_of_what_the_collectors_have():
    import ast

    from sensor.api import local_api
    from sensor.collectors import osquery_manager

    whole = stop_limits.COLLECTORS_STOP_SECONDS
    parts = {
        "CHILD_TERM_SECONDS": (log_forwarder,),
        "CHILD_KILL_SECONDS": (log_forwarder, osquery_manager),
        "STATE_WRITE_SECONDS": (log_forwarder, file_monitor),
        "API_SHUTDOWN_SECONDS": (local_api,),
    }

    # The longest chains, as the tests above measure them.
    assert (
        stop_limits.CHILD_TERM_SECONDS
        + stop_limits.CHILD_KILL_SECONDS
        + stop_limits.STATE_WRITE_SECONDS
        < whole
    )
    assert 2 * stop_limits.API_SHUTDOWN_SECONDS < whole
    # Each is computed from the whole, not a number of its own that the
    # next change of the whole leaves behind...
    assigned = {
        node.targets[0].id: {
            name.id for name in ast.walk(node.value) if isinstance(name, ast.Name)
        }
        for node in ast.parse(Path(stop_limits.__file__).read_text()).body
        if isinstance(node, ast.Assign)
    }
    for name, users in parts.items():
        assert assigned[name] == {"COLLECTORS_STOP_SECONDS"}, name
        # ... and the collectors read it there, and have none of their own.
        for module in users:
            assert getattr(module, name) is getattr(stop_limits, name)
    for module, gone in ((log_forwarder, "CHILD_STOP_SECONDS"), (osquery_manager, "KILL_WAIT")):
        assert not hasattr(module, gone)
