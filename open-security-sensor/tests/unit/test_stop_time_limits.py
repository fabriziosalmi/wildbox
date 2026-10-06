"""The sensor's stop ends inside the time it is given (#765).

Whoever stops the sensor gives it a time to end in and kills it after that:
``stop_grace_period`` in the Compose files, 30 seconds. The stop had three
waits of its own, of up to 15, 2 and 15 seconds: 32, so a stop that used
them was killed before it had written its log positions and said what it
left behind. Nothing compared the two numbers; the one test there was asked
for 25 seconds.

The worst case is not added up by hand here, it is run: the real daemon and
the real agent, stopped while starting, with a start that does not end when
it is abandoned, collectors and a pipeline whose ``stop()`` never returns and
an event that never leaves the queue. The clock is the event loop's, made to
leap to the next timer instead of waiting for it, so the test takes
milliseconds and measures what the limits add up to. A wait
added to the stop without a limit would never end here; one added with a
limit moves the measure, and the Compose files are held against it.
"""

import asyncio
import re
import signal
import sys
import types
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
sys.path.insert(0, str(SERVICE_ROOT))

import main as sensor_main  # noqa: E402
from sensor.core import agent as agent_module  # noqa: E402
from sensor.core.agent import SecuritySensorAgent  # noqa: E402
from sensor.core.config import DataLakeConfig, SensorConfig  # noqa: E402
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import DataForwarder  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Seconds the time the sensor is given must leave beyond its limits, for what
# has none: the log positions and the file monitor's baseline are written and
# flushed to disk, the last lines are logged, Docker notices the exit.
ROOM_FOR_THE_LAST_WRITES = 4.0

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
    """A component whose stop never returns."""

    interrupted = ()

    def __init__(self, clock=None):
        self._clock = clock
        self.written_at = None

    async def stop(self):
        await asyncio.Event().wait()

    def save_positions(self):
        self.written_at = self._clock()


def _worst_stop(loop, tmp_path, monkeypatch):
    """Stop a daemon in which everything takes all the time it is allowed.
    The exit status, the seconds from the request to the last write, and to
    the end."""
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
    daemon = sensor_main.SensorDaemon(str(config))

    async def scenario():
        running = asyncio.ensure_future(daemon.start())
        await starting.wait()
        asked = loop.time()
        await daemon.stop()
        # On the leaping clock: a stop that waits without a limit ends
        # here, as a failure, and not never.
        code = await asyncio.wait_for(running, timeout=3600)
        return code, collector.written_at - asked, loop.time() - asked

    code, written, ended = loop.run_until_complete(scenario())
    # To the tenth of a second: the leaps are exact, and the few
    # milliseconds the test really takes are on the clock too.
    return code, round(written, 1), round(ended, 1)


def _limits():
    return (
        sensor_main.START_ABORT_SECONDS,
        agent_module.COLLECTORS_STOP_SECONDS,
        agent_module.QUEUE_DRAIN_SECONDS,
        agent_module.PIPELINE_STOP_SECONDS,
    )


def test_a_stop_in_which_everything_takes_its_whole_limit_ends_at_their_sum(
    leaping, tmp_path, monkeypatch
):
    code, written, ended = _worst_stop(leaping, tmp_path, monkeypatch)

    assert code == 0
    # Each wait was used to its end, and there is no other.
    assert ended == sum(_limits())
    # The positions are written last, after every wait: that is what the
    # limits are for.
    assert written == ended


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
    # own end, which has its limit too.
    needed = ended + sensor_main.EXIT_SECONDS + ROOM_FOR_THE_LAST_WRITES

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
        # main: 32 seconds of limits against the 30 of both files.
        assert _seconds(grace) >= needed, (
            f"{name} gives the sensor {grace} to stop; its limits add up to "
            f"{ended + sensor_main.EXIT_SECONDS:.0f} seconds and the last "
            f"writes need {ROOM_FOR_THE_LAST_WRITES:.0f} more"
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
    agent.log_forwarder = collector = Stuck(leaping.time)
    agent.file_monitor = Stuck()
    agent.file_monitor.save_baseline = lambda: None

    began = leaping.time()
    leaping.run_until_complete(asyncio.wait_for(agent.stop(), timeout=3600))

    assert leaping.time() - began == pytest.approx(
        agent_module.COLLECTORS_STOP_SECONDS, abs=0.5
    )
    assert collector.written_at is not None
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
