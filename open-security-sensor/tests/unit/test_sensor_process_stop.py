"""A stop asked for at any moment of the sensor's start ends it in order,
and in time (#765).

In its container the sensor is process 1, and the kernel does not deliver to
process 1 a signal it has no handler for. The handlers were installed after
the imports, the configuration and the agent, so a ``docker stop`` in that
time was not received: the container was killed when its grace period ran
out (measured in the image: 12.3 seconds for ``docker stop -t 12``, exit
status 137). Once they were installed, a stop still waited for the start to
end by itself, whatever that took, and after the stop the process waited
without a limit for every worker thread.

The sensor here is the real one: ``python main.py --config ...`` in a
process of its own, with a real SIGTERM. Not process 1, so a signal without
a handler ends it on the spot instead of being ignored: either way it is no
orderly stop, and the exit status says which it was.

The signal is not timed. An audit hook, put into the child by a
``sitecustomize`` module on its path, sends it at the moment the sensor does
a named thing: imports a module, opens its configuration, lists a watched
directory, asks for a name, puts its position file in place. The hook can
also hold that call for minutes, as a file system or a resolver that does
not answer would. One test needs no hook: the osqueryi the sensor starts
asks its parent to stop.

And a stop while the data directory does not answer ends in time too (#777):
the write that is held there has the store's lock, the stop's own write
waited for that lock in the event loop, and nothing was left to end the
process but whoever had asked it to stop.
"""

import asyncio
import logging
import os
import signal
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

import main as sensor_main  # noqa: E402
from sensor.core.agent import SecuritySensorAgent  # noqa: E402

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="signals are delivered differently on Windows"
)

# What the Compose files give the sensor to stop in: the whole run of each
# test, its start included, must fit.
GRACE_SECONDS = 30
# Seconds the hook holds a call: far longer than any test may take.
HOLD_SECONDS = 300
# When the test gives up on a child that has not ended, and kills it.
GIVE_UP_SECONDS = 60

HOOK = """
import os, signal, sys, time

_KIND, _, _WHAT = os.environ.get("SENSOR_TEST_STOP_AT", "").partition(":")
_EVENTS = {
    "import": "import",
    "open": "open",
    "scandir": "os.scandir",
    "lookup": "socket.gethostbyaddr",
    "rename": "os.rename",
}
# Which argument of the event names the thing: the first, but for a rename,
# which is named by what it puts in place.
_NAMED_BY = {"rename": 1}
_HOLD = float(os.environ.get("SENSOR_TEST_HOLD", "0"))
_reached = []


def _hook(event, args):
    if _reached or event != _EVENTS[_KIND]:
        return
    if str(args[_NAMED_BY.get(_KIND, 0)]) != _WHAT:
        return
    _reached.append(event)
    fd = os.open(os.environ["SENSOR_TEST_MARK"], os.O_WRONLY | os.O_CREAT)
    os.close(fd)
    os.kill(os.getpid(), signal.SIGTERM)
    if _HOLD:
        time.sleep(_HOLD)


if _KIND:
    sys.addaudithook(_hook)
"""

# osqueryi, played by a shell script: its version, and one socket with an
# address to look up. With OSQUERY_SLOW set it does not answer: it says
# which process it is, asks the sensor that started it to stop, as `docker
# stop` would at that moment, and stays.
OSQUERYI = """#!/bin/sh
if [ -n "$OSQUERY_SLOW" ]; then
    echo $$ > "$OSQUERY_SLOW"
    : > "$SENSOR_TEST_MARK"
    kill -TERM $PPID
    exec sleep 300
fi
case "$*" in
    *osquery_info*) echo '[{"version": "5.23.1"}]' ;;
    *) echo '[{"pid": "7", "name": "curl", "local_address": "127.0.0.1",' \\
            '"remote_address": "203.0.113.9", "remote_port": "443"}]' ;;
esac
"""


class Run:
    """How a sensor process ended."""

    def __init__(self, code, output, seconds, reached):
        self.code = code
        self.output = output
        self.seconds = seconds
        # Did the sensor get to the point at which the hook acts?
        self.reached = reached

    def __repr__(self):
        return f"exit status {self.code} after {self.seconds:.1f} s:\n{self.output}"


@pytest.fixture
def sensor(tmp_path):
    """Run the sensor in a process of its own: ``sensor(stop_at, ...)``."""
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    (hooks / "sitecustomize.py").write_text(HOOK)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    osqueryi = bin_dir / "osqueryi"
    osqueryi.write_text(OSQUERYI)
    osqueryi.chmod(osqueryi.stat().st_mode | stat.S_IXUSR)
    mark = tmp_path / "reached"
    config = tmp_path / "config.yaml"
    children = []

    def run(
        stop_at="",
        hold=0,
        at_line=None,
        slow_osquery=None,
        stop_before_it_starts=False,
        settings=None,
        **collection,
    ):
        enabled = dict.fromkeys(
            (
                "process_events",
                "network_connections",
                "file_monitoring",
                "user_events",
                "system_inventory",
                "log_forwarding",
            ),
            False,
        )
        watched = collection.pop("watched", None)
        enabled.update(collection)
        config.write_text(
            yaml.safe_dump(
                {
                    # No key: nothing is sent anywhere.
                    "data_lake": {"endpoint": "https://gateway.example"},
                    "collection": enabled,
                    "fim": {
                        "enabled": watched is not None,
                        "paths": [str(watched)] if watched else [],
                    },
                    "network": {"enable_api": False},
                    # A data directory, log sources.
                    **(settings or {}),
                }
            )
        )
        env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "PYTHONPATH": str(hooks),
            "HOME": str(tmp_path),
            "SENSOR_TEST_STOP_AT": stop_at.replace("CONFIG", str(config)),
            "SENSOR_TEST_HOLD": str(hold),
            "SENSOR_TEST_MARK": str(mark),
        }
        if slow_osquery:
            env["OSQUERY_SLOW"] = str(slow_osquery)
        began = time.monotonic()
        # As the image starts it: with SIGTERM blocked, which the child
        # inherits from this thread, and here with one already sent to it
        # before its interpreter has run a line.
        blocked = {signal.SIGTERM} if stop_before_it_starts else set()
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(SERVICE_ROOT / "main.py"),
                    "--config",
                    str(config),
                ],
                cwd=tmp_path,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                # A group of its own: what it started ends with it.
                start_new_session=True,
            )
            children.append(child)
            if stop_before_it_starts:
                child.send_signal(signal.SIGTERM)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        give_up = threading.Timer(
            GIVE_UP_SECONDS, os.killpg, (child.pid, signal.SIGKILL)
        )
        give_up.start()
        lines = []
        try:
            for line in child.stdout:
                lines.append(line)
                if at_line and at_line in line:
                    at_line = None
                    child.send_signal(signal.SIGTERM)
            code = child.wait()
        finally:
            give_up.cancel()
            child.stdout.close()
        return Run(code, "".join(lines), time.monotonic() - began, mark.exists())

    yield run
    for child in children:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


# -- the real process ---------------------------------------------------------


@pytest.mark.parametrize(
    "module",
    [
        # The first import after the handlers, some in the middle, and the
        # sensor's own modules.
        "argparse",
        "asyncio",
        "sensor.core.agent",
        "aiohttp",
        "yaml",
    ],
)
def test_a_stop_while_the_modules_are_imported_ends_the_sensor_in_order(sensor, module):
    run = sensor(f"import:{module}")

    assert run.reached, run
    # main: -15, the signal ended the process where it was (as process 1:
    # not delivered, and killed with status 137 when the grace period ended).
    assert run.code == 0, run
    assert (
        "Security Sensor not started: a stop was asked for while it was starting"
    ) in run.output
    assert "Traceback" not in run.output
    # Nothing was started, not even the reading of the configuration.
    assert "Starting Open Security Sensor" not in run.output
    assert run.seconds < GRACE_SECONDS


def test_a_stop_sent_before_the_interpreter_has_run_a_line_is_kept_and_obeyed(sensor):
    # The moment no handler can cover: the process exists and Python is
    # still starting. The image starts the sensor with the signal blocked
    # (`env --block-signal` in its CMD), so that it is kept until main.py
    # has a handler for it and unblocks it. main.py without that unblocking
    # would never receive it, nor any later one.
    run = sensor(stop_before_it_starts=True, log_forwarding=True)

    assert run.code == 0, run
    assert run.output.strip() == (
        "Security Sensor not started: a stop was asked for while it was starting"
    )
    assert run.seconds < GRACE_SECONDS


def test_the_image_starts_the_sensor_with_the_stop_signals_blocked():
    dockerfile = (SERVICE_ROOT / "Dockerfile").read_text()
    (command,) = [
        line
        for line in dockerfile.splitlines()
        if line.startswith(("CMD", "ENTRYPOINT"))
    ]

    assert command.startswith(
        'CMD ["env", "--block-signal=TERM", "--block-signal=INT", "python", "main.py",'
    )
    # And the build says so if the base image's env cannot do that: the
    # container would not start.
    assert "RUN env --block-signal=TERM --block-signal=INT true" in dockerfile


def test_a_stop_while_the_configuration_is_read_starts_nothing(sensor):
    run = sensor("open:CONFIG", log_forwarding=True)

    assert run.reached, run
    assert run.code == 0, run  # main: -15
    assert (
        "A stop was asked for before the sensor had started anything: "
        "nothing is started"
    ) in run.output
    assert "Starting Security Sensor Agent" not in run.output
    assert run.output.rstrip().endswith("nothing is started")
    assert "Traceback" not in run.output


def test_a_stop_while_the_agent_starts_abandons_the_start(sensor, tmp_path):
    # The start is held by an osqueryi that does not answer its first
    # query, and the stop is asked for then. main took the signal, and went
    # on waiting for the query, 30 seconds, before it began to stop.
    pid_file = tmp_path / "osqueryi.pid"

    run = sensor(slow_osquery=pid_file, process_events=True)

    assert run.reached, run
    assert run.code == 0, run
    assert (
        "A stop was asked for while the sensor was starting: the start is "
        "abandoned, and what it had started is stopped"
    ) in run.output
    assert "Security Sensor started successfully" not in run.output
    assert run.output.rstrip().endswith("Security Sensor stopped")
    assert "Traceback" not in run.output and "ERROR" not in run.output
    assert run.seconds < GRACE_SECONDS
    # The query it had begun did not outlive it.
    assert _gone(int(pid_file.read_text()))


def test_a_stop_during_a_first_scan_that_does_not_end_is_not_held_by_it(
    sensor, tmp_path
):
    # The file monitor's first scan is listing a directory that does not
    # answer, in its worker thread, which nothing can interrupt. main waited
    # for the scan before it began to stop; then the event loop, and the
    # interpreter after it, wait for the thread before the process ends.
    watched = tmp_path / "etc"
    watched.mkdir()
    (watched / "hosts").write_text("127.0.0.1 localhost\n")

    run = sensor(
        f"scandir:{watched}", hold=HOLD_SECONDS, watched=watched, file_monitoring=True
    )

    assert run.reached, run
    assert run.code == 0, run
    assert "the start is abandoned" in run.output
    assert "Security Sensor stopped" in run.output
    assert (
        "The sensor has stopped and its process has not ended after 2 "
        "seconds: it is waiting for threads that are still busy (asyncio_0"
    ) in run.output
    assert run.output.rstrip().endswith("The process ends without waiting for them")
    assert run.seconds < GRACE_SECONDS


def test_a_running_sensor_does_not_wait_for_a_lookup_the_resolver_never_answers(sensor):
    # The sensor runs; a worker looks up the name of an address osquery
    # reported, in a thread, and the resolver does not answer. The event is
    # passed on without the name after two seconds, as it always was; the
    # thread stays. main stopped in order and then did not exit: the
    # interpreter waited for the thread.
    run = sensor("lookup:203.0.113.9", hold=HOLD_SECONDS, network_connections=True)

    assert run.reached, run
    assert run.code == 0, run
    assert "Security Sensor started successfully" in run.output
    assert "Security Sensor stopped" in run.output
    assert "The process ends without waiting for them" in run.output
    assert run.seconds < GRACE_SECONDS


def test_a_stop_while_the_data_directory_does_not_answer_is_not_held_by_it(
    sensor, tmp_path
):
    # The periodic write of the log positions is putting its file in place,
    # in its worker thread, with the store's lock, and that call does not
    # return. The stop is asked for then. main wrote the positions once more
    # from the event loop as the forwarder stopped: the loop waited for the
    # lock, no limit of the stop could end, the one that ends the process
    # was not armed yet, and the sensor was there until it was killed.
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    log = tmp_path / "app.log"
    log.write_text("one\n")

    run = sensor(
        f"rename:{data_dir / 'log-positions.json'}",
        hold=HOLD_SECONDS,
        log_forwarding=True,
        settings={
            "data_dir": str(data_dir),
            "log_sources": [{"name": "app", "path": str(log), "format": "raw"}],
        },
    )

    assert run.reached, run
    assert run.code == 0, run  # main: -9, from the test, after a minute
    assert "Traceback" not in run.output
    said = [line.split(" - ", 3)[-1] for line in run.output.splitlines()]
    # The forwarder gives its own write up, the agent the last one, and
    # says what that means; then the sensor has stopped, and its process
    # leaves the three threads that are still waiting for that directory.
    limits = (
        "The log positions were not written within 2 seconds of the log "
        f"forwarder's stop: a write to {data_dir} has not ended",
        "Stopped without writing the log positions: the write had not ended "
        "after 2 seconds, and is left to its thread. If that stays so, after "
        "the restart the log sources are read from the positions last saved, "
        "and what was delivered since is sent again",
        "Security Sensor stopped",
    )
    assert [line for line in said if line in limits] == list(limits), run
    # Three threads: the write that is held, and the two that wait for it.
    assert said[-1].startswith(
        "The sensor has stopped and its process has not ended after 2 "
        "seconds: it is waiting for threads that are still busy (asyncio_0, "
        "asyncio_1, asyncio_2"
    ), run
    assert said[-1].endswith("The process ends without waiting for them")
    assert run.seconds < GRACE_SECONDS
    # Nothing was written, and the sensor did not say that anything was.
    assert not (data_dir / "log-positions.json").exists()


def test_a_stop_of_a_sensor_that_has_started_ends_without_the_exit_limit(sensor):
    # The ordinary stop, for comparison: nothing is abandoned, no thread
    # is left, and the process ends by itself.
    run = sensor(at_line="Security Sensor started successfully", log_forwarding=True)

    assert run.code == 0, run
    assert run.output.rstrip().endswith("Security Sensor stopped")
    assert "abandoned" not in run.output
    assert "without waiting" not in run.output


# -- the pieces, in this process ---------------------------------------------


@pytest.fixture
def handlers():
    """The process's signal handlers as they were, after the test. The
    event loop of an asynchronous test is closed by then, and has taken its
    own handlers away."""
    before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    yield
    for signum, handler in before.items():
        signal.signal(signum, handler)


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setattr(sensor_main, "setup_logging", lambda settings: None)
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "data_lake": {"endpoint": "https://gateway.example"},
                "fim": {"enabled": False},
                "network": {"enable_api": False},
            }
        )
    )
    return str(path)


def test_a_signal_is_noted_and_does_nothing_else(handlers):
    before = [signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)]
    asked = sensor_main.StopAsked()
    asked.watch()

    os.kill(os.getpid(), signal.SIGTERM)
    os.kill(os.getpid(), signal.SIGINT)

    # Still here: neither ended the process, nor raised KeyboardInterrupt.
    assert asked.signum == signal.SIGTERM  # the first one
    asked.unwatch()
    assert [signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)] == before


def test_importing_the_module_installs_nothing(handlers):
    # The handlers are the sensor's own process's, not those of whoever
    # imports main.py, as these tests do.
    assert signal.getsignal(signal.SIGTERM) != sensor_main.STOP_ASKED._note
    assert sensor_main.STOP_ASKED.signum is None


@pytest.mark.asyncio
async def test_a_stop_noted_before_the_loop_ran_starts_nothing(
    handlers, tmp_path, capsys
):
    asked = sensor_main.StopAsked()
    asked.signum = signal.SIGTERM
    # Not even the configuration is read: there is none at this path.
    daemon = sensor_main.SensorDaemon(str(tmp_path / "missing.yaml"), stop_asked=asked)

    assert await asyncio.wait_for(daemon.start(), timeout=10) == 0

    assert daemon.agent is None
    assert "a stop was asked for while it was starting" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_a_stop_noted_while_the_configuration_was_read_starts_nothing(
    handlers, config, monkeypatch, caplog
):
    asked = sensor_main.StopAsked()
    load = sensor_main.load_config
    started = []

    def loading(path):
        # As the handler at the top of main.py would, had SIGTERM come now.
        asked._note(signal.SIGTERM, None)
        return load(path)

    async def start(agent):
        started.append(agent)

    monkeypatch.setattr(sensor_main, "load_config", loading)
    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    daemon = sensor_main.SensorDaemon(config, stop_asked=asked)

    with caplog.at_level(logging.INFO):
        assert await asyncio.wait_for(daemon.start(), timeout=10) == 0

    assert started == []
    assert "nothing is started" in caplog.text
    assert daemon.running is False


@pytest.mark.asyncio
async def test_a_stop_while_the_agent_starts_cancels_the_start_and_stops_it(
    handlers, config, monkeypatch
):
    calls = []

    async def start(agent):
        calls.append("start")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            calls.append("start cancelled")
            raise

    async def stop(agent):
        calls.append("stop")

    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    monkeypatch.setattr(SecuritySensorAgent, "stop", stop)
    daemon = sensor_main.SensorDaemon(config)
    running = asyncio.ensure_future(daemon.start())
    while "start" not in calls:
        await asyncio.sleep(0)

    await daemon.stop()
    # main: start() was awaited to its end before the stop was looked at.
    assert await asyncio.wait_for(running, timeout=10) == 0

    assert calls == ["start", "start cancelled", "stop"]
    assert daemon.running is False


@pytest.mark.asyncio
async def test_a_real_signal_while_the_agent_starts_does_the_same(
    handlers, config, monkeypatch
):
    calls = []

    async def start(agent):
        calls.append("start")
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.Event().wait()

    async def stop(agent):
        calls.append("stop")

    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    monkeypatch.setattr(SecuritySensorAgent, "stop", stop)

    code = await asyncio.wait_for(sensor_main.SensorDaemon(config).start(), timeout=10)

    assert code == 0 and calls == ["start", "stop"]


@pytest.mark.asyncio
async def test_a_start_that_does_not_end_when_abandoned_is_not_waited_for(
    handlers, config, monkeypatch, caplog
):
    monkeypatch.setattr(sensor_main, "START_ABORT_SECONDS", 0.05)
    calls = []
    release = asyncio.Event()

    async def start(agent):
        calls.append("start")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await release.wait()

    async def stop(agent):
        calls.append("stop")

    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    monkeypatch.setattr(SecuritySensorAgent, "stop", stop)
    daemon = sensor_main.SensorDaemon(config)
    running = asyncio.ensure_future(daemon.start())
    while "start" not in calls:
        await asyncio.sleep(0)

    await daemon.stop()
    with caplog.at_level(logging.WARNING):
        assert await asyncio.wait_for(running, timeout=10) == 0

    assert calls == ["start", "stop"]
    assert "The start had not ended" in caplog.text
    release.set()


@pytest.mark.asyncio
async def test_a_start_that_fails_still_ends_with_status_1(
    handlers, config, monkeypatch
):
    stopped = []

    async def start(agent):
        raise RuntimeError("osquery not found")

    async def stop(agent):
        stopped.append(agent)

    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    monkeypatch.setattr(SecuritySensorAgent, "stop", stop)

    daemon = sensor_main.SensorDaemon(config)
    assert await asyncio.wait_for(daemon.start(), timeout=10) == 1
    # The agent stops what it had started by itself when its start fails;
    # the daemon does not stop it a second time.
    assert stopped == []


@pytest.mark.asyncio
async def test_a_start_that_fails_as_it_is_abandoned_ends_with_status_1(
    handlers, config, monkeypatch
):
    calls = []

    async def start(agent):
        calls.append("start")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise RuntimeError("failed while it was being cancelled") from None

    async def stop(agent):
        calls.append("stop")

    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    monkeypatch.setattr(SecuritySensorAgent, "stop", stop)
    daemon = sensor_main.SensorDaemon(config)
    running = asyncio.ensure_future(daemon.start())
    while "start" not in calls:
        await asyncio.sleep(0)

    await daemon.stop()

    assert await asyncio.wait_for(running, timeout=10) == 1
    assert calls == ["start"]


@pytest.mark.parametrize(
    "option", ["--validate-config", "--test-connection", "--status"]
)
def test_a_command_that_answers_and_exits_is_interrupted_as_any_command(
    handlers, config, monkeypatch, option
):
    # The handlers that only note a stop are for the daemon. Left in place
    # for these commands, Ctrl-C would do nothing at all.
    before = [signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)]
    seen = []

    async def connection(settings):
        seen.append(signal.getsignal(signal.SIGINT))
        return {"success": False, "endpoint": "nowhere", "error": "not asked"}

    def status(settings):
        seen.append(signal.getsignal(signal.SIGINT))
        return 1, ["not asked"]

    monkeypatch.setattr(sensor_main, "_test_connection", connection)
    monkeypatch.setattr("sensor.api.status_client.check", status)
    asked = sensor_main.StopAsked()
    asked.watch()
    monkeypatch.setattr(sensor_main, "STOP_ASKED", asked)
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", config, option])

    sensor_main.main()

    # Put back before the command did its work, not after.
    assert asked._note not in seen
    assert len(seen) == (0 if option == "--validate-config" else 1)
    assert [signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)] == before


def test_such_a_command_does_not_run_when_a_stop_was_already_asked_for(
    handlers, config, monkeypatch, capsys
):
    asked = sensor_main.StopAsked()
    asked.watch()
    os.kill(os.getpid(), signal.SIGTERM)
    monkeypatch.setattr(sensor_main, "STOP_ASKED", asked)
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--config", config, "--validate-config"]
    )

    assert sensor_main.main() == 128 + signal.SIGTERM
    assert capsys.readouterr().out == ""


def test_the_exit_limit_ends_the_process_with_the_sensors_status(monkeypatch, caplog):
    left = threading.Event()
    codes = []

    def leave(code):
        codes.append(code)
        left.set()

    monkeypatch.setattr(sensor_main.os, "_exit", leave)
    monkeypatch.setattr(sensor_main.logging, "shutdown", lambda: None)

    with caplog.at_level(logging.WARNING):
        timer = sensor_main._leave_within(0.01, 3)
        assert left.wait(timeout=10)

    assert codes == [3]
    # One more thread to wait for would defeat it.
    assert timer.daemon is True
    assert "The process ends without waiting for them" in caplog.text


@pytest.mark.asyncio
async def test_the_exit_limit_is_armed_when_the_daemon_has_stopped(monkeypatch):
    armed = []
    monkeypatch.setattr(
        sensor_main,
        "_leave_within",
        lambda seconds, code: armed.append((seconds, code)),
    )

    class Daemon:
        async def start(self):
            # Not while the sensor runs, or stops: only afterwards.
            assert armed == []
            return 7

    assert await sensor_main._run(Daemon()) == 7
    assert armed == [(sensor_main.EXIT_SECONDS, 7)]


# -- the limit of the last writes (#777) ---------------------------------------


class Noted:
    """What stands in for the exit limit: how it was armed, and whether it
    was taken away."""

    def __init__(self):
        self.armed = []
        self.cancelled = 0

    def __call__(self, seconds, code, stopped=True):
        self.armed.append((seconds, code, stopped))
        return types.SimpleNamespace(cancel=self._cancel)

    def _cancel(self):
        self.cancelled += 1


class Writes:
    """A log forwarder that has stopped, and whose last write is ``write``."""

    interrupted = ()

    def __init__(self, write):
        self._write = write

    async def stop(self):
        pass

    async def write_positions(self):
        return self._write()


@pytest.mark.asyncio
async def test_the_exit_limit_ends_a_sensor_whose_last_write_holds_the_event_loop(
    handlers, config, monkeypatch, caplog
):
    # What main's last write was: a call that waits in the event loop's own
    # thread. No timer of the loop can end it; the thread armed before it
    # does.
    monkeypatch.setattr(sensor_main, "LAST_WRITES_SECONDS", 0.05)
    monkeypatch.setattr(sensor_main, "EXIT_SECONDS", 0.05)
    left = threading.Event()
    codes = []

    def leave(code):
        codes.append(code)
        left.set()

    monkeypatch.setattr(sensor_main.os, "_exit", leave)
    monkeypatch.setattr(sensor_main.logging, "shutdown", lambda: None)

    def held():
        # Until the process "ends"; the test gives up long before a hang.
        assert left.wait(timeout=30), "nothing ended the process"

    async def start(agent):
        agent.log_forwarder = Writes(held)

    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    daemon = sensor_main.SensorDaemon(config)
    running = asyncio.ensure_future(daemon.start())
    while not daemon.running:
        await asyncio.sleep(0)

    await daemon.stop()
    with caplog.at_level(logging.WARNING):
        assert await asyncio.wait_for(running, timeout=60) == 0

    # With the status of an orderly stop, which is what was asked for.
    assert codes == [0]
    assert (
        "The sensor began to write its log positions and its file monitor's "
        "baseline for the last time and its process has not ended after 0 "
        "seconds"
    ) in caplog.text


@pytest.mark.asyncio
async def test_the_limit_of_the_last_writes_is_taken_away_when_the_daemon_has_stopped(
    handlers, config, monkeypatch
):
    noted = Noted()
    monkeypatch.setattr(sensor_main, "_leave_within", noted)
    seen = []

    async def start(agent):
        # Not armed while the sensor runs: only as its last writes begin.
        agent.log_forwarder = Writes(lambda: seen.append(list(noted.armed)))

    monkeypatch.setattr(SecuritySensorAgent, "start", start)
    daemon = sensor_main.SensorDaemon(config)
    running = asyncio.ensure_future(daemon.start())
    while not daemon.running:
        await asyncio.sleep(0)
    assert noted.armed == []

    await daemon.stop()
    assert await asyncio.wait_for(running, timeout=10) == 0

    limit = (sensor_main.LAST_WRITES_SECONDS + sensor_main.EXIT_SECONDS, 0, False)
    # Armed before the write was begun, once, and not left behind: _run()
    # arms the limit of the process's end as the daemon returns.
    assert seen == [[limit]]
    assert noted.armed == [limit] and noted.cancelled == 1


@pytest.mark.asyncio
async def test_a_start_that_fails_arms_that_limit_with_status_1(
    handlers, tmp_path, monkeypatch
):
    # The agent stops what a failed start had started, by itself, and
    # writes the positions as it does: the same limit, and the status the
    # process then ends with.
    noted = Noted()
    monkeypatch.setattr(sensor_main, "_leave_within", noted)
    monkeypatch.setattr(sensor_main, "setup_logging", lambda settings: None)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    log = tmp_path / "app.log"
    log.write_text("one\n")
    empty = tmp_path / "bin"
    empty.mkdir()
    # No osqueryi: the osquery manager's start fails.
    monkeypatch.setenv("PATH", str(empty))
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "data_lake": {"endpoint": "https://gateway.example"},
                "collection": {"process_events": True, "log_forwarding": True},
                "fim": {"enabled": False},
                "network": {"enable_api": False},
                "data_dir": str(data_dir),
                "log_sources": [{"name": "app", "path": str(log), "format": "raw"}],
            }
        )
    )

    daemon = sensor_main.SensorDaemon(str(path))
    assert await asyncio.wait_for(daemon.start(), timeout=30) == 1

    limit = (sensor_main.LAST_WRITES_SECONDS + sensor_main.EXIT_SECONDS, 1, False)
    assert noted.armed == [limit] and noted.cancelled == 1
