#!/usr/bin/env python3
"""
Open Security Sensor - Main Entry Point

A lightweight, high-performance, cross-platform endpoint agent for comprehensive 
security telemetry collection and forwarding to the Open Security Data platform.
"""

# The stop signals are taken first, before anything else is imported (#765).
#
# In its container the sensor is process 1, and the kernel does not deliver
# to process 1 a signal it has no handler for. The handlers used to be
# installed in SensorDaemon.start(), after every import, the configuration
# and the agent: a `docker stop` in that time was not received at all, and
# the container was killed when its grace period ran out (exit status 137).
# Outside a container the same signal ended the process on the spot, which
# is no orderly stop either.
#
# That leaves the interpreter's own start, before the first line of this file
# runs: 5 to 35 ms in the image, in which 7 of 100 signals sent as soon as
# Docker allowed were still lost. No line of Python can cover it, so the
# image starts the sensor with the two signals blocked, and watch() below
# unblocks them once their handlers are installed.
import signal
import sys


class StopAsked:
    """A stop signal that arrives before the event loop can take it.

    The handler does one assignment and nothing else. It runs between two
    instructions of whatever the main thread is doing, an import or the
    reading of the configuration: there is no event loop yet whose objects
    it could touch, and logging or printing from there could meet the very
    call it interrupted. SensorDaemon.start() reads ``signum`` once the
    loop's own handlers are in place.
    """

    SIGNALS = (signal.SIGINT, signal.SIGTERM)

    def __init__(self):
        # The first stop signal received, or None.
        self.signum = None
        self._before = {}

    def watch(self):
        for signum in self.SIGNALS:
            self._before[signum] = signal.signal(signum, self._note)
        # The image starts the sensor with these two signals blocked (its
        # CMD runs `env --block-signal`). A blocked signal is kept, where
        # one without a handler is dropped: so a stop sent while the
        # interpreter itself was starting has waited for this line, and is
        # delivered now, to the handler just installed. Nothing changes
        # for a sensor started without them blocked.
        if hasattr(signal, "pthread_sigmask"):
            signal.pthread_sigmask(signal.SIG_UNBLOCK, self.SIGNALS)

    def unwatch(self):
        """Put back the handlers that were there: for the commands that
        answer and exit, which Ctrl-C interrupts as it does any command."""
        while self._before:
            signum, handler = self._before.popitem()
            signal.signal(signum, handler)

    def _note(self, signum, frame):
        if self.signum is None:
            self.signum = signum


STOP_ASKED = StopAsked()
if __name__ == "__main__":
    STOP_ASKED.watch()

import argparse  # noqa: E402
import asyncio  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import threading  # noqa: E402
from typing import Optional  # noqa: E402

from sensor.core.agent import SecuritySensorAgent  # noqa: E402
from sensor.core.config import SensorConfig, load_config  # noqa: E402
from sensor.core.stop_limits import LAST_WRITES_SECONDS  # noqa: E402
from sensor.utils.logging import setup_logging  # noqa: E402
from sensor.utils.platform import describe_platform  # noqa: E402

__version__ = "1.0.0"

logger = logging.getLogger(__name__)

# Two more of the stop's time limits; the others, and what they add up to,
# are in sensor/core/stop_limits.py.
#
# Seconds a start that is abandoned gets to end, when the stop is asked for
# while the sensor is starting: a query that was running is killed and
# waited for.
START_ABORT_SECONDS = 2.0
# Seconds the process gets to end by itself once the sensor has stopped. The
# event loop and the interpreter wait, without a limit of their own, for
# every worker thread: a reverse DNS lookup the resolver has not answered,
# a scan in a file system that does not answer, a write of the log positions
# to a data directory that does not. Such a thread cannot be interrupted,
# and the process leaves without it.
#
# The limit is armed twice (#777). First when the agent's last writes begin,
# for LAST_WRITES_SECONDS and these: from then on the process ends whatever
# the writes, the last log lines or the event loop itself do. Then, as
# before, when the sensor has stopped, for these alone. It used to be armed
# only then, after the writes, and a write that never returned was never
# followed by it.
EXIT_SECONDS = 2.0
# Seconds the exit limit's own last line, and the flush of the log after it,
# get before the process is ended whatever they do. The line is written by
# the log's handlers, and a handler can wait as long as a worker thread can:
# for a log file in a directory that does not answer, for a pipe nobody
# reads, for its own lock, held by a thread that is waiting for one of
# those. The limit used to log and flush in its own thread and end the
# process after that, so a handler that did not return held the one thing
# that was there to end the process (#788).
EXIT_LOG_SECONDS = 1.0


class SensorDaemon:
    """Main sensor daemon class"""

    def __init__(self, config_path: str = None, stop_asked: Optional[StopAsked] = None):
        self.config_path = config_path
        self.config = None
        self.agent = None
        self.running = False
        # Set when a signal, or stop(), asks the sensor to stop.
        self._stop_requested = None
        # The stop signals noted since the process started, if it is the
        # sensor's own process.
        self._stop_asked = stop_asked
        # Is the sensor stopping because it was asked to (exit status 0), or
        # is the agent stopping what a failed start had started (1)?
        self._stopping = False
        # The exit limit armed when the agent's last writes began.
        self._last_writes_limit: Optional[threading.Timer] = None

    async def start(self):
        """Run the sensor until it is asked to stop, and until it has
        stopped; its exit status."""
        try:
            return await self._run_and_stop()
        finally:
            # The daemon has ended, and _run() arms the exit limit proper
            # in its next statement.
            limit, self._last_writes_limit = self._last_writes_limit, None
            if limit is not None:
                limit.cancel()

    def _limit_the_last_writes(self):
        """Called by the agent as its last writes begin: arm the exit
        limit, for the time those writes are given and the process's own
        end. The writes are made in worker threads and the agent stops
        waiting for them by itself; this is for whatever does not keep to
        that, a call that holds the event loop included."""
        if self._last_writes_limit is None:
            self._last_writes_limit = _leave_within(
                LAST_WRITES_SECONDS + EXIT_SECONDS,
                0 if self._stopping else 1,
                stopped=False,
            )

    async def _run_and_stop(self):
        """Run the sensor until it is asked to stop, and until it has
        stopped.

        It used to return, and the process to end, as soon as a stop was
        asked for: the agent's own stopping, which sends the last batches
        and writes the log positions, was a task still running, cancelled
        with the event loop within a second.

        A stop may be asked for at any moment from the first line of this
        file on (#765), and ends the sensor in an orderly way whenever it
        comes: before anything is started, nothing is; while the agent is
        starting, the start is abandoned and what it had started is
        stopped. The start used to be waited for whatever it took (a first
        scan of the watched files, an osqueryi that does not answer for 30
        seconds) before the stop began.
        """
        self._stop_requested = asyncio.Event()
        if self._stop_asked is not None and self._stop_asked.signum is not None:
            # Asked for while the modules were being imported. Logging is
            # not set up yet at this point.
            print(
                "Security Sensor not started: a stop was asked for while it "
                "was starting",
                file=sys.stderr,
            )
            return 0

        asked = None
        starting = None
        try:
            # Load configuration. A configuration error is the operator's to
            # fix, so say what it is and stop, without a traceback; logging
            # is not set up yet at this point.
            try:
                self.config = load_config(self.config_path)
            except (FileNotFoundError, ValueError) as e:
                print(f"Security Sensor not started: {e}", file=sys.stderr)
                return 2

            # Setup logging
            setup_logging(self.config.logging)

            logger.info(f"Starting Open Security Sensor v{__version__}")
            # The system, its release, the architecture and the Python
            # version. Not the account or the environment: see
            # describe_platform().
            logger.info("Platform: %s", describe_platform())

            # Initialize the agent
            self.agent = SecuritySensorAgent(self.config)
            self.agent.before_last_writes = self._limit_the_last_writes

            # The event loop's handlers, here and not earlier: they act
            # when the loop runs, and nothing above lets it. Up to this
            # line a signal is noted by the handler installed at the top of
            # this file, which the loop's handlers take over from.
            self._setup_signal_handlers()
            if self._stop_requested.is_set():
                logger.info(
                    "A stop was asked for before the sensor had started "
                    "anything: nothing is started"
                )
                return 0

            # Start the agent, unless a stop is asked for first.
            starting = asyncio.ensure_future(self.agent.start())
            asked = asyncio.ensure_future(self._stop_requested.wait())
            await asyncio.wait({starting, asked}, return_when=asyncio.FIRST_COMPLETED)

            if starting.done():
                # Raises what the start raised.
                starting.result()
                self.running = True

                logger.info("Security Sensor started successfully")

                # Keep running until asked to stop.
                await asked
            elif not await self._abandon(starting):
                return 1

        except Exception as e:
            logger.error(f"Failed to start sensor: {e}", exc_info=True)
            return 1
        finally:
            for task in (asked, starting):
                if task is not None and not task.done():
                    task.cancel()

        # Here, and not in a task nobody waits for.
        await self._stop()
        return 0

    async def _abandon(self, starting) -> bool:
        """End a start that a stop has overtaken. False when the start had
        failed by itself meanwhile, and has stopped what it had started."""
        logger.info(
            "A stop was asked for while the sensor was starting: the start "
            "is abandoned, and what it had started is stopped"
        )
        starting.cancel()
        # Each component's start ends where it is. One that had begun a
        # query kills it and waits for it, which is why this is waited for,
        # and why not for long.
        done, _ = await asyncio.wait({starting}, timeout=START_ABORT_SECONDS)
        if not done:
            logger.warning(
                "The start had not ended %.0f seconds after it was "
                "abandoned: the stop goes on without waiting for it",
                START_ABORT_SECONDS,
            )
            # However it ends, nobody is left to ask.
            starting.add_done_callback(
                lambda task: task.cancelled() or task.exception()
            )
            return True
        if starting.cancelled() or starting.exception() is None:
            return True
        logger.error(
            "Failed to start sensor: %s", starting.exception(), exc_info=starting.exception()
        )
        return False

    async def stop(self):
        """Ask the sensor to stop; start() returns when it has."""
        if self._stop_requested is not None:
            self._stop_requested.set()

    async def _stop(self):
        logger.info("Stopping Security Sensor...")
        self.running = False
        self._stopping = True

        if self.agent:
            await self.agent.stop()

        logger.info("Security Sensor stopped")

    def _request_stop(self, signum):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self._stop_requested.set()

    def _setup_signal_handlers(self):
        """Stop on SIGINT and SIGTERM"""
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                # Wakes the event loop at once, wherever it is waiting.
                loop.add_signal_handler(signum, self._request_stop, signum)
            except (NotImplementedError, RuntimeError):
                # An event loop without signal support (Windows): the
                # handler runs outside the loop and hands over to it.
                signal.signal(
                    signum,
                    lambda received, frame: loop.call_soon_threadsafe(
                        self._request_stop, received
                    ),
                )
        # Read after the loop's handlers are in place, and not before: a
        # signal that arrives while they are being installed is seen by the
        # one or by the other.
        if self._stop_asked is not None and self._stop_asked.signum is not None:
            self._request_stop(self._stop_asked.signum)


def _leave_within(seconds: float, code: int, stopped: bool = True) -> threading.Timer:
    """End the process with ``code`` if it is still there in ``seconds``.

    Called when the sensor has stopped (``stopped``). See EXIT_SECONDS: what
    is left is the event loop's and the interpreter's own tidying up, which
    waits for worker threads for as long as they take. And called before
    that, when the sensor begins to write what it writes last.

    Nothing that can wait stands between the limit and the end of the
    process: why it ends is said, and the log flushed, in a thread of their
    own, which gets ``EXIT_LOG_SECONDS`` and is then left where it is.
    """

    def leave():
        said = threading.Thread(target=say, name="sensor-exit-log", daemon=True)
        said.start()
        said.join(EXIT_LOG_SECONDS)
        os._exit(code)

    def say():
        busy = [
            thread.name
            for thread in threading.enumerate()
            if thread is not threading.main_thread() and not thread.daemon
        ]
        logger.warning(
            "%s and its process has not ended after %.0f seconds: it is "
            "waiting for threads that are still busy (%s). The process ends "
            "without waiting for them",
            (
                "The sensor has stopped"
                if stopped
                else "The sensor began to write its log positions and its "
                "file monitor's baseline for the last time"
            ),
            seconds,
            ", ".join(busy) or "none is left",
        )
        logging.shutdown()
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except (OSError, ValueError):
                pass

    timer = threading.Timer(seconds, leave)
    # It must not itself be one more thread to wait for.
    timer.daemon = True
    timer.start()
    return timer


async def _run(daemon: SensorDaemon) -> int:
    """The daemon, from its start to the moment it has stopped."""
    code = 1
    try:
        code = await daemon.start()
        return code
    finally:
        _leave_within(EXIT_SECONDS, code)


async def _test_connection(config: SensorConfig) -> dict:
    """One empty batch through the forwarder's own session."""
    from sensor.pipeline.data_forwarder import DataForwarder

    forwarder = DataForwarder(config, asyncio.Queue())
    try:
        return await forwarder.test_connection()
    finally:
        if forwarder.session:
            await forwarder.session.close()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Open Security Sensor - Endpoint Telemetry Agent"
    )
    
    parser.add_argument(
        "--config", "-c",
        help="Path to configuration file",
        default=None
    )
    
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration file and exit"
    )
    
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="Test connection to data lake and exit"
    )
    
    parser.add_argument(
        "--status",
        action="store_true",
        help="Ask the running sensor's local API for its status and exit: "
             "0 running, 1 not running, 2 cannot be told"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"Open Security Sensor v{__version__}"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()

    if args.validate_config or args.test_connection or args.status:
        # A command that answers and exits is interrupted like any other:
        # the handlers that only note a stop are for the daemon.
        STOP_ASKED.unwatch()
        if STOP_ASKED.signum is not None:
            return 128 + STOP_ASKED.signum

    # Handle special commands
    if args.validate_config:
        try:
            config = load_config(args.config)
            print("✓ Configuration is valid")
            return 0
        except Exception as e:
            print(f"✗ Configuration error: {e}")
            return 1
    
    if args.test_connection:
        # Posts an empty batch to the gateway's ingest route with the
        # configured key: it proves the URL, the TLS trust, the key and its
        # data:ingest scope. This used to print success without connecting.
        try:
            config = load_config(args.config)
            result = asyncio.run(_test_connection(config))
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
            return 1
        if result["success"]:
            print(
                f"✓ {result['endpoint']} accepted the sensor's key "
                f"(HTTP {result['status_code']}, {result['response_time_ms']} ms)"
            )
            return 0
        print(f"✗ Connection test failed for {result['endpoint']}: {result['error']}")
        return 1
    
    if args.status:
        # Asks the running sensor's local API. This used to print
        # "Security Sensor Status: Running" without looking.
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"✗ Configuration error: {e}")
            return 1
        from sensor.api.status_client import check

        code, lines = check(config)
        print("\n".join(lines))
        return code
    
    # Start the daemon
    daemon = SensorDaemon(args.config, stop_asked=STOP_ASKED)

    try:
        return asyncio.run(_run(daemon))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
