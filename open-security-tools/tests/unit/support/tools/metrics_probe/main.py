"""A tool that ends the way the test asks: every end a run can have."""

import os
import signal
import time

from .schemas import MetricsProbeInput, MetricsProbeOutput

TOOL_INFO = {
    "name": "metrics_probe",
    "display_name": "Metrics Probe",
    "description": "Test tool: returns, raises, sleeps, hangs or dies on request",
    "version": "1.0.0",
    "author": "Wildbox tests",
    "category": "test",
}


def _started_before(marker: str) -> bool:
    """Whether an earlier start of this task left ``marker``; leave it now."""
    if os.path.exists(marker):
        return True
    with open(marker, "w", encoding="utf-8"):
        pass
    return False


def _die() -> None:
    # The process is gone mid-task, as when the kernel kills it for memory.
    os.kill(os.getpid(), signal.SIGKILL)


def execute_tool(data: MetricsProbeInput) -> MetricsProbeOutput:
    if data.starts:
        # One line per call of the tool, whatever it then does.
        with open(data.starts, "a", encoding="utf-8") as starts:
            starts.write("called\n")
    if data.behaviour == "raise":
        # One of the five classes the task has always caught.
        raise ValueError("the probe was asked to fail")
    if data.behaviour == "quote":
        # As above, with an error that repeats the input it was raised over.
        raise ValueError(f"the probe cannot use {data.marker!r}")
    if data.behaviour == "crash":
        # Any other class. Celery used to call the tool again for it, twice.
        raise RuntimeError("the probe was asked to crash")
    if data.behaviour == "crash_quote":
        # As above, with an error that repeats the input it was raised over.
        raise RuntimeError(f"the probe crashed over {data.marker!r}")
    if data.behaviour == "touch":
        # Leaves a trace that the tool ran at all.
        _started_before(data.marker)
    if data.behaviour == "die":
        # Every start dies: a tool that takes its process down each time.
        # One line in the marker per start, so the test can count them.
        with open(data.marker, "a", encoding="utf-8") as starts:
            starts.write("started\n")
        _die()
    if data.behaviour == "die_once" and not _started_before(data.marker):
        # Celery puts the task back on the queue; the second start returns.
        _die()
    if data.behaviour == "sleep_once" and not _started_before(data.marker):
        # The first start sleeps (the test kills its worker meanwhile); the
        # start after the task comes back returns at once.
        time.sleep(data.seconds)
    if data.behaviour == "sleep":
        # Stops when the soft time limit raises in it.
        time.sleep(data.seconds)
    if data.behaviour == "hang":
        # Does not stop when asked: what a tool does that catches every
        # exception around its work, or is stuck outside Python. Only the
        # hard time limit, which kills the process, ends it.
        deadline = time.monotonic() + data.seconds
        while time.monotonic() < deadline:
            try:
                time.sleep(0.05)
            except Exception:  # noqa: BLE001 - the point of this branch
                pass
    return MetricsProbeOutput(success=True)
