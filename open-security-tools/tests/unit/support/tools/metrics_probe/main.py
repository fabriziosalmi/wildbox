"""A tool that ends the way the test asks: every end a run can have."""

import os
import signal
import time

from .schemas import MetricsProbeInput, MetricsProbeOutput

TOOL_INFO = {
    "name": "metrics_probe",
    "display_name": "Metrics Probe",
    "description": "Test tool: returns, raises, sleeps or hangs on request",
    "version": "1.0.0",
    "author": "Wildbox tests",
    "category": "test",
}


def execute_tool(data: MetricsProbeInput) -> MetricsProbeOutput:
    if data.behaviour == "raise":
        # A type the task catches: the run is reported as failed.
        raise ValueError("the probe was asked to fail")
    if data.behaviour == "crash":
        # A type nothing catches: Celery retries the task, then fails it.
        raise RuntimeError("the probe was asked to crash")
    if data.behaviour == "die_once" and not os.path.exists(data.marker):
        # The process is gone mid-task, as when the kernel kills it for
        # memory. Celery puts the task back on the queue.
        with open(data.marker, "w", encoding="utf-8"):
            pass
        os.kill(os.getpid(), signal.SIGKILL)
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
