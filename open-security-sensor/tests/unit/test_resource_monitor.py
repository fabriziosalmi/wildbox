"""The resource monitor reports, and says that it only reports (#745).

``performance.max_memory_mb`` and ``performance.max_cpu_percent`` set a flag
called ``throttled`` and a log line, "throttling enabled". Nothing read the
flag: no collector slowed down, no query was skipped. The flag is
``over_limits`` now, and the log says what happens, which is nothing.

The process measured is the test's own.
"""

import asyncio
import logging
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.core.config import (  # noqa: E402
    DataLakeConfig,
    PerformanceConfig,
    SensorConfig,
)
from sensor.utils import resource_monitor  # noqa: E402
from sensor.utils.resource_monitor import ResourceMonitor  # noqa: E402


def _monitor(max_memory_mb, max_cpu_percent=10**9):
    # CPU is out of the way unless a test asks: measured over the instant
    # between two calls, a process's share of a CPU can be anything.
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        performance=PerformanceConfig(
            max_memory_mb=max_memory_mb, max_cpu_percent=max_cpu_percent
        ),
    )
    stats = {}
    return ResourceMonitor(config, stats), stats


def _messages(caplog, level):
    return [r.getMessage() for r in caplog.records if r.levelno == level]


def test_over_a_threshold_is_reported_and_nothing_is_called_throttling(caplog):
    # This process uses more than one megabyte.
    monitor, stats = _monitor(max_memory_mb=1)

    with caplog.at_level(logging.INFO, logger=resource_monitor.__name__):
        monitor._measure()
        monitor._measure()

    assert stats["over_limits"] is True
    assert stats["memory_mb"] > 1
    assert stats["cpu_percent"] >= 0
    # main: a key named for something the sensor does not do.
    assert "throttled" not in stats
    (warning,) = _messages(caplog, logging.WARNING)  # once, not at each measure
    assert warning.startswith(
        "The sensor uses more than its configured thresholds (memory "
    )
    assert "of performance.max_memory_mb 1, CPU" in warning
    assert warning.endswith(
        "Nothing is slowed down: it is reported as over_limits in the statistics"
    )
    assert "throttl" not in caplog.text


def test_cpu_over_its_threshold_is_reported_too(caplog, monkeypatch):
    monitor, stats = _monitor(max_memory_mb=10**9, max_cpu_percent=5)
    monkeypatch.setattr(monitor.process, "cpu_percent", lambda: 12.5)

    with caplog.at_level(logging.WARNING, logger=resource_monitor.__name__):
        monitor._measure()

    assert stats["over_limits"] is True
    assert stats["cpu_percent"] == 12.5
    assert "CPU 12.5% of performance.max_cpu_percent 5)" in caplog.text


def test_under_the_thresholds_nothing_is_said(caplog):
    monitor, stats = _monitor(max_memory_mb=10**9)

    with caplog.at_level(logging.INFO, logger=resource_monitor.__name__):
        monitor._measure()

    assert stats["over_limits"] is False
    assert caplog.records == []


def test_the_flag_is_held_for_a_while_and_then_cleared(caplog, monkeypatch):
    monitor, stats = _monitor(max_memory_mb=1)
    clock = [1000.0]
    monkeypatch.setattr(resource_monitor.time, "monotonic", lambda: clock[0])

    with caplog.at_level(logging.INFO, logger=resource_monitor.__name__):
        monitor._measure()
        # Back under the threshold: not cleared at once, so that a process
        # at the threshold is not said to cross it at every measurement.
        monitor.config.performance.max_memory_mb = 10**9
        clock[0] += resource_monitor.OVER_LIMITS_HOLD - 1
        monitor._measure()
        held = stats["over_limits"]
        clock[0] += 1
        monitor._measure()

    assert held is True
    assert stats["over_limits"] is False
    assert _messages(caplog, logging.INFO) == [
        "The sensor is back under its configured thresholds"
    ]
    assert len(_messages(caplog, logging.WARNING)) == 1


def test_the_hold_counts_from_the_last_measurement_over_a_threshold(monkeypatch):
    monitor, stats = _monitor(max_memory_mb=1)
    clock = [1000.0]
    monkeypatch.setattr(resource_monitor.time, "monotonic", lambda: clock[0])
    hold = resource_monitor.OVER_LIMITS_HOLD

    monitor._measure()
    clock[0] += hold - 10
    monitor._measure()  # still over
    monitor.config.performance.max_memory_mb = 10**9
    clock[0] += hold - 10
    monitor._measure()
    held = stats["over_limits"]
    clock[0] += 10
    monitor._measure()

    assert held is True
    assert stats["over_limits"] is False


@pytest.mark.asyncio
async def test_it_measures_at_its_interval_and_stop_ends_it(monkeypatch):
    monkeypatch.setattr(resource_monitor, "MEASURE_INTERVAL", 0.01)
    monitor, stats = _monitor(max_memory_mb=10**9)
    measures = []
    real = monitor._measure
    monkeypatch.setattr(monitor, "_measure", lambda: (measures.append(1), real()))
    before = len(asyncio.all_tasks())

    await monitor.start()
    await asyncio.sleep(0.2)
    await monitor.stop()
    taken = len(measures)
    await asyncio.sleep(0.1)

    assert taken >= 3
    assert stats["memory_mb"] > 0
    # main: the task was not kept, and went on until its next sleep ended.
    assert len(measures) == taken
    assert len(asyncio.all_tasks()) == before


@pytest.mark.asyncio
async def test_stop_does_not_wait_for_the_next_measurement(monkeypatch):
    monkeypatch.setattr(resource_monitor, "MEASURE_INTERVAL", 30)
    monitor, stats = _monitor(max_memory_mb=10**9)

    await monitor.start()
    await asyncio.sleep(0.05)
    assert "memory_mb" in stats  # measured at once, not an interval later
    await asyncio.wait_for(monitor.stop(), timeout=2)

    assert monitor._task is None


def test_nothing_in_the_sensor_claims_to_throttle():
    for path in (SERVICE_ROOT / "sensor").rglob("*.py"):
        text = path.read_text()
        if path.name == "resource_monitor.py":
            # Its docstring says what the flag was called.
            text = text.split('"""', 2)[2]
        assert "throttl" not in text.lower(), path
