"""
What the sensor's own process uses, measured and reported.

The monitor compares the process's memory and CPU with
``performance.max_memory_mb`` and ``performance.max_cpu_percent`` and says,
in the log and in the statistics (``over_limits``), when either is exceeded.
It slows nothing down (#745): the flag was called ``throttled`` and the log
said "throttling enabled", and no collector ever looked at it. Pausing a
collector because the sensor is busy would be a decision about what is not
watched meanwhile, and it is not taken here: the two settings are the
thresholds of a warning, and the flag is named for what it is.
"""

import asyncio
import logging
import time
from typing import Any, Dict, Optional

import psutil
from sensor.core.config import SensorConfig

logger = logging.getLogger(__name__)

# Seconds between two measurements.
MEASURE_INTERVAL = 5
# Seconds over_limits stays set after the last measurement over a limit, so
# that a process at the threshold is not reported at every measurement.
OVER_LIMITS_HOLD = 30


class ResourceMonitor:
    """Measure the sensor's memory and CPU, and say when they are over the
    configured thresholds"""

    def __init__(self, config: SensorConfig, stats: Dict[str, Any]):
        self.config = config
        self.stats = stats
        self.running = False
        self.process = psutil.Process()

        # Over a threshold now, or within the last OVER_LIMITS_HOLD seconds.
        self.over_limits = False
        self._over_until = 0.0
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        """Start resource monitoring"""
        self.running = True
        logger.info("Starting resource monitor")
        self._task = asyncio.create_task(self._monitor_resources())

    async def stop(self):
        """Stop resource monitoring"""
        self.running = False
        logger.info("Stopping resource monitor")
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def _measure(self):
        """One measurement, compared with the thresholds."""
        memory_mb = self.process.memory_info().rss / 1024 / 1024
        cpu_percent = self.process.cpu_percent()
        performance = self.config.performance
        over = (
            memory_mb > performance.max_memory_mb
            or cpu_percent > performance.max_cpu_percent
        )
        now = time.monotonic()

        if over:
            if not self.over_limits:
                logger.warning(
                    "The sensor uses more than its configured thresholds "
                    "(memory %.1f MB of performance.max_memory_mb %s, CPU "
                    "%.1f%% of performance.max_cpu_percent %s). Nothing is "
                    "slowed down: it is reported as over_limits in the "
                    "statistics",
                    memory_mb,
                    performance.max_memory_mb,
                    cpu_percent,
                    performance.max_cpu_percent,
                )
            self.over_limits = True
            self._over_until = now + OVER_LIMITS_HOLD
        elif self.over_limits and now >= self._over_until:
            logger.info("The sensor is back under its configured thresholds")
            self.over_limits = False

        self.stats.update(
            {
                "memory_mb": memory_mb,
                "cpu_percent": cpu_percent,
                "over_limits": self.over_limits,
            }
        )

    async def _monitor_resources(self):
        """Measure every MEASURE_INTERVAL seconds"""
        while self.running:
            try:
                self._measure()
                await asyncio.sleep(MEASURE_INTERVAL)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in resource monitoring: {e}")
                await asyncio.sleep(MEASURE_INTERVAL)
