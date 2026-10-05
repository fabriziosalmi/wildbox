"""``main.py --status``: ask the running sensor how it is (#745).

The option printed "Security Sensor Status: Running" and exited 0 without
looking, on a host where no sensor ran as on one where it did. It now asks
the sensor's local API, at the address the configuration gives it:

* ``GET /health``, which needs no key: is a sensor there, and running;
* ``GET /api/v1/stats`` with ``network.api_key`` when one is configured:
  what it has collected and delivered, and whether it is delivering.

The answer is the exit status: 0 the sensor is running, 1 it is not (nothing
answers, or it is starting or stopping), 2 it cannot be told (the local API
is off, or what answers is not a sensor).

The requests go to the sensor's own address and nowhere else: no proxy of
the environment is used and no redirect is followed, so the key is sent to
nothing but the local API. It is never printed.
"""

import http.client
import json
import re
import urllib.error
import urllib.request
from typing import Any, List, Optional, Tuple

from sensor.core.config import SensorConfig

RUNNING, NOT_RUNNING, UNKNOWN = 0, 1, 2

# Seconds one request may take, and bytes of an answer that are read.
TIMEOUT = 5.0
MAX_ANSWER = 1024 * 1024

_WORD = re.compile(r"^[a-z_]{1,32}$")
_TIME = re.compile(r"^[0-9T:.+Z-]{1,40}$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, not somewhere to send the key."""

    def redirect_request(self, *args, **kwargs):
        return None


def _get(url: str, key: Optional[str] = None) -> Tuple[int, Any]:
    """The status of the answer and its JSON, or None when it is not JSON.

    Raises OSError or http.client.HTTPException when nothing answers.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={"X-API-Key": key} if key else {})
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            status, raw = response.status, response.read(MAX_ANSWER)
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read(MAX_ANSWER)
    try:
        return status, json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return status, None


def _address(config: SensorConfig) -> str:
    """Where the local API of this configuration listens, as a client
    reaches it."""
    host = config.network.bind_address
    if host in ("0.0.0.0", ""):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{config.network.bind_port}"


def _count(value: Any) -> str:
    """A counter as the sensor reports it, and nothing else that could have
    been put in its place."""
    if isinstance(value, bool) or not isinstance(value, int):
        return "?"
    return str(value)


def _why(error: Exception) -> str:
    reason = getattr(error, "reason", None) or error
    return getattr(reason, "strerror", None) or str(reason) or type(error).__name__


def check(config: SensorConfig) -> Tuple[int, List[str]]:
    """The exit status of ``--status`` and the lines it prints."""
    if not config.network.enable_api:
        return UNKNOWN, [
            "? The local API is off (network.enable_api: false): a running "
            "sensor cannot be asked for its status"
        ]
    base = _address(config)

    try:
        status, health = _get(f"{base}/health")
    except (OSError, http.client.HTTPException) as e:
        return NOT_RUNNING, [f"✗ No sensor answers at {base}: {_why(e)}"]
    state = health.get("status") if isinstance(health, dict) else None
    if state == "unhealthy" and status == 503:
        return NOT_RUNNING, [
            f"✗ The sensor at {base} is not running: it is starting or stopping"
        ]
    if state != "healthy" or status != 200:
        return UNKNOWN, [
            f"? What answers at {base}/health (HTTP {status}) is not a sensor"
        ]
    lines = [f"✓ The sensor at {base} is running"]

    key = config.network.api_key
    if not key:
        lines.append(
            "  Its counters need the local API's key (network.api_key, or "
            "SENSOR_API_KEY), which is not set"
        )
        return RUNNING, lines
    try:
        status, stats = _get(f"{base}/api/v1/stats", key)
    except (OSError, http.client.HTTPException) as e:
        lines.append(f"  Its counters could not be read: {_why(e)}")
        return RUNNING, lines
    if status != 200 or not isinstance(stats, dict):
        why = f"HTTP {status}"
        if status == 403:
            why += ": the configured network.api_key is not the running sensor's"
        lines.append(f"  Its counters could not be read: {why}")
        return RUNNING, lines

    lines.append(
        f"  Up {_count(stats.get('uptime_seconds'))} s. Events: "
        f"{_count(stats.get('events_collected'))} collected, "
        f"{_count(stats.get('events_forwarded'))} delivered, "
        f"{_count(stats.get('events_dropped'))} dropped, "
        f"{_count(stats.get('events_in_pipeline'))} waiting"
    )
    delivery = stats.get("delivery_state")
    if delivery == "ok":
        lines.append("  Delivering to the data service")
    elif isinstance(delivery, str) and _WORD.match(delivery):
        since = stats.get("delivery_since")
        when = (
            f" since {since}" if isinstance(since, str) and _TIME.match(since) else ""
        )
        lines.append(
            f"  NOT delivering to the data service: {delivery}{when}. See "
            f"data_forwarder in GET /api/v1/components"
        )
    return RUNNING, lines
