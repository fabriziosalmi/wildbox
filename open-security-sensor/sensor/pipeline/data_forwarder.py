"""
Data Forwarder

Forwards processed telemetry to the data service through the gateway, in
batches, and keeps what the gateway does not take yet.

How a batch gets in (#628): the sensor posts to the gateway's
``/api/v1/data/ingest`` with an identity personal API key in ``X-API-Key``. The
gateway resolves the key at identity, refuses it if it is invalid, expired,
revoked or lacks the ``data:ingest`` scope, and forwards the batch to the data
service with the key's user and team, which is the team the data service
stores the events under. The forwarder used to post to the data service
directly with ``Authorization: Bearer <key>``; the data service accepts only
requests the gateway has authenticated, so every batch was refused.

The key is a credential. It is set once, as a session header, and nothing here
logs it, the headers or the request.

The buffer (#725). Events wait here, serialized, until the gateway accepts
them:

* It is bounded: at most ``data_lake.buffer_max_events`` events and
  ``data_lake.buffer_max_bytes`` bytes of serialized events. The two queues
  before it hold at most ``performance.max_queue_size`` events each.
* A batch is the oldest events, at most ``batch_size`` of them and
  ``MAX_BATCH_BYTES`` bytes. It leaves the buffer when the gateway answers:
  accepted, or refused. A batch that fails for a reason that may pass (a
  network error, HTTP 429, a 5xx answer) stays where it is, whole, and is
  sent again after a delay that doubles from ``retry_delay`` up to
  ``retry_max_delay``, for as long as it takes.
* Nothing is dropped to make room. When the buffer is full the forwarder
  stops taking events, the queues fill, and the collectors wait: a log source
  goes on later from where it stopped, the file monitor reports what changed
  when it scans again, and osquery's snapshots are not taken meanwhile.
* What is dropped, and counted under ``events_dropped_*``: the events of a
  batch the gateway refuses (a 4xx answer: sending it again would get the
  same answer), an event that cannot be serialized or is larger than a
  batch may be, every event while no API key is configured, and what is
  still here when the sensor stops.
"""

import asyncio
import json
import logging
import random
import socket
import ssl
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from itertools import islice
from typing import Any, Deque, Dict, List, Optional

import aiohttp
from sensor.core.config import MAX_BATCH_BYTES, SensorConfig

logger = logging.getLogger(__name__)

USER_AGENT = "Open-Security-Sensor/1.0"

# The data service's telemetry event types, chosen from the type a collector
# gives an event: osquery events are "<pack>.<query>", the file monitor's
# "file_<change>", the log forwarder's "log.<source>". First match wins.
_EVENT_TYPES = (
    ("process_events.", "process_event"),
    ("network.", "network_connection"),
    ("user_events.", "user_event"),
    ("system_inventory.", "system_inventory"),
    ("file_", "file_change"),
)
_DEFAULT_EVENT_TYPE = "security_event"

# Outcome of one POST.
SENT = "sent"
RETRY = "retry"  # transient: network error, 429, 5xx
REFUSED = "refused"  # the request itself is wrong: retrying cannot help

# Why an event leaves the sensor without reaching the data service.
DROP_REASONS = ("refused", "oversize", "unserializable", "unconfigured", "shutdown")
# Seconds to wait after an HTTP 429 that names no Retry-After.
RATE_LIMIT_DELAY = 10
# Seconds the last batches get when the sensor stops.
STOP_FLUSH_SECONDS = 10
# Seconds between two log lines that sum up what was dropped.
DROP_REPORT_INTERVAL = 60


def ingest_event_type(sensor_type: Any) -> str:
    """The data service's event type for a collector's event type."""
    text = str(sensor_type or "")
    for prefix, event_type in _EVENT_TYPES:
        if text.startswith(prefix):
            return event_type
    return _DEFAULT_EVENT_TYPE


def _iso_timestamp(value: Any) -> str:
    """The event's time as ISO 8601, or now if it has none that parses.

    The data service validates every event of a batch, so one unparseable
    timestamp would get the whole batch refused.
    """
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.isoformat()
    return datetime.now(timezone.utc).isoformat()


def to_ingest_event(event: Dict[str, Any], sensor_id: str) -> Dict[str, Any]:
    """One processed event in the shape the data service's ingest accepts.

    The processed event is kept whole in ``event_data``, so nothing the
    collectors and the processor produced is lost; the collector's own type
    (``log.nginx_access``, ``network.listening_ports``...) is also a tag.
    """
    host = event.get("host") if isinstance(event.get("host"), dict) else {}
    sensor_type = event.get("type")
    tags = [str(sensor_type)] if sensor_type else []
    extra_tags = event.get("tags")
    if isinstance(extra_tags, list):
        tags.extend(str(tag) for tag in extra_tags if tag not in (None, ""))
    return {
        "sensor_id": sensor_id,
        "event_type": ingest_event_type(sensor_type),
        "timestamp": _iso_timestamp(event.get("timestamp")),
        "source_host": host.get("hostname"),
        "event_data": event,
        "tags": tags,
    }


def build_batch(events: List[Dict[str, Any]], sensor_id: str) -> Dict[str, Any]:
    """The body of POST /api/v1/data/ingest for these events.

    It carries no team: the team is the one the gateway resolves from the key,
    and the data service ignores anything else.
    """
    return {
        "batch_id": str(uuid.uuid4()),
        "events": [to_ingest_event(event, sensor_id) for event in events],
    }


def encode_event(event: Dict[str, Any], sensor_id: str) -> bytes:
    """One event as it travels in a batch: the JSON of ``to_ingest_event``.

    Raises TypeError or ValueError for an event JSON cannot carry: a value
    of a type it has none for, or NaN, which the data service would refuse
    with the whole batch.
    """
    return json.dumps(to_ingest_event(event, sensor_id), allow_nan=False).encode(
        "utf-8"
    )


def encode_batch(bodies: List[bytes]) -> bytes:
    """The request body for events already encoded; see ``build_batch``."""
    head = json.dumps({"batch_id": str(uuid.uuid4())})[:-1].encode("utf-8")
    return head + b', "events": [' + b",".join(bodies) + b"]}"


def retry_delay(failures: int, first: float, longest: float) -> float:
    """Seconds to wait after ``failures`` failed attempts in a row.

    ``first`` after the first one, twice as long after each further one, and
    never more than ``longest``.
    """
    if failures < 1 or first <= 0:
        return 0.0
    return float(min(first * 2 ** min(failures - 1, 32), max(longest, first)))


def build_ssl_context(tls_verify: bool, ca_bundle: Optional[str]) -> ssl.SSLContext:
    """The TLS context for the gateway: verified unless explicitly disabled.

    With ``ca_bundle`` the gateway's certificate is verified against that
    bundle; without it, against the system's trust store.
    """
    if not tls_verify:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=ca_bundle or None)


class DataForwarder:
    """Forward processed data to the data service, through the gateway."""

    def __init__(self, config: SensorConfig, input_queue: asyncio.Queue):
        self.config = config
        self.input_queue = input_queue
        self.running = False

        # HTTP session for connections
        self.session: Optional[aiohttp.ClientSession] = None

        # The events waiting for the gateway, oldest first, as they will be
        # sent; see the module's description for the bounds.
        self.buffer: Deque[bytes] = deque()
        self.buffer_bytes = 0
        self.max_events = config.data_lake.buffer_max_events
        self.max_bytes = config.data_lake.buffer_max_bytes
        # An event that no batch could carry is not kept.
        self.max_event_bytes = min(MAX_BATCH_BYTES, self.max_bytes)
        self._oldest_since = time.monotonic()
        self._full_since: Optional[float] = None
        self._in_hand: Optional[bytes] = None
        self._room = asyncio.Event()
        self._wake = asyncio.Event()
        self._stopping = asyncio.Event()
        self._tasks: List[asyncio.Task] = []

        self.sensor_id = config.data_lake.sensor_id or socket.gethostname()

        # Statistics. events_received is every event taken from the pipeline:
        # it equals events_forwarded + events_dropped + what the buffer holds.
        self.stats: Dict[str, Any] = {
            "events_received": 0,
            "events_forwarded": 0,
            "events_dropped": 0,
            "batches_sent": 0,
            "batches_refused": 0,
            "send_failures": 0,
            "times_buffer_full": 0,
            "network_errors": 0,
            "api_errors": 0,
            "last_successful_send": None,
            "last_error": None,
        }
        for reason in DROP_REASONS:
            self.stats[f"events_dropped_{reason}"] = 0
        self._dropped_reported = dict.fromkeys(DROP_REASONS, 0)
        self._next_drop_report = time.monotonic() + DROP_REPORT_INTERVAL

        # Consecutive attempts that failed for a reason that may pass.
        self.failures = 0
        self._retry_after = 0.0
        self._next_attempt: Optional[float] = None

        # Rate limiting
        self.last_request_time = 0.0
        self.min_request_interval = 1.0  # Minimum seconds between requests

    @property
    def enabled(self) -> bool:
        return self.config.data_lake.forwarding_enabled

    async def start(self):
        """Start data forwarding"""
        logger.info("Starting data forwarder")
        self.running = True

        for key in self.config.data_lake.obsolete_keys:
            logger.warning(
                "data_lake.%s is set and no longer used: a batch that fails "
                "for a reason that may pass is kept and sent again until the "
                "gateway answers for it. Remove the key; see "
                "data_lake.retry_max_delay and data_lake.buffer_max_events",
                key,
            )

        try:
            if self.enabled:
                await self._init_session()
                logger.info(
                    "Events are kept until the gateway accepts them, up to %d "
                    "events and %d bytes; beyond that the collectors wait",
                    self.max_events,
                    self.max_bytes,
                )
            else:
                logger.warning(
                    "Telemetry forwarding is disabled: data_lake.api_key "
                    "(SENSOR_DATA_LAKE_API_KEY) is not set. Create an identity "
                    "API key with the data:ingest scope for the sensor's team "
                    "member, set it, and restart the sensor. Events are "
                    "collected and discarded until then."
                )

            # Start forwarding tasks
            self._tasks = [
                asyncio.create_task(self._collect_events()),
                asyncio.create_task(self._send_batches()),
            ]

            logger.info("Data forwarder started successfully")

        except Exception as e:
            logger.error(f"Failed to start data forwarder: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Stop data forwarding"""
        logger.info("Stopping data forwarder")
        self.running = False
        # A gateway that does not answer must not keep the sensor from
        # stopping: everything below shares this much time.
        deadline = time.monotonic() + STOP_FLUSH_SECONDS

        tasks, self._tasks = self._tasks, []
        if tasks:
            collecting, sending = tasks
            collecting.cancel()
            # The sender is not cancelled: a request the gateway is
            # answering would be sent a second time by the lines below. It
            # ends by itself after the attempt it is making, if any.
            self._stopping.set()
            self._wake.set()
            try:
                await asyncio.wait_for(sending, STOP_FLUSH_SECONDS)
            except asyncio.TimeoutError:
                pass
            await asyncio.gather(*tasks, return_exceptions=True)
        if self._in_hand is not None:
            # Taken from the queue and still waiting for room.
            self._hold(self._in_hand)
            self._in_hand = None

        # The last batches.
        if self.session and not self.session.closed:
            while self.buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    outcome = await asyncio.wait_for(self._flush_batch(), remaining)
                except asyncio.TimeoutError:
                    break
                if outcome == RETRY:
                    break

        if self.buffer:
            left = len(self.buffer)
            self._release(left)
            self._count_dropped("shutdown", left)
            logger.warning(
                "Stopped with %d events the gateway had not accepted: they "
                "are dropped",
                left,
            )
        self._report_drops(force=True)

        # Close HTTP session
        if self.session:
            await self.session.close()

    def _headers(self) -> Dict[str, str]:
        """The session's headers. The key goes in X-API-Key, which the gateway
        authenticates and strips before it forwards the request."""
        return {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "X-API-Key": self.config.data_lake.api_key.strip(),
        }

    async def _init_session(self):
        """Initialize HTTP session with proper configuration"""
        data_lake = self.config.data_lake

        ssl_context = build_ssl_context(data_lake.tls_verify, data_lake.ca_bundle)
        if not data_lake.tls_verify:
            logger.warning(
                "TLS verification of the gateway is disabled "
                "(data_lake.tls_verify: false): the API key is sent to whoever "
                "answers. Set data_lake.ca_bundle to the gateway's certificate "
                "instead."
            )

        # Connector configuration
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=10,
            limit_per_host=5,
            keepalive_timeout=30,
            enable_cleanup_closed=True,
        )

        # Timeout configuration
        timeout = aiohttp.ClientTimeout(
            total=data_lake.timeout, connect=10, sock_read=data_lake.timeout
        )

        self.session = aiohttp.ClientSession(
            timeout=timeout, connector=connector, headers=self._headers()
        )

        logger.info(
            "HTTP session initialized for %s (sensor_id %s, TLS %s)",
            data_lake.ingest_url,
            self.sensor_id,
            (
                f"verified against {data_lake.ca_bundle}"
                if data_lake.tls_verify and data_lake.ca_bundle
                else "verified" if data_lake.tls_verify else "NOT verified"
            ),
        )

    # -- the buffer -------------------------------------------------------

    def accept(self, event: Dict[str, Any]) -> bool:
        """Take one processed event; False when it is dropped instead.

        It does not wait for room: the running forwarder takes events with
        ``_collect_events``, which does.
        """
        body = self._prepare(event)
        if body is None:
            return False
        self._hold(body)
        return True

    def _prepare(self, event: Dict[str, Any]) -> Optional[bytes]:
        """The event as it will be sent, or None when it is dropped."""
        self.stats["events_received"] += 1
        if not self.enabled:
            # Nowhere to send it; keeping it would only fill the buffer.
            self._count_dropped("unconfigured")
            return None
        event_type = event.get("type") if isinstance(event, dict) else None
        try:
            body = encode_event(event, self.sensor_id)
        except (TypeError, ValueError, AttributeError) as e:
            self._count_dropped("unserializable")
            logger.warning(
                "Dropped an event of type %r that JSON cannot carry: %s",
                event_type,
                e,
            )
            return None
        if len(body) > self.max_event_bytes:
            self._count_dropped("oversize")
            logger.warning(
                "Dropped an event of type %r: its %d bytes are more than a "
                "batch may be (%d)",
                event_type,
                len(body),
                self.max_event_bytes,
            )
            return None
        return body

    def _hold(self, body: bytes):
        if not self.buffer:
            self._oldest_since = time.monotonic()
        self.buffer.append(body)
        self.buffer_bytes += len(body)
        if len(self.buffer) in (1, self.config.data_lake.batch_size):
            # The sender has a deadline to compute, or a batch to send.
            self._wake.set()

    def _lacks_room(self, size: int) -> bool:
        if len(self.buffer) >= self.max_events:
            return True
        return bool(self.buffer) and self.buffer_bytes + size > self.max_bytes

    def _release(self, count: int):
        """Take the ``count`` oldest events out of the buffer."""
        for _ in range(count):
            self.buffer_bytes -= len(self.buffer.popleft())
        self._oldest_since = time.monotonic()
        self._room.set()
        if self._full_since is not None and not self._lacks_room(0):
            logger.info(
                "The buffer has room again after %.0f seconds: taking events "
                "from the collectors",
                time.monotonic() - self._full_since,
            )
            self._full_since = None

    def _count_dropped(self, reason: str, count: int = 1):
        self.stats[f"events_dropped_{reason}"] += count
        self.stats["events_dropped"] += count

    def _report_drops(self, force: bool = False):
        """One line for what was dropped since the last one, if anything."""
        now = time.monotonic()
        if not force and now < self._next_drop_report:
            return
        self._next_drop_report = now + DROP_REPORT_INTERVAL
        new = {
            reason: self.stats[f"events_dropped_{reason}"]
            - self._dropped_reported[reason]
            for reason in DROP_REASONS
        }
        if not any(new.values()):
            return
        for reason in DROP_REASONS:
            self._dropped_reported[reason] = self.stats[f"events_dropped_{reason}"]
        logger.warning(
            "Dropped %d events since the last report (%s); %d since the "
            "sensor started",
            sum(new.values()),
            ", ".join(f"{reason}: {count}" for reason, count in new.items() if count),
            self.stats["events_dropped"],
        )

    async def _collect_events(self):
        """Move events from the pipeline into the buffer, while it has room"""
        while self.running:
            try:
                event = await self.input_queue.get()
                body = self._prepare(event)
                if body is None:
                    continue
                self._in_hand = body
                while self._lacks_room(len(body)):
                    if self._full_since is None:
                        self._full_since = time.monotonic()
                        self.stats["times_buffer_full"] += 1
                        logger.warning(
                            "The buffer is full (%d events, %d bytes) and the "
                            "gateway accepts none: the sensor stops taking "
                            "events from its collectors until a batch is "
                            "accepted. Log sources continue later from where "
                            "they stopped",
                            len(self.buffer),
                            self.buffer_bytes,
                        )
                    self._room.clear()
                    await self._room.wait()
                self._in_hand = None
                self._hold(body)

            except asyncio.CancelledError:
                break

            except Exception as e:
                logger.error(f"Error collecting events: {e}")
                await asyncio.sleep(1)

    # -- sending ----------------------------------------------------------

    def _until_due(self) -> float:
        """Seconds until the oldest events are to be sent; 0 when they are."""
        data_lake = self.config.data_lake
        if not self.buffer:
            return float(data_lake.flush_interval)
        if (
            len(self.buffer) >= data_lake.batch_size
            or self.buffer_bytes >= MAX_BATCH_BYTES
        ):
            return 0.0
        waited = time.monotonic() - self._oldest_since
        return max(0.0, data_lake.flush_interval - waited)

    async def _send_batches(self):
        """Send the buffer's batches as they fall due; back off when one fails"""
        while self.running:
            try:
                self._report_drops()
                wait = self._until_due()
                if wait > 0:
                    self._wake.clear()
                    try:
                        await asyncio.wait_for(self._wake.wait(), timeout=wait)
                    except asyncio.TimeoutError:
                        pass
                    continue

                if await self._flush_batch() != RETRY:
                    continue
                delay = self._backoff()
                self._next_attempt = time.time() + delay
                logger.warning(
                    "The batch was not accepted (attempt %d in a row): it is "
                    "kept and sent again in %.0f seconds. The buffer holds %d "
                    "events (%d bytes)",
                    self.failures,
                    delay,
                    len(self.buffer),
                    self.buffer_bytes,
                )
                await self._pause(delay)
                self._next_attempt = None

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error sending batches: {e}")
                await asyncio.sleep(1)

    async def _pause(self, seconds: float):
        """Wait before the next attempt, unless the forwarder is stopping."""
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    def _backoff(self) -> float:
        """Seconds before the next attempt, after ``self.failures`` failures."""
        data_lake = self.config.data_lake
        delay = retry_delay(
            self.failures, data_lake.retry_delay, data_lake.retry_max_delay
        )
        # Up to a fifth less, so that the sensors of a site do not all come
        # back at the same instant.
        delay *= random.uniform(0.8, 1.0)  # nosec B311 - not a secret
        return max(delay, self._retry_after)

    def _next_batch(self) -> int:
        """How many of the oldest events the next batch takes."""
        count = size = 0
        for body in islice(self.buffer, self.config.data_lake.batch_size):
            if count and size + len(body) > MAX_BATCH_BYTES:
                break
            count += 1
            size += len(body)
        return count

    async def _flush_batch(self) -> Optional[str]:
        """Send the oldest events as one batch: SENT, RETRY or REFUSED.

        None when there is nothing to send. The events leave the buffer when
        the gateway has answered for them, and stay in it, in their place,
        when the attempt fails for a reason that may pass.
        """
        count = self._next_batch()
        if not count:
            return None

        logger.debug(f"Flushing batch of {count} events")
        self._retry_after = 0.0
        outcome = await self._send(encode_batch(list(islice(self.buffer, count))))

        if outcome == RETRY:
            self.failures += 1
            self.stats["send_failures"] += 1
            return RETRY

        self.failures = 0
        self._release(count)
        if outcome == SENT:
            self.stats["batches_sent"] += 1
            self.stats["events_forwarded"] += count
            self.stats["last_successful_send"] = datetime.now(timezone.utc).isoformat()
            logger.debug(f"Successfully forwarded batch of {count} events")
        else:
            # Not kept: a refused batch sent again gets the same answer, and
            # would hold back everything collected after it for good.
            self.stats["batches_refused"] += 1
            self._count_dropped("refused", count)
            logger.error(
                "The gateway refused a batch of %d events (%s): they are " "dropped",
                count,
                self.stats["last_error"],
            )
        return outcome

    async def _send(self, body: bytes) -> str:
        """One attempt for one batch; SENT, RETRY or REFUSED."""
        try:
            await self._apply_rate_limiting()
            return await self._send_http_request(body)
        except Exception as e:
            logger.error(f"Error sending batch: {e}")
            self.stats["network_errors"] += 1
            self.stats["last_error"] = str(e)
            return RETRY

    async def _apply_rate_limiting(self):
        """Apply rate limiting to prevent overwhelming the API"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.min_request_interval:
            wait_time = self.min_request_interval - time_since_last
            await asyncio.sleep(wait_time)

        self.last_request_time = time.time()

    def _post(self, body: bytes):
        """POST to the ingest URL. Redirects are not followed: a redirected
        request would carry the API key to wherever the redirect points."""
        return self.session.post(
            self.config.data_lake.ingest_url, data=body, allow_redirects=False
        )

    async def _send_http_request(self, body: bytes) -> str:
        """Send one batch; SENT, RETRY or REFUSED."""
        try:
            async with self._post(body) as response:
                if response.status in (200, 201):
                    return SENT

                detail = (await response.text())[:300]
                self.stats["api_errors"] += 1
                self.stats["last_error"] = f"HTTP {response.status}"

                if response.status == 429:
                    self._retry_after = self._rate_limit_delay(response)
                    logger.warning(
                        "API rate limit hit, backing off for at least %.0f " "seconds",
                        self._retry_after,
                    )
                    return RETRY
                if response.status == 401:
                    logger.error(
                        "The gateway refused the sensor's API key (HTTP 401): "
                        "it is invalid, expired or revoked. Set "
                        "data_lake.api_key to a valid identity API key."
                    )
                    return REFUSED
                if response.status == 403:
                    logger.error(
                        "The gateway refused the batch (HTTP 403): %s. The "
                        "sensor's API key needs the data:ingest scope.",
                        detail,
                    )
                    return REFUSED
                if 300 <= response.status < 400:
                    logger.error(
                        "The ingest URL %s answered HTTP %s (a redirect). "
                        "data_lake.endpoint must be the gateway's https:// URL.",
                        self.config.data_lake.ingest_url,
                        response.status,
                    )
                    return REFUSED
                if 400 <= response.status < 500:
                    logger.error(f"API client error {response.status}: {detail}")
                    return REFUSED

                # Server error - can retry
                logger.error(f"API server error {response.status}: {detail}")
                return RETRY

        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error: {e}")
            self.stats["network_errors"] += 1
            self.stats["last_error"] = str(e)
            return RETRY
        except Exception as e:
            logger.error(f"Unexpected HTTP error: {e}")
            self.stats["network_errors"] += 1
            self.stats["last_error"] = str(e)
            return RETRY

    def _rate_limit_delay(self, response) -> float:
        """Seconds a 429 asks for: its Retry-After, within retry_max_delay."""
        try:
            asked = float(response.headers.get("Retry-After", ""))
        except ValueError:
            return float(RATE_LIMIT_DELAY)
        if asked != asked or asked < 0:  # NaN, or a time already past
            return float(RATE_LIMIT_DELAY)
        return min(asked, float(self.config.data_lake.retry_max_delay))

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the data lake API.

        Posts an empty batch: the gateway authenticates the key and checks its
        scope, and the data service answers 200 with nothing ingested.
        """
        test_result = {
            "success": False,
            "response_time_ms": None,
            "status_code": None,
            "endpoint": self.config.data_lake.ingest_url,
            "error": None,
        }

        if not self.enabled:
            test_result["error"] = (
                "data_lake.api_key is not set: forwarding is disabled"
            )
            return test_result

        if not self.session:
            await self._init_session()

        try:
            start_time = time.time()

            async with self._post(encode_batch([])) as response:
                response_time_ms = int((time.time() - start_time) * 1000)
                test_result["response_time_ms"] = response_time_ms
                test_result["status_code"] = response.status

                if response.status in (200, 201):
                    test_result["success"] = True
                else:
                    error_text = (await response.text())[:300]
                    test_result["error"] = f"HTTP {response.status}: {error_text}"

        except Exception as e:
            test_result["error"] = str(e)

        return test_result

    def get_status(self) -> Dict[str, Any]:
        """Get forwarder status"""
        data_lake = self.config.data_lake
        next_attempt = None
        if self._next_attempt is not None:
            next_attempt = datetime.fromtimestamp(
                self._next_attempt, timezone.utc
            ).isoformat()
        return {
            "running": self.running,
            "forwarding_enabled": self.enabled,
            "endpoint": data_lake.ingest_url,
            "sensor_id": self.sensor_id,
            "tls_verify": data_lake.tls_verify,
            "batch_size": data_lake.batch_size,
            "flush_interval": data_lake.flush_interval,
            "buffer": {
                "events": len(self.buffer),
                "bytes": self.buffer_bytes,
                "max_events": self.max_events,
                "max_bytes": self.max_bytes,
                # Full: no event is taken from the collectors until a batch
                # is accepted.
                "full": self._full_since is not None,
            },
            "retry": {
                "consecutive_failures": self.failures,
                "next_attempt": next_attempt,
            },
            "queue_size": self.input_queue.qsize(),
            "stats": self.stats.copy(),
            "session_active": self.session is not None and not self.session.closed,
        }
