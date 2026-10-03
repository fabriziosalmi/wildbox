"""
Data Forwarder

Forwards processed telemetry to the data service through the gateway, in
batches, with retries.

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
"""

import asyncio
import logging
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp
from sensor.core.config import SensorConfig

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

        # Batching
        self.batch_buffer: List[Dict[str, Any]] = []
        self.last_flush_time = time.time()

        self.sensor_id = config.data_lake.sensor_id or socket.gethostname()

        # Statistics
        self.stats = {
            "batches_sent": 0,
            "events_forwarded": 0,
            "events_failed": 0,
            "events_dropped_unconfigured": 0,
            "network_errors": 0,
            "api_errors": 0,
            "last_successful_send": None,
            "last_error": None,
        }

        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1.0  # Minimum seconds between requests

    @property
    def enabled(self) -> bool:
        return self.config.data_lake.forwarding_enabled

    async def start(self):
        """Start data forwarding"""
        logger.info("Starting data forwarder")
        self.running = True

        try:
            if self.enabled:
                await self._init_session()
            else:
                logger.warning(
                    "Telemetry forwarding is disabled: data_lake.api_key "
                    "(SENSOR_DATA_LAKE_API_KEY) is not set. Create an identity "
                    "API key with the data:ingest scope for the sensor's team "
                    "member, set it, and restart the sensor. Events are "
                    "collected and discarded until then."
                )

            # Start forwarding tasks
            asyncio.create_task(self._collect_events())
            asyncio.create_task(self._flush_periodically())

            logger.info("Data forwarder started successfully")

        except Exception as e:
            logger.error(f"Failed to start data forwarder: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Stop data forwarding"""
        logger.info("Stopping data forwarder")
        self.running = False

        # Flush any remaining events
        if self.batch_buffer:
            await self._flush_batch()

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

    async def _collect_events(self):
        """Collect events from input queue and batch them"""
        while self.running:
            try:
                # Get event with timeout
                event = await asyncio.wait_for(self.input_queue.get(), timeout=1.0)

                # Add to batch buffer
                self.batch_buffer.append(event)

                # Check if we should flush the batch
                if len(self.batch_buffer) >= self.config.data_lake.batch_size:
                    await self._flush_batch()

            except asyncio.TimeoutError:
                # No events available, check if we should flush based on time
                if self._should_flush_by_time():
                    await self._flush_batch()
                continue

            except asyncio.CancelledError:
                break

            except Exception as e:
                logger.error(f"Error collecting events: {e}")
                await asyncio.sleep(1)

    async def _flush_periodically(self):
        """Flush batches periodically based on time interval"""
        while self.running:
            try:
                await asyncio.sleep(self.config.data_lake.flush_interval)

                if self.batch_buffer and self._should_flush_by_time():
                    await self._flush_batch()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic flush: {e}")

    def _should_flush_by_time(self) -> bool:
        """Check if batch should be flushed based on time"""
        return (
            time.time() - self.last_flush_time
        ) >= self.config.data_lake.flush_interval

    async def _flush_batch(self):
        """Flush current batch to the data lake"""
        if not self.batch_buffer:
            return

        batch_size = len(self.batch_buffer)

        if not self.enabled:
            # Nowhere to send them; keeping them would only grow the buffer.
            self.stats["events_dropped_unconfigured"] += batch_size
            self.batch_buffer.clear()
            self.last_flush_time = time.time()
            return

        logger.debug(f"Flushing batch of {batch_size} events")

        # Clear buffer before sending (to avoid duplication on retry)
        current_batch = self.batch_buffer.copy()
        self.batch_buffer.clear()
        self.last_flush_time = time.time()

        batch_payload = build_batch(current_batch, self.sensor_id)

        # Send batch with retries
        success = await self._send_batch_with_retries(batch_payload)

        if success:
            self.stats["batches_sent"] += 1
            self.stats["events_forwarded"] += batch_size
            self.stats["last_successful_send"] = datetime.now(timezone.utc).isoformat()
            logger.debug(f"Successfully forwarded batch of {batch_size} events")
        else:
            # Re-add failed events to buffer for retry (with limit to prevent memory issues)
            if len(self.batch_buffer) < self.config.performance.max_queue_size:
                self.batch_buffer.extend(current_batch[:100])  # Limit to 100 events

            self.stats["events_failed"] += batch_size
            logger.error(f"Failed to forward batch of {batch_size} events")

    async def _send_batch_with_retries(self, batch_payload: Dict[str, Any]) -> bool:
        """Send batch with retry logic"""

        for attempt in range(self.config.data_lake.retry_attempts):
            try:
                # Rate limiting
                await self._apply_rate_limiting()

                # Send HTTP request
                outcome = await self._send_http_request(batch_payload)

                if outcome == SENT:
                    return True
                if outcome == REFUSED:
                    # Retrying a refused key or a malformed batch sends the
                    # same request to get the same answer.
                    return False

                # Wait before retry
                if attempt < self.config.data_lake.retry_attempts - 1:
                    wait_time = self.config.data_lake.retry_delay * (
                        2**attempt
                    )  # Exponential backoff
                    logger.debug(
                        f"Retrying batch send in {wait_time} seconds (attempt {attempt + 1})"
                    )
                    await asyncio.sleep(wait_time)

            except Exception as e:
                logger.error(f"Error sending batch (attempt {attempt + 1}): {e}")
                self.stats["network_errors"] += 1
                self.stats["last_error"] = str(e)

                if attempt < self.config.data_lake.retry_attempts - 1:
                    await asyncio.sleep(self.config.data_lake.retry_delay)

        return False

    async def _apply_rate_limiting(self):
        """Apply rate limiting to prevent overwhelming the API"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.min_request_interval:
            wait_time = self.min_request_interval - time_since_last
            await asyncio.sleep(wait_time)

        self.last_request_time = time.time()

    def _post(self, payload: Dict[str, Any]):
        """POST to the ingest URL. Redirects are not followed: a redirected
        request would carry the API key to wherever the redirect points."""
        return self.session.post(
            self.config.data_lake.ingest_url, json=payload, allow_redirects=False
        )

    async def _send_http_request(self, payload: Dict[str, Any]) -> str:
        """Send one batch; SENT, RETRY or REFUSED."""
        try:
            async with self._post(payload) as response:
                if response.status in (200, 201):
                    return SENT

                detail = (await response.text())[:300]
                self.stats["api_errors"] += 1
                self.stats["last_error"] = f"HTTP {response.status}"

                if response.status == 429:
                    logger.warning("API rate limit hit, backing off")
                    await asyncio.sleep(10)
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

            async with self._post(
                {"batch_id": str(uuid.uuid4()), "events": []}
            ) as response:
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
        return {
            "running": self.running,
            "forwarding_enabled": self.enabled,
            "endpoint": self.config.data_lake.ingest_url,
            "sensor_id": self.sensor_id,
            "tls_verify": self.config.data_lake.tls_verify,
            "batch_size": self.config.data_lake.batch_size,
            "flush_interval": self.config.data_lake.flush_interval,
            "current_batch_size": len(self.batch_buffer),
            "queue_size": self.input_queue.qsize(),
            "stats": self.stats.copy(),
            "session_active": self.session is not None and not self.session.closed,
        }
