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
* What is dropped, and counted under ``events_dropped_*``: an event the
  data service finds unacceptable, an event that cannot be serialized or is
  larger than a batch may be, every event while no API key is configured,
  and what is still here when the sensor stops.
* An answer is read for what it says (#745, ``classify_answer``). That the
  sensor is not allowed, or not now (a revoked or expired key, a missing
  scope, a rate limit), or that the address is wrong, says nothing about
  the events: the batch is kept as in an outage, and the sensor reports
  that it is not delivering and why. Only an answer about the payload (413,
  422, a 400 of the data service, and from a data service older than #755
  a 200 that stored nothing) costs events,
  and then the batch is split in halves until the event at fault is alone:
  that one is dropped, the others are delivered. ``SPLIT_BUDGET`` bounds the
  requests spent on one batch.
* An event may carry a ``Delivery`` (``sensor.pipeline.delivery``), which is
  settled when the gateway accepts the event's batch or the event is
  dropped. What is still here when the sensor stops is not settled; an
  event whose collector will read it again after the restart is then
  counted under ``events_returned_to_source`` and not as dropped.
* The pace is the gateway's (#745). The next batch goes when the previous
  one is answered, not a second later. The gateway counts requests per team
  and minute and says what is left in each answer (``X-RateLimit-*``): when
  what is left falls to the share the sensor leaves to the team's other
  clients (``data_lake.rate_limit_share``), the sender waits for the next
  minute. ``MIN_REQUEST_INTERVAL`` keeps it under nginx's limit per address.
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
from typing import Any, Deque, Dict, List, Optional, Tuple

import aiohttp
from sensor.core.config import MAX_BATCH_BYTES, SensorConfig
from sensor.pipeline.delivery import Delivery, settle, take_delivery

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
RETRY = "retry"  # the batch is kept: it may pass later, or once someone acts
REFUSED = "refused"  # the payload is unacceptable: sent again, the same answer

# Why batches are, or are not, being delivered. All but OK keep the batch.
OK = "ok"
UNAVAILABLE = "unavailable"  # a network error, a 5xx answer
RATE_LIMITED = "rate_limited"  # 429
UNAUTHORIZED = "unauthorized"  # the key is invalid, expired or revoked
FORBIDDEN = "forbidden"  # the key may not ingest
MISCONFIGURED = "misconfigured"  # the address is not the gateway's ingest route
PAYLOAD = "payload"  # the data service refuses what was sent

# What to do about each state that someone has to act on.
_REMEDIES = {
    UNAUTHORIZED: (
        "the gateway does not accept the sensor's API key: it is invalid, "
        "expired or revoked. Set data_lake.api_key (SENSOR_DATA_LAKE_API_KEY) "
        "to a valid identity API key and restart the sensor"
    ),
    FORBIDDEN: (
        "the sensor's API key is not allowed to ingest. It needs the "
        "data:ingest scope, and its member must still belong to the team and "
        "have changed the initial password"
    ),
    MISCONFIGURED: (
        "the ingest URL does not answer as the gateway's ingest route. "
        "data_lake.endpoint must be the gateway's https:// URL"
    ),
}
# The gateway's own error codes that are about the credential, whatever the
# status they come with.
_CREDENTIAL_ERRORS = ("invalid_token", "authentication_required")
# Requests one refused batch may cost before what is left of it is dropped
# whole. Finding one bad event among 100 takes about 8.
SPLIT_BUDGET = 64

# Why an event leaves the sensor without reaching the data service.
DROP_REASONS = ("refused", "oversize", "unserializable", "unconfigured", "shutdown")
# Seconds to wait after an HTTP 429 that names no Retry-After.
RATE_LIMIT_DELAY = 10
# Seconds between two requests, at least. The gateway's nginx admits 100
# requests a second from one address, in bursts of 10 (limit_req zone=global
# in wildbox_gateway.conf): this keeps a sensor at half of that.
MIN_REQUEST_INTERVAL = 0.02
# The longest the sender waits for the gateway's next window on its word: the
# gateway's windows are a minute long.
MAX_BUDGET_WAIT = 120
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


def _error_of(text: str) -> str:
    """The code and message of an error answer, from either shape in use:
    the gateway's ``{"error": "code", "message": ...}`` and the services'
    ``{"error": {"code": 403, "message": ..., "details": {...}}}``."""
    try:
        answer = json.loads(text)
    except (ValueError, RecursionError):
        return ""
    error = answer.get("error") if isinstance(answer, dict) else None
    parts = []
    if isinstance(error, str):
        parts = [error, answer.get("message")]
    elif isinstance(error, dict):
        details = error.get("details")
        code = details.get("code") if isinstance(details, dict) else None
        parts = [code, error.get("message")]
    return ": ".join(str(part) for part in parts if isinstance(part, str) and part)


def _from_a_service(text: str) -> bool:
    """Is this error answer in the shape the Wildbox services answer in?"""
    try:
        answer = json.loads(text)
    except (ValueError, RecursionError):
        return False
    return isinstance(answer, dict) and isinstance(answer.get("error"), dict)


def classify_answer(status: int, text: str = ""):
    """What an answer to a batch means: (outcome, state, reason).

    Read from what the gateway (nginx/lua/auth_handler.lua, nginx's own
    limits) and the data service (POST /api/v1/ingest) answer:

    * 200, 201: stored.
    * 401, and the gateway's 400 for a token too long to be one: the key.
    * 403: the key's scope, its member's place in the team or its initial
      password, at the gateway; the scope again at the data service.
    * 429: the team's request budget, or nginx's limit per address.
    * 413 (nginx: the body is too large), 422 (the data service's
      validation) and the data service's own 400 (too many events): the
      payload. A 400 that is not in the services' error shape is nginx's or
      the gateway's, about the request and not about the events.
    * 5xx: the gateway could not reach identity or the data service, or the
      data service could not store the batch.
    * a redirect, 404 and any other 4xx: the request did not reach the
      ingest route.
    """
    error = _error_of(text)
    reason = f"HTTP {status}" + (f" {error}" if error else "")
    reason = reason[:300]
    if status in (200, 201):
        return SENT, OK, reason
    if status == 401 or (status == 400 and error.startswith(_CREDENTIAL_ERRORS)):
        return RETRY, UNAUTHORIZED, reason
    if status == 403:
        return RETRY, FORBIDDEN, reason
    if status == 429:
        return RETRY, RATE_LIMITED, reason
    if status in (413, 422) or (status == 400 and _from_a_service(text)):
        return REFUSED, PAYLOAD, reason
    if status >= 500:
        return RETRY, UNAVAILABLE, reason
    return RETRY, MISCONFIGURED, reason


def stored_events(text: str, sent: int) -> int:
    """How many of the ``sent`` events an accepting answer says were stored.

    The data service answers 200 with ``events_ingested``. Since #755 that
    is the whole batch or the answer is not a 200: a batch is stored in one
    transaction, a batch it refuses is a 422 and one it could not store a
    5xx (``tests/shared/ingest_answer_vectors.json`` lists its answers, for
    its tests and for this module's). A data service from before that
    answered 200 with fewer events than it received when it could not
    process some, and with 0 when it could not commit the batch: the count
    is still read, so that such an answer is not taken for a delivery. An
    answer that does not say is taken at its status: all of them.
    """
    try:
        answer = json.loads(text)
    except (ValueError, RecursionError):
        return sent
    stored = answer.get("events_ingested") if isinstance(answer, dict) else None
    if isinstance(stored, bool) or not isinstance(stored, int):
        return sent
    return min(max(stored, 0), sent)


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
        # sent, each with what its collector wants to be told; see the
        # module's description for the bounds.
        self.buffer: Deque[Tuple[bytes, Optional[Delivery]]] = deque()
        self.buffer_bytes = 0
        self.max_events = config.data_lake.buffer_max_events
        self.max_bytes = config.data_lake.buffer_max_bytes
        # An event that no batch could carry is not kept.
        self.max_event_bytes = min(MAX_BATCH_BYTES, self.max_bytes)
        self._oldest_since = time.monotonic()
        self._full_since: Optional[float] = None
        self._in_hand: Optional[Tuple[bytes, Optional[Delivery]]] = None
        self._room = asyncio.Event()
        self._wake = asyncio.Event()
        self._stopping = asyncio.Event()
        self._tasks: List[asyncio.Task] = []

        self.sensor_id = config.data_lake.sensor_id or socket.gethostname()

        # Statistics. events_received is every event taken from the pipeline:
        # it equals events_forwarded + events_dropped +
        # events_returned_to_source + what the buffer holds.
        self.stats: Dict[str, Any] = {
            "events_received": 0,
            "events_forwarded": 0,
            "events_dropped": 0,
            "events_returned_to_source": 0,
            "batches_sent": 0,
            "batches_refused": 0,
            "batches_split": 0,
            "budget_waits": 0,
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

        # Why batches are or are not being delivered, since when, and what
        # the last answer said.
        self.delivery_state = OK
        self.delivery_since: Optional[str] = None
        self.delivery_reason: Optional[str] = None
        # The body of the last accepting answer.
        self._accepted = ""
        # The oldest events, when they belong to a batch that was refused:
        # [size, whether this very run was refused] for each run of them,
        # in order. And the requests spent on finding the event at fault.
        self._suspects: Deque[List[Any]] = deque()
        self._split_requests = 0

        # Consecutive attempts after which the batch was kept.
        self.failures = 0
        self._retry_after = 0.0
        self._next_attempt: Optional[float] = None

        # Pacing. No request before _not_before (a monotonic time): the
        # interval above after every request, and the gateway's next window
        # once the sensor has used its share of the team's budget.
        self.min_request_interval = MIN_REQUEST_INTERVAL
        self._not_before = 0.0
        # What the gateway last said of the team's budget, and until when
        # the sender is waiting for it.
        self.budget: Optional[Dict[str, int]] = None
        self._budget_wait_until: Optional[float] = None

    @property
    def enabled(self) -> bool:
        return self.config.data_lake.forwarding_enabled

    @property
    def held(self) -> int:
        """Events the sender holds: its buffer's, and the one in its hand
        while the buffer has no room for it."""
        return len(self.buffer) + (self._in_hand is not None)

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
            self._hold(*self._in_hand)
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
            # Not settled: the collector of an event that can be read again
            # keeps its position before it.
            left = self._release(len(self.buffer))
            returned = sum(1 for delivery in left if delivery and delivery.replayable)
            self.stats["events_returned_to_source"] += returned
            self._count_dropped("shutdown", len(left) - returned)
            logger.warning(
                "Stopped with %d events the gateway had not accepted: %d are "
                "dropped, %d will be read again from their log source after "
                "the restart",
                len(left),
                len(left) - returned,
                returned,
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
        held = self._prepare(event)
        if held is None:
            return False
        self._hold(*held)
        return True

    def _prepare(
        self, event: Dict[str, Any]
    ) -> Optional[Tuple[bytes, Optional[Delivery]]]:
        """The event as it will be sent and its Delivery, or None when the
        event is dropped."""
        self.stats["events_received"] += 1
        # Taken out first: it is not part of what is sent.
        delivery = take_delivery(event)
        try:
            body = self._encode(event)
        except Exception as e:
            # Not one of the errors _encode expects of an event JSON cannot
            # carry (a RecursionError, say, for one nested too deep). The
            # event is dropped like those, and like those it is counted and
            # its collector told (#765): this used to leave the method, and
            # the event was received and nothing else, in a log line and in
            # no counter, its Delivery never settled, so that its log
            # file's position stayed before it for as long as the sensor
            # ran.
            self._count_dropped("unserializable")
            logger.error(
                "Dropped an event of type %r: making it into what is sent "
                "failed with %s: %s",
                event.get("type") if isinstance(event, dict) else None,
                type(e).__name__,
                e,
            )
            body = None
        if body is None:
            # Dropped for good: the sensor has finished with it.
            settle(delivery)
            return None
        return body, delivery

    def _encode(self, event: Dict[str, Any]) -> Optional[bytes]:
        """The event as it will be sent; None, and counted, when dropped."""
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

    def _hold(self, body: bytes, delivery: Optional[Delivery] = None):
        if not self.buffer:
            self._oldest_since = time.monotonic()
        self.buffer.append((body, delivery))
        self.buffer_bytes += len(body)
        if len(self.buffer) in (1, self.config.data_lake.batch_size):
            # The sender has a deadline to compute, or a batch to send.
            self._wake.set()

    def _lacks_room(self, size: int) -> bool:
        if len(self.buffer) >= self.max_events:
            return True
        return bool(self.buffer) and self.buffer_bytes + size > self.max_bytes

    def _release(self, count: int) -> List[Optional[Delivery]]:
        """Take the ``count`` oldest events out of the buffer; what their
        collectors want to be told."""
        deliveries = []
        for _ in range(count):
            body, delivery = self.buffer.popleft()
            self.buffer_bytes -= len(body)
            deliveries.append(delivery)
        self._oldest_since = time.monotonic()
        self._room.set()
        if self._full_since is not None and not self._lacks_room(0):
            logger.info(
                "The buffer has room again after %.0f seconds: taking events "
                "from the collectors",
                time.monotonic() - self._full_since,
            )
            self._full_since = None
        return deliveries

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
                try:
                    held = self._in_hand = self._prepare(event)
                finally:
                    # The sender's from here: in its hand until the buffer
                    # has room, or dropped and counted. Said in the same
                    # turn of the event loop as the get, so that whoever
                    # waits on the queue's join() (the agent's stop) is
                    # never told that nothing is left while an event is in
                    # neither place (#754). Not said after the wait for
                    # room below: that is a wait for the gateway, and
                    # stop() takes what is in hand.
                    self.input_queue.task_done()
                if held is None:
                    continue
                while self._lacks_room(len(held[0])):
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
                self._hold(*held)

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
        if self._suspects:
            return 0.0  # the rest of a batch that is being split
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
        self._resolve_suspects()
        if self._suspects:
            # Part of a batch that was refused: a run of it, to find out
            # whether the event at fault is there.
            return self._suspects[0][0]
        count = size = 0
        for body, _ in islice(self.buffer, self.config.data_lake.batch_size):
            if count and size + len(body) > MAX_BATCH_BYTES:
                break
            count += 1
            size += len(body)
        return count

    def _resolve_suspects(self):
        """Do what needs no request about the events of a refused batch:
        drop a refused event that is alone, halve a run known to hold one."""
        while self._suspects and self._suspects[0][1]:
            size = self._suspects[0][0]
            if size == 1:
                self._suspects.popleft()
                self._drop_refused(1)
                continue
            if self._split_requests >= SPLIT_BUDGET:
                left = sum(run[0] for run in self._suspects)
                self._suspects.clear()
                logger.error(
                    "Finding the events the data service refuses took %d "
                    "requests: the %d events of the batch that are not "
                    "delivered yet are dropped with them",
                    self._split_requests,
                    left,
                )
                self._drop_refused(left)
                continue
            # Two halves, each tried in its turn. Neither is taken for
            # refused because the other was accepted: a batch refused for
            # its size has two halves that are both fine, and an event is
            # dropped only when it was refused alone.
            self._suspects.popleft()
            self._suspects.appendleft([size - size // 2, False])
            self._suspects.appendleft([size // 2, False])
            self.stats["batches_split"] += 1
        if not self._suspects:
            self._split_requests = 0

    def _drop_refused(self, count: int):
        """Drop the oldest ``count`` events as refused by the data service."""
        if count == 1 and self.buffer:
            try:
                event_type = json.loads(self.buffer[0][0])["event_data"].get("type")
            except (ValueError, KeyError, AttributeError, TypeError):
                event_type = None
            logger.error(
                "The data service refuses an event of type %r (%s): it is "
                "dropped. The other events of its batch are delivered",
                event_type,
                self.stats["last_error"],
            )
        self._count_dropped("refused", count)
        for delivery in self._release(count):
            # Dropped for good: its collector may move past it.
            settle(delivery)

    async def _flush_batch(self) -> Optional[str]:
        """Send the oldest events as one batch: SENT, RETRY or REFUSED.

        None when there is nothing to send. The events leave the buffer when
        the data service has taken them, or refused them for what they are.
        They stay in it, in their place, for any other answer and when there
        is none: see ``classify_answer``.
        """
        count = self._next_batch()
        if not count:
            return None

        logger.debug(f"Flushing batch of {count} events")
        self._retry_after = 0.0
        self._accepted = ""
        bodies = [body for body, _ in islice(self.buffer, count)]
        outcome = await self._send(encode_batch(bodies))
        splitting = bool(self._suspects)
        if splitting:
            self._split_requests += 1

        stored = stored_events(self._accepted, count) if outcome == SENT else 0
        if outcome == SENT and stored == 0:
            # Accepted, and nothing stored: the data service could not
            # commit the batch. Its events are not delivered.
            outcome = REFUSED
            self._note(PAYLOAD, "HTTP 200, and none of the events stored")

        if outcome == RETRY:
            self.failures += 1
            self.stats["send_failures"] += 1
            return RETRY

        self.failures = 0
        if outcome == REFUSED:
            self.stats["batches_refused"] += 1
            if splitting:
                self._suspects[0][1] = True
            else:
                self._suspects.append([count, True])
            self._resolve_suspects()
            return REFUSED

        if splitting:
            self._suspects.popleft()
        deliveries = self._release(count)
        self.stats["batches_sent"] += 1
        self.stats["events_forwarded"] += stored
        self.stats["last_successful_send"] = datetime.now(timezone.utc).isoformat()
        logger.debug(f"Successfully forwarded batch of {count} events")
        if stored < count:
            # The data service says which it could not store only by their
            # place in the batch; they are counted, not found.
            self._count_dropped("refused", count - stored)
            logger.error(
                "The data service stored %d of the %d events of a batch it "
                "accepted: the other %d are dropped",
                stored,
                count,
                count - stored,
            )
        # Stored, or dropped for good: either way the sensor has finished
        # with these events, and their collectors may move past them.
        for delivery in deliveries:
            settle(delivery)
        return SENT

    def _note(self, state: str, reason: str):
        """Record why the last batch was, or was not, delivered; say so
        when that changes."""
        if state != OK:
            self.stats["last_error"] = reason
        if state == PAYLOAD:
            # About this batch: the request did reach the data service.
            state, reason = OK, None
        if state == self.delivery_state:
            self.delivery_reason = None if state == OK else reason
            return
        was, since = self.delivery_state, self.delivery_since
        self.delivery_state = state
        self.delivery_since = datetime.now(timezone.utc).isoformat()
        self.delivery_reason = None if state == OK else reason
        if state == OK:
            logger.info(
                "The gateway accepts the sensor's batches again (it was %s "
                "since %s)",
                was,
                since,
            )
        elif state in _REMEDIES:
            logger.error(
                "Not delivering since %s (%s): %s. Nothing is dropped: the "
                "events wait, and no log source moves past what was accepted",
                self.delivery_since,
                reason,
                _REMEDIES[state],
            )
        else:
            logger.warning(
                "Not delivering since %s: %s (%s). The events wait",
                self.delivery_since,
                state,
                reason,
            )

    async def _send(self, body: bytes) -> str:
        """One attempt for one batch; SENT, RETRY or REFUSED."""
        try:
            await self._pace()
            try:
                return await self._send_http_request(body)
            finally:
                self._not_before = max(
                    self._not_before, time.monotonic() + self.min_request_interval
                )
        except Exception as e:
            logger.error(f"Error sending batch: {e}")
            self.stats["network_errors"] += 1
            self.stats["last_error"] = str(e)
            return RETRY

    async def _pace(self):
        """Wait until the next request may go."""
        wait = self._not_before - time.monotonic()
        if wait > 0:
            await self._pause(wait)
            # Waited for, or the forwarder is stopping: not owed any more.
            self._not_before = time.monotonic()
        self._budget_wait_until = None

    def _read_budget(self, response):
        """Take the team's request budget from an answer, and wait for the
        next window when the sensor's share of this one is used.

        The gateway counts every request of the team, the dashboard's and
        other sensors' with this one's, against one budget per minute, and
        answers 429 to all of them once it is spent. A sensor with a
        backlog would spend it alone.
        """
        try:
            limit = int(response.headers["X-RateLimit-Limit"])
            remaining = int(response.headers["X-RateLimit-Remaining"])
            reset = int(response.headers["X-RateLimit-Reset"])
        except (KeyError, ValueError):
            return
        if limit <= 0 or remaining < 0:
            return
        self.budget = {"limit": limit, "remaining": remaining, "reset": reset}
        share = self.config.data_lake.rate_limit_share
        if remaining > limit * (1 - share):
            return
        wait = min(max(reset - time.time(), 0.0), MAX_BUDGET_WAIT)
        if wait > 0:
            self.stats["budget_waits"] += 1
            self._budget_wait_until = time.time() + wait
            self._not_before = max(self._not_before, time.monotonic() + wait)
            logger.debug(
                "The team's request budget is at %d of %d: waiting %.0f "
                "seconds for the gateway's next window",
                remaining,
                limit,
                wait,
            )

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
                text = await response.text()
                self._read_budget(response)
                outcome, state, reason = classify_answer(response.status, text)
                if outcome == SENT:
                    self._accepted = text
                else:
                    self.stats["api_errors"] += 1
                if state == RATE_LIMITED:
                    self._retry_after = self._rate_limit_delay(response)
                self._note(state, reason)
                return outcome

        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error: {e}")
            self.stats["network_errors"] += 1
            self._note(UNAVAILABLE, str(e)[:300])
            return RETRY
        except Exception as e:
            logger.error(f"Unexpected HTTP error: {e}")
            self.stats["network_errors"] += 1
            self._note(UNAVAILABLE, str(e)[:300])
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
            # ok, or why no batch gets through: unavailable, rate_limited,
            # unauthorized, forbidden, misconfigured; since when, and what
            # the last answer said.
            "delivery": {
                "state": self.delivery_state if self.enabled else "unconfigured",
                "since": self.delivery_since,
                "reason": self.delivery_reason,
            },
            "retry": {
                "consecutive_failures": self.failures,
                "next_attempt": next_attempt,
            },
            # The team's request budget for the current minute, as the
            # gateway last stated it, and until when the sender waits for
            # the next one (null: it is not waiting).
            "pacing": {
                "min_request_interval": self.min_request_interval,
                "rate_limit_share": data_lake.rate_limit_share,
                "budget": self.budget,
                "waiting_for_budget_until": (
                    datetime.fromtimestamp(
                        self._budget_wait_until, timezone.utc
                    ).isoformat()
                    if self._budget_wait_until
                    else None
                ),
            },
            "queue_size": self.input_queue.qsize(),
            "stats": self.stats.copy(),
            "session_active": self.session is not None and not self.session.closed,
        }
