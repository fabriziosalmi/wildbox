"""The data forwarder sends batches to the gateway, the way the gateway accepts them.

It used to post to the data service's /api/v1/ingest directly with
``Authorization: Bearer <key>``. The data service accepts only requests the
gateway has authenticated, so every batch was refused and no telemetry was
ever stored (#628). Batches now go to ``https://<gateway>/api/v1/data/ingest``
with an identity API key in X-API-Key, over TLS verified against the gateway's
certificate.

The gateway is played by a real HTTPS server on the loopback, with a
certificate made for the test: TLS verification is exercised for real, not
assumed from a mock.

What the forwarder keeps while the gateway takes nothing (#725): a batch that
failed for a reason that may pass used to come back as its first 100 events,
and one event was lost with every further attempt. The buffer is now what
its bounds say, and every event that leaves it unsent is counted.
"""

import asyncio
import datetime
import json
import logging
import sys
from collections import deque
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.core.config import (  # noqa: E402
    MIN_BUFFER_BYTES,
    DataLakeConfig,
    SensorConfig,
    _build_config_from_dict,
)
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import (  # noqa: E402
    DROP_REASONS,
    REFUSED,
    RETRY,
    SENT,
    SPLIT_BUDGET,
    DataForwarder,
    build_batch,
    classify_answer,
    encode_batch,
    encode_event,
    ingest_event_type,
    retry_delay,
    stored_events,
)
from sensor.pipeline.delivery import DELIVERY_KEY, Delivery  # noqa: E402

# Shaped like an identity key; not one.
API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

EVENTS = [
    {
        "id": "e1",
        "timestamp": "2026-10-03T10:00:00+00:00",
        "source": "osquery",
        "type": "network.listening_ports",
        "data": [{"port": "22"}],
        "metadata": {},
        "host": {"hostname": "web-1", "platform": "Linux"},
    },
    {
        "id": "e2",
        "timestamp": "not a timestamp",
        "source": "file_monitor",
        "type": "file_modified",
        "data": {"path": "/etc/passwd"},
        "host": {"hostname": "web-1"},
    },
]


def _certificate(tmp_path):
    """A self-signed certificate for localhost/127.0.0.1, usable as its own CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            # localhost only: the hostname test connects to 127.0.0.1.
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "gateway.crt"
    key_path = tmp_path / "gateway.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class FakeGateway:
    """Records every request; answers with ``status`` (and ``location``).

    ``outage`` holds the statuses of the next answers, before ``status``
    applies again: an outage that ends.
    """

    def __init__(self):
        self.requests = []
        self.status = 200
        self.outage = deque()
        # None: what the data service answers, every event stored. Else
        # this, whatever the status.
        self.body = None
        self.location = None
        self.retry_after = None
        self.delay = 0  # seconds between receiving a request and answering
        # As the data service: 422 for a batch that holds one of these ids.
        self.unacceptable = set()
        # As nginx (413) or the data service (400): no more events than this.
        self.most_events = None
        self.too_many = 413

    async def handle(self, request):
        raw = await request.read()
        status = self.outage.popleft() if self.outage else self.status
        if status == 200 and raw:
            ids = [e["event_data"].get("id") for e in json.loads(raw)["events"]]
            if self.most_events is not None and len(ids) > self.most_events:
                status = self.too_many
            elif self.unacceptable.intersection(ids):
                status = 422
        self.requests.append(
            {
                "method": request.method,
                "path": request.path,
                "headers": dict(request.headers),
                "json": json.loads(raw) if raw else None,
                "status": status,
            }
        )
        headers = {}
        if self.location:
            headers["Location"] = self.location
        if self.retry_after is not None:
            headers["Retry-After"] = self.retry_after
        if self.delay:
            await asyncio.sleep(self.delay)
        body = self.body
        if body is None:
            count = len(json.loads(raw)["events"]) if raw else 0
            body = {"batch_id": "b", "events_received": count, "events_ingested": count}
            if status >= 400:
                body = {"error": {"code": status, "message": "refused by the stand-in"}}
        return web.json_response(body, status=status, headers=headers)

    def accepted_ids(self):
        """The ids of the events of every batch answered 200, in order."""
        return [
            event["event_data"]["id"]
            for request in self.requests
            if request["status"] == 200
            for event in request["json"]["events"]
        ]


@pytest_asyncio.fixture
async def gateway(tmp_path):
    import ssl

    cert_path, key_path = _certificate(tmp_path)
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.load_cert_chain(cert_path, key_path)

    fake = FakeGateway()
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", fake.handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_context)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    fake.url = f"https://localhost:{port}"
    fake.ca = str(cert_path)
    try:
        yield fake
    finally:
        await runner.cleanup()


def _forwarder(endpoint, queue_size=0, **data_lake):
    settings = {"api_key": API_KEY, "retry_delay": 0}
    settings.update(data_lake)
    config = SensorConfig(data_lake=DataLakeConfig(endpoint=endpoint, **settings))
    assert [e for e in config.validate() if "ca_bundle" not in e] == []
    forwarder = DataForwarder(config, asyncio.Queue(maxsize=queue_size))
    # Not the second a sensor leaves between two requests, and not zero
    # either: a running forwarder whose batch fails tries again at once here
    # (retry_delay is 0), and would do nothing else.
    forwarder.min_request_interval = 0.002
    return forwarder


async def _flush(forwarder, events=EVENTS):
    await forwarder._init_session()
    try:
        for event in events:
            forwarder.accept(event)
        return await forwarder._flush_batch()
    finally:
        await forwarder.session.close()


def _numbered(count, start=0):
    return [dict(EVENTS[0], id=f"e{index}") for index in range(start, start + count)]


def _ids(count, start=0):
    return [f"e{index}" for index in range(start, start + count)]


def _held_ids(forwarder):
    """The ids of the events the buffer holds, oldest first."""
    return [json.loads(body)["event_data"]["id"] for body, _ in forwarder.buffer]


def _accounted(forwarder):
    """Every event received is forwarded, dropped, returned or still held."""
    stats = forwarder.stats
    assert stats["events_dropped"] == sum(
        stats[f"events_dropped_{reason}"] for reason in DROP_REASONS
    )
    return stats["events_received"] == (
        stats["events_forwarded"]
        + stats["events_dropped"]
        + stats["events_returned_to_source"]
        + len(forwarder.buffer)
    )


async def _until(condition, timeout=10):
    """Wait for ``condition``; fail if it does not come within ``timeout``."""
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


@pytest.mark.asyncio
async def test_a_batch_goes_to_the_gateway_ingest_route_with_the_key_in_x_api_key(
    gateway,
):
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, sensor_id="sensor-a")

    await _flush(forwarder)

    assert forwarder.stats["batches_sent"] == 1
    assert forwarder.stats["events_forwarded"] == 2
    assert len(gateway.requests) == 1
    sent = gateway.requests[0]
    assert sent["method"] == "POST"
    assert sent["path"] == "/api/v1/data/ingest"
    assert sent["headers"].get("X-API-Key") == API_KEY
    # Not a bearer token: the gateway treats Authorization as a session JWT.
    assert "Authorization" not in sent["headers"]


@pytest.mark.asyncio
async def test_the_batch_has_the_data_service_shape_and_no_team(gateway):
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, sensor_id="sensor-a")

    await _flush(forwarder)

    body = gateway.requests[0]["json"]
    # The team is the key's, resolved by the gateway; the batch names none.
    assert set(body) == {"batch_id", "events"}
    first, second = body["events"]
    assert first["sensor_id"] == "sensor-a"
    assert first["event_type"] == "network_connection"
    assert first["timestamp"] == "2026-10-03T10:00:00+00:00"
    assert first["source_host"] == "web-1"
    assert first["event_data"]["data"] == [{"port": "22"}]
    assert "network.listening_ports" in first["tags"]
    assert second["event_type"] == "file_change"
    # An unparseable time is replaced, not sent to fail the whole batch.
    datetime.datetime.fromisoformat(second["timestamp"])


@pytest.mark.asyncio
async def test_a_full_ingest_url_is_used_as_it_is(gateway):
    forwarder = _forwarder(gateway.url + "/api/v1/data/ingest", ca_bundle=gateway.ca)

    await _flush(forwarder)

    assert [r["path"] for r in gateway.requests] == ["/api/v1/data/ingest"]


def test_tls_verification_is_on_by_default():
    assert DataLakeConfig(endpoint="https://gw", api_key=API_KEY).tls_verify is True
    context = data_forwarder.build_ssl_context(True, None)
    assert context.verify_mode == data_forwarder.ssl.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.asyncio
async def test_an_untrusted_gateway_certificate_is_refused_by_default(gateway):
    # No ca_bundle, default tls_verify: the test certificate is in no trust
    # store, so the handshake must fail and nothing must reach the server.
    forwarder = _forwarder(gateway.url)

    await _flush(forwarder)

    assert gateway.requests == []
    assert forwarder.stats["batches_sent"] == 0
    assert forwarder.stats["network_errors"] == 1
    assert "certificate" in str(forwarder.stats["last_error"]).lower()


@pytest.mark.asyncio
async def test_the_ca_bundle_does_not_trust_another_hostname(gateway):
    # The certificate names localhost only: the same server reached as
    # 127.0.0.1 must fail verification even with the right bundle.
    url = gateway.url.replace("localhost", "127.0.0.1")
    forwarder = _forwarder(url, ca_bundle=gateway.ca)

    await _flush(forwarder)

    assert gateway.requests == []
    assert forwarder.stats["batches_sent"] == 0
    assert "certificate" in str(forwarder.stats["last_error"]).lower()


# What the gateway and the data service answer when the sensor is not
# allowed, not now, or not at the right address (#745): the status, the body,
# and the state the sensor must report. None of them says anything about the
# events. From open-security-gateway/nginx/lua/auth_handler.lua, nginx itself
# and open-security-shared's error shape.
NOT_ABOUT_THE_EVENTS = {
    "a revoked or expired key": (
        401,
        {
            "error": "invalid_token",
            "message": "Authentication token is invalid or expired",
        },
        "unauthorized",
    ),
    "no key at all": (
        401,
        {
            "error": "authentication_required",
            "message": "Valid authentication token required",
        },
        "unauthorized",
    ),
    "a key too long to be one": (
        400,
        {
            "error": "invalid_token",
            "message": "Authentication token exceeds maximum allowed length",
        },
        "unauthorized",
    ),
    "a key without the scope": (
        403,
        {
            "error": "insufficient_scope",
            "message": "This API key is not authorized for this operation.",
            "required_scope": "data:ingest",
        },
        "forbidden",
    ),
    "a member removed from the team": (
        403,
        {
            "error": "team_membership_ended",
            "message": "The account no longer belongs to this team",
        },
        "forbidden",
    ),
    "an initial password not changed": (
        403,
        {
            "error": "PASSWORD_CHANGE_REQUIRED",
            "message": "Change the initial password before using the account",
        },
        "forbidden",
    ),
    "identity's own refusal, without a body": (403, "", "forbidden"),
    "the data service's scope check": (
        403,
        {
            "error": {
                "code": 403,
                "message": "Forbidden",
                "details": {"code": "INSUFFICIENT_SCOPE"},
            }
        },
        "forbidden",
    ),
    "the team's request budget": (
        429,
        {
            "error": "rate_limit_exceeded",
            "message": "Rate limit exceeded",
            "limit_per_hour": 10000,
            "retry_after_seconds": 1,
        },
        "rate_limited",
    ),
    "nginx's limit per address": (
        429,
        "<html><h1>429 Too Many Requests</h1></html>",
        "rate_limited",
    ),
    "identity unreachable": (
        503,
        {
            "error": "service_unavailable",
            "message": "Authentication service temporarily unavailable",
        },
        "unavailable",
    ),
    "the data service unreachable": (
        502,
        "<html><h1>502 Bad Gateway</h1></html>",
        "unavailable",
    ),
    "the batch not stored": (
        503,
        {"error": {"code": 503, "message": "The batch was not stored; send it again."}},
        "unavailable",
    ),
    "a route that is not the ingest route": (
        404,
        {"error": "not_found"},
        "misconfigured",
    ),
    "a request nginx refuses": (
        400,
        "<html><h1>400 Bad Request</h1></html>",
        "misconfigured",
    ),
    "a method not allowed there": (405, "", "misconfigured"),
}


@pytest.mark.parametrize("case", sorted(NOT_ABOUT_THE_EVENTS))
@pytest.mark.asyncio
async def test_an_answer_that_is_not_about_the_events_costs_none(
    gateway, monkeypatch, case
):
    # main: every one of these but 429 and the 5xx dropped the batch and let
    # the log positions move past its lines. A revoked key threw away
    # everything the sensor read, for good.
    monkeypatch.setattr(data_forwarder, "RATE_LIMIT_DELAY", 0)
    status, body, state = NOT_ABOUT_THE_EVENTS[case]
    gateway.status, gateway.body = status, body
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    settled = []
    await forwarder._init_session()
    try:
        forwarder.accept(_tracked(settled, "a"))
        forwarder.accept(_tracked(settled, "b"))

        assert await forwarder._flush_batch() == RETRY
        assert await forwarder._flush_batch() == RETRY
        refused = forwarder.get_status()

        # Whoever had to act has acted, or the limit has passed.
        gateway.status, gateway.body = 200, None
        assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    # Kept, whole; nothing dropped, nothing its collector may move past.
    assert refused["buffer"]["events"] == 2
    assert refused["stats"]["events_dropped"] == 0
    assert refused["retry"]["consecutive_failures"] == 2
    assert refused["delivery"]["state"] == state
    assert refused["delivery"]["since"]
    assert refused["delivery"]["reason"].startswith(f"HTTP {status}")
    # And delivered once, when it could be.
    assert gateway.accepted_ids() == ["a", "b"]
    assert settled == ["a", "b"]
    assert forwarder.get_status()["delivery"] == {
        "state": "ok",
        "since": forwarder.delivery_since,
        "reason": None,
    }
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_a_refused_key_is_said_loudly_once_and_when_it_is_over(gateway, caplog):
    gateway.status = 401
    gateway.body = {
        "error": "invalid_token",
        "message": "Authentication token is invalid or expired",
    }
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    await forwarder._init_session()
    try:
        forwarder.accept(EVENTS[0])
        with caplog.at_level(logging.INFO, logger=data_forwarder.__name__):
            for _ in range(3):
                assert await forwarder._flush_batch() == RETRY
            gateway.status, gateway.body = 200, None
            assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    # Once, not at each of the three attempts; with what to do about it,
    # and that nothing is lost meanwhile.
    (said,) = errors
    assert said.startswith("Not delivering since ")
    assert "HTTP 401 invalid_token" in said
    assert "invalid, expired or revoked" in said
    assert "Nothing is dropped" in said
    assert (
        "The gateway accepts the sensor's batches again (it was unauthorized"
        in caplog.text
    )
    assert forwarder.stats["last_error"].startswith("HTTP 401 invalid_token")


@pytest.mark.asyncio
async def test_a_missing_scope_says_which_scope_the_key_needs(gateway, caplog):
    gateway.status = 403
    gateway.body = {"error": "insufficient_scope", "required_scope": "data:ingest"}
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)

    with caplog.at_level(logging.ERROR, logger=data_forwarder.__name__):
        assert await _flush(forwarder) == RETRY

    assert len(gateway.requests) == 1
    assert "data:ingest" in caplog.text
    assert forwarder.get_status()["delivery"]["state"] == "forbidden"
    assert len(forwarder.buffer) == 2


@pytest.mark.asyncio
async def test_a_sensor_without_a_key_says_so_in_its_delivery_state(gateway):
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, api_key="")

    assert forwarder.get_status()["delivery"]["state"] == "unconfigured"


@pytest.mark.parametrize(
    "status, text, expected",
    [
        (200, "", (SENT, "ok")),
        (201, "", (SENT, "ok")),
        (
            422,
            '{"error": {"code": 422, "message": "Validation failed"}}',
            (REFUSED, "payload"),
        ),
        (413, "<html>413 Request Entity Too Large</html>", (REFUSED, "payload")),
        (
            400,
            '{"error": {"code": 400, "message": "Too many events in batch. Maximum allowed: 1000"}}',
            (REFUSED, "payload"),
        ),
        (400, '{"error": "invalid_token"}', (RETRY, "unauthorized")),
        (400, "<html>400 Bad Request</html>", (RETRY, "misconfigured")),
        (400, "", (RETRY, "misconfigured")),
        (401, "", (RETRY, "unauthorized")),
        (403, "", (RETRY, "forbidden")),
        (429, "", (RETRY, "rate_limited")),
        (301, "", (RETRY, "misconfigured")),
        (307, "", (RETRY, "misconfigured")),
        (404, "", (RETRY, "misconfigured")),
        (409, "", (RETRY, "misconfigured")),
        (500, "", (RETRY, "unavailable")),
        (502, "", (RETRY, "unavailable")),
        (504, "", (RETRY, "unavailable")),
    ],
)
def test_what_each_answer_means(status, text, expected):
    outcome, state, reason = classify_answer(status, text)

    assert (outcome, state) == expected
    assert reason.startswith(f"HTTP {status}")


def test_the_reason_names_the_code_and_the_message_of_either_error_shape():
    gateway_shape = '{"error": "insufficient_scope", "message": "Not authorized", "required_scope": "data:ingest"}'
    service_shape = '{"error": {"code": 403, "message": "Forbidden", "details": {"code": "GATEWAY_AUTH_REQUIRED"}}}'

    assert (
        classify_answer(403, gateway_shape)[2]
        == "HTTP 403 insufficient_scope: Not authorized"
    )
    assert (
        classify_answer(403, service_shape)[2]
        == "HTTP 403 GATEWAY_AUTH_REQUIRED: Forbidden"
    )
    assert classify_answer(502, "<html>" + "x" * 5000)[2] == "HTTP 502"
    assert classify_answer(403, '{"error": {"message": 5}}')[2] == "HTTP 403"
    assert len(classify_answer(401, json.dumps({"error": "e" * 5000}))[2]) == 300
    assert classify_answer(403, "[" * 100_000)[2] == "HTTP 403"


@pytest.mark.parametrize(
    "text, expected",
    [
        ('{"events_received": 5, "events_ingested": 5}', 5),
        ('{"events_received": 5, "events_ingested": 3}', 3),
        ('{"events_received": 5, "events_ingested": 0}', 0),
        ('{"events_ingested": 99}', 5),  # more than was sent: no
        ('{"events_ingested": -1}', 0),
        ('{"events_ingested": "5"}', 5),  # not a count: the status stands
        ('{"events_ingested": true}', 5),
        ("{}", 5),
        ("[]", 5),
        ("", 5),
        ("<html>ok</html>", 5),
    ],
)
def test_how_many_events_an_accepting_answer_says_it_stored(text, expected):
    assert stored_events(text, 5) == expected


# -- an answer about the payload: the event at fault, not its batch ---------


async def _deliver(forwarder, events):
    """Hand the forwarder the events and flush until its buffer is empty;
    the outcomes."""
    await forwarder._init_session()
    outcomes = []
    try:
        for event in events:
            forwarder.accept(event)
        while forwarder.buffer:
            outcomes.append(await forwarder._flush_batch())
            assert len(outcomes) < 500, "the forwarder does not finish"
    finally:
        await forwarder.session.close()
    return outcomes


@pytest.mark.asyncio
async def test_one_unacceptable_event_costs_that_event_and_not_its_batch(
    gateway, caplog
):
    # main: the 100 events of the batch, for one the data service refused.
    gateway.unacceptable = {"e37"}
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=100)
    settled = []
    events = [_tracked(settled, f"e{index}") for index in range(100)]

    with caplog.at_level(logging.ERROR, logger=data_forwarder.__name__):
        await _deliver(forwarder, events)

    delivered = [f"e{index}" for index in range(100) if index != 37]
    assert gateway.accepted_ids() == delivered
    assert forwarder.stats["events_forwarded"] == 99
    assert forwarder.stats["events_dropped_refused"] == 1
    assert forwarder.stats["events_dropped"] == 1
    # Every event is finished with, the dropped one included.
    assert sorted(settled) == sorted(f"e{index}" for index in range(100))
    # About two requests for each halving of 100.
    assert len(gateway.requests) <= 16
    assert forwarder.stats["batches_split"] >= 6
    assert (
        "The data service refuses an event of type 'network.listening_ports'"
        in caplog.text
    )
    assert "HTTP 422" in caplog.text
    assert forwarder.get_status()["delivery"]["state"] == "ok"
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_the_running_forwarder_does_not_wait_between_the_parts_of_a_split(
    gateway,
):
    # Fewer events than a batch, due after flush_interval: once the batch
    # is refused, its parts are not each made to wait that long again.
    gateway.unacceptable = {"e2"}
    forwarder = _forwarder(
        gateway.url, ca_bundle=gateway.ca, batch_size=100, flush_interval=1
    )

    await forwarder.start()
    try:
        for event in _numbered(6):
            await forwarder.input_queue.put(event)
        started = asyncio.get_running_loop().time()
        await _until(
            lambda: not forwarder.buffer and forwarder.stats["events_forwarded"] == 5
        )
        took = asyncio.get_running_loop().time() - started
    finally:
        await forwarder.stop()

    assert gateway.accepted_ids() == ["e0", "e1", "e3", "e4", "e5"]
    assert forwarder.stats["events_dropped_refused"] == 1
    # One flush_interval before the batch is due, not one for each part.
    assert took < 2.5


@pytest.mark.asyncio
async def test_several_unacceptable_events_are_each_found(gateway):
    gateway.unacceptable = {"e0", "e21", "e22", "e49"}
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=50)

    await _deliver(forwarder, _numbered(60))

    assert gateway.accepted_ids() == [
        f"e{index}" for index in range(60) if index not in (0, 21, 22, 49)
    ]
    assert forwarder.stats["events_dropped_refused"] == 4
    assert forwarder.stats["events_forwarded"] == 56


@pytest.mark.parametrize("too_many", [413, 400])
@pytest.mark.asyncio
async def test_a_batch_refused_for_its_size_is_delivered_in_parts_and_loses_nothing(
    gateway, too_many
):
    # nginx's 413 for a body too large, or the data service's 400 for too
    # many events: no event is at fault, and no half of the batch is taken
    # for refused because the other one was accepted.
    gateway.most_events = 12
    gateway.too_many = too_many
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=100)

    await _deliver(forwarder, _numbered(100))

    assert gateway.accepted_ids() == _ids(100)
    assert forwarder.stats["events_dropped"] == 0
    assert forwarder.stats["events_forwarded"] == 100
    assert (
        max(len(r["json"]["events"]) for r in gateway.requests if r["status"] == 200)
        <= 12
    )


@pytest.mark.asyncio
async def test_the_work_spent_on_one_refused_batch_is_bounded(gateway, caplog):
    # A batch of which the data service accepts nothing, in any part.
    gateway.unacceptable = set(_ids(100))
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=100)
    await forwarder._init_session()
    try:
        for event in _numbered(100):
            forwarder.accept(event)
        forwarder.accept(dict(EVENTS[0], id="after"))
        with caplog.at_level(logging.ERROR, logger=data_forwarder.__name__):
            for _ in range(300):
                if len(forwarder.buffer) <= 1:
                    break
                await forwarder._flush_batch()
        refused_batch = len(gateway.requests)
        assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    # Not one request for each of its hundred events and their halves.
    assert refused_batch <= SPLIT_BUDGET + 1
    assert forwarder.stats["events_dropped_refused"] == 100
    assert "requests: the " in caplog.text and "are dropped with them" in caplog.text
    # And the batch after it is not held up.
    assert gateway.accepted_ids() == ["after"]
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_an_outage_while_a_batch_is_being_split_loses_and_repeats_nothing(
    gateway,
):
    gateway.unacceptable = {"e5"}
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=16)
    await forwarder._init_session()
    try:
        for event in _numbered(16):
            forwarder.accept(event)
        assert await forwarder._flush_batch() == REFUSED
        # Refused for what it holds: the request did get through.
        assert forwarder.get_status()["delivery"]["state"] == "ok"
        assert await forwarder._flush_batch() == REFUSED  # the half with e5
        # The gateway goes away in the middle of it.
        gateway.outage.extend([503, 502, 429])
        gateway.retry_after = "0"
        for _ in range(3):
            assert await forwarder._flush_batch() == RETRY
        assert forwarder.get_status()["delivery"]["state"] == "rate_limited"
        assert forwarder.stats["events_dropped"] == 0
        while forwarder.buffer:
            await forwarder._flush_batch()
    finally:
        await forwarder.session.close()

    assert sorted(gateway.accepted_ids(), key=lambda i: int(i[1:])) == [
        f"e{index}" for index in range(16) if index != 5
    ]
    assert len(gateway.accepted_ids()) == 15
    assert forwarder.stats["events_dropped_refused"] == 1


@pytest.mark.asyncio
async def test_events_a_200_says_were_not_stored_are_not_counted_as_forwarded(
    gateway, caplog
):
    # The data service answers 200 with events_ingested below what it
    # received when it could not process some events. They were counted as
    # forwarded.
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    gateway.body = {
        "batch_id": "b",
        "events_received": 5,
        "events_ingested": 3,
        "errors": ["Event 1: processing failed", "Event 4: processing failed"],
    }
    settled = []
    await forwarder._init_session()
    try:
        for index in range(5):
            forwarder.accept(_tracked(settled, f"e{index}"))
        with caplog.at_level(logging.ERROR, logger=data_forwarder.__name__):
            assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    assert forwarder.stats["events_forwarded"] == 3
    assert forwarder.stats["events_dropped_refused"] == 2
    assert len(settled) == 5
    assert "stored 3 of the 5 events" in caplog.text
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_a_200_that_stored_nothing_is_not_a_delivery(gateway):
    # "Batch commit failed": the data service answers 200 and has stored
    # none of the batch. The sensor took it for delivered.
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    gateway.body = {
        "batch_id": "b",
        "events_received": 2,
        "events_ingested": 0,
        "errors": ["Batch commit failed"],
    }
    settled = []
    await forwarder._init_session()
    try:
        forwarder.accept(_tracked(settled, "a"))
        forwarder.accept(_tracked(settled, "b"))
        assert await forwarder._flush_batch() == REFUSED
        assert settled == [] and len(forwarder.buffer) == 2
        assert forwarder.stats["events_forwarded"] == 0

        # It was the commit of that moment: its halves are stored.
        gateway.body = None
        while forwarder.buffer:
            assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    assert gateway.requests[-2]["json"]["events"][0]["event_data"]["id"] == "a"
    assert forwarder.stats["events_forwarded"] == 2
    assert forwarder.stats["events_dropped"] == 0
    assert settled == ["a", "b"]


@pytest.mark.asyncio
async def test_a_batch_that_fails_for_a_passing_reason_stays_whole_and_in_place(
    gateway,
):
    gateway.status = 503
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    await forwarder._init_session()
    try:
        for event in EVENTS:
            forwarder.accept(event)

        assert await forwarder._flush_batch() == RETRY
        assert await forwarder._flush_batch() == RETRY

        # One request per attempt, the same two events each time, and both
        # still held: nothing was given up.
        assert [len(r["json"]["events"]) for r in gateway.requests] == [2, 2]
        assert _held_ids(forwarder) == ["e1", "e2"]
        assert forwarder.failures == 2
        assert forwarder.stats["send_failures"] == 2
        assert forwarder.stats["events_dropped"] == 0

        gateway.status = 200
        assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    assert gateway.accepted_ids() == ["e1", "e2"]
    assert not forwarder.buffer and forwarder.buffer_bytes == 0
    assert forwarder.failures == 0
    assert forwarder.stats["events_forwarded"] == 2
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_an_outage_loses_no_event_and_repeats_none(gateway):
    # What main did with this: 300 events collected while every batch failed
    # left the first 100 in the buffer and lost the other 200, one with each
    # further attempt.
    gateway.status = 503
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=100)
    await forwarder._init_session()
    try:
        for event in _numbered(300):
            forwarder.accept(event)
            if len(forwarder.buffer) >= 100:
                assert await forwarder._flush_batch() == RETRY

        assert _held_ids(forwarder) == _ids(300)
        assert forwarder.stats["events_dropped"] == 0

        gateway.status = 200
        while forwarder.buffer:
            assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    assert gateway.accepted_ids() == _ids(300)
    assert forwarder.stats["events_forwarded"] == 300
    assert forwarder.stats["batches_sent"] == 3
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_the_running_forwarder_sends_everything_once_after_an_outage(
    gateway, monkeypatch
):
    # The real loops: events arrive on the queue while the first six
    # attempts fail, for a reason that passes.
    monkeypatch.setattr(data_forwarder, "RATE_LIMIT_DELAY", 0)
    gateway.outage.extend([503, 502, 500, 429, 503, 504])
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=10)

    await forwarder.start()
    try:
        for event in _numbered(95):
            await forwarder.input_queue.put(event)
        await _until(lambda: forwarder.stats["events_forwarded"] >= 90)
        # The last five are fewer than a batch: they go when the forwarder
        # stops, or after flush_interval.
    finally:
        await forwarder.stop()

    assert gateway.accepted_ids() == _ids(95)
    assert forwarder.stats["events_forwarded"] == 95
    assert forwarder.stats["send_failures"] == 6
    assert forwarder.stats["events_dropped"] == 0
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_a_batch_smaller_than_batch_size_goes_after_flush_interval(gateway):
    forwarder = _forwarder(
        gateway.url, ca_bundle=gateway.ca, batch_size=100, flush_interval=1
    )

    await forwarder.start()
    try:
        await forwarder.input_queue.put(EVENTS[0])
        await _until(lambda: forwarder.stats["events_forwarded"] == 1)
    finally:
        await forwarder.stop()

    assert gateway.accepted_ids() == ["e1"]


@pytest.mark.asyncio
async def test_the_buffer_holds_no_more_events_than_its_bound_and_drops_none(gateway):
    gateway.status = 503
    forwarder = _forwarder(
        gateway.url,
        ca_bundle=gateway.ca,
        batch_size=5,
        buffer_max_events=20,
        queue_size=10,
    )
    largest = []
    hold = forwarder._hold

    def watched(*held):
        hold(*held)
        largest.append(len(forwarder.buffer))

    forwarder._hold = watched

    async def collector():
        for event in _numbered(100):
            await forwarder.input_queue.put(event)

    await forwarder.start()
    collecting = asyncio.ensure_future(collector())
    try:
        await _until(lambda: forwarder.get_status()["buffer"]["full"])
        await _until(lambda: forwarder.input_queue.full())
        await _until(lambda: forwarder.failures >= 2)

        # Full: the forwarder takes nothing more, the queue before it is
        # full too, and the collector waits. Nothing is dropped.
        assert len(forwarder.buffer) == 20
        assert not collecting.done()
        assert forwarder.stats["events_dropped"] == 0
        assert forwarder.stats["times_buffer_full"] == 1
        status = forwarder.get_status()
        assert status["buffer"] == {
            "events": 20,
            "bytes": forwarder.buffer_bytes,
            "max_events": 20,
            "max_bytes": forwarder.max_bytes,
            "full": True,
        }
        assert status["retry"]["consecutive_failures"] >= 1

        gateway.status = 200
        await asyncio.wait_for(collecting, timeout=10)
        await _until(lambda: forwarder.stats["events_forwarded"] == 100)
    finally:
        collecting.cancel()
        await forwarder.stop()

    assert max(largest) == 20
    assert gateway.accepted_ids() == _ids(100)
    assert forwarder.get_status()["buffer"]["full"] is False
    assert forwarder.stats["events_dropped"] == 0
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_the_buffer_holds_no_more_bytes_than_its_bound(gateway):
    gateway.status = 503
    forwarder = _forwarder(
        gateway.url,
        ca_bundle=gateway.ca,
        batch_size=4,
        buffer_max_bytes=MIN_BUFFER_BYTES,
    )
    events = [dict(event, data={"pad": "x" * 9000}) for event in _numbered(40)]
    size = len(encode_event(events[0], forwarder.sensor_id))
    fit = MIN_BUFFER_BYTES // size
    assert 2 <= fit < 40
    heaviest = []
    hold = forwarder._hold

    def watched(*held):
        hold(*held)
        heaviest.append(forwarder.buffer_bytes)

    forwarder._hold = watched

    await forwarder.start()
    try:
        for event in events:
            forwarder.input_queue.put_nowait(event)
        await _until(lambda: forwarder.get_status()["buffer"]["full"])
        assert len(forwarder.buffer) == fit
        assert forwarder.buffer_bytes == fit * size

        gateway.status = 200
        await _until(lambda: forwarder.stats["events_forwarded"] == 40)
    finally:
        await forwarder.stop()

    assert max(heaviest) <= MIN_BUFFER_BYTES
    assert gateway.accepted_ids() == _ids(40)
    assert forwarder.stats["events_dropped"] == 0


@pytest.mark.asyncio
async def test_a_batch_is_bounded_in_bytes_as_well_as_in_events(gateway, monkeypatch):
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=100)
    size = len(encode_event(_numbered(1)[0], forwarder.sensor_id))
    monkeypatch.setattr(data_forwarder, "MAX_BATCH_BYTES", 3 * size + 1)
    await forwarder._init_session()
    try:
        for event in _numbered(8):
            forwarder.accept(event)
        while forwarder.buffer:
            assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    assert [len(r["json"]["events"]) for r in gateway.requests] == [3, 3, 2]
    assert gateway.accepted_ids() == _ids(8)


@pytest.mark.asyncio
async def test_an_event_no_batch_could_carry_is_dropped_and_counted(gateway, caplog):
    forwarder = _forwarder(
        gateway.url, ca_bundle=gateway.ca, buffer_max_bytes=MIN_BUFFER_BYTES
    )
    huge = dict(EVENTS[0], id="huge", data={"pad": "x" * (MIN_BUFFER_BYTES + 1)})
    await forwarder._init_session()
    try:
        with caplog.at_level(logging.WARNING, logger=data_forwarder.__name__):
            assert forwarder.accept(_numbered(1)[0]) is True
            assert forwarder.accept(huge) is False
            assert forwarder.accept(_numbered(1, start=1)[0]) is True
        assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    assert gateway.accepted_ids() == ["e0", "e1"]
    assert forwarder.stats["events_dropped_oversize"] == 1
    assert forwarder.stats["events_dropped"] == 1
    assert "more than a batch may be" in caplog.text
    assert "network.listening_ports" in caplog.text
    assert _accounted(forwarder)


@pytest.mark.parametrize(
    "value", [b"bytes", float("nan"), float("inf"), {1, 2}, object()]
)
@pytest.mark.asyncio
async def test_an_event_json_cannot_carry_is_dropped_and_not_its_batch(
    gateway, caplog, value
):
    # It used to reach the request, fail there as a network error, and come
    # back with its batch at every attempt.
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    bad = dict(EVENTS[0], id="bad", data={"value": value})
    await forwarder._init_session()
    try:
        with caplog.at_level(logging.WARNING, logger=data_forwarder.__name__):
            assert forwarder.accept(_numbered(1)[0]) is True
            assert forwarder.accept(bad) is False
        assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    assert gateway.accepted_ids() == ["e0"]
    assert forwarder.stats["events_dropped_unserializable"] == 1
    assert forwarder.stats["network_errors"] == 0
    assert "JSON cannot carry" in caplog.text
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_what_is_left_when_the_sensor_stops_is_counted_and_said(gateway, caplog):
    gateway.status = 503
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=5)

    await forwarder.start()
    for event in _numbered(12):
        await forwarder.input_queue.put(event)
    await _until(lambda: len(forwarder.buffer) == 12 and gateway.requests)
    with caplog.at_level(logging.WARNING, logger=data_forwarder.__name__):
        await asyncio.wait_for(forwarder.stop(), timeout=10)

    assert forwarder.stats["events_dropped_shutdown"] == 12
    assert not forwarder.buffer and forwarder.buffer_bytes == 0
    assert (
        "Stopped with 12 events the gateway had not accepted: 12 are dropped"
        in caplog.text
    )
    assert "shutdown: 12" in caplog.text
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_stopping_sends_what_the_gateway_takes(gateway):
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=100)

    await forwarder.start()
    for event in _numbered(7):
        await forwarder.input_queue.put(event)
    await _until(lambda: len(forwarder.buffer) == 7)
    await forwarder.stop()

    assert gateway.accepted_ids() == _ids(7)
    assert forwarder.stats["events_dropped"] == 0


@pytest.mark.asyncio
async def test_stopping_during_a_request_does_not_send_its_batch_twice(gateway):
    # The gateway has the batch and is answering. Cancelling the request
    # there and sending "what is left" would store the batch twice.
    gateway.delay = 0.3
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, batch_size=3)

    await forwarder.start()
    for event in _numbered(3):
        await forwarder.input_queue.put(event)
    await _until(lambda: gateway.requests)
    assert forwarder.stats["events_forwarded"] == 0
    await asyncio.wait_for(forwarder.stop(), timeout=10)

    assert gateway.accepted_ids() == _ids(3)
    assert forwarder.stats["events_forwarded"] == 3
    assert forwarder.stats["events_dropped"] == 0


@pytest.mark.asyncio
async def test_stopping_interrupts_the_wait_before_the_next_attempt(gateway):
    gateway.status = 503
    forwarder = _forwarder(
        gateway.url,
        ca_bundle=gateway.ca,
        batch_size=1,
        retry_delay=3600,
        retry_max_delay=3600,
    )

    await forwarder.start()
    await forwarder.input_queue.put(EVENTS[0])
    await _until(lambda: forwarder.get_status()["retry"]["next_attempt"])
    await asyncio.wait_for(forwarder.stop(), timeout=5)

    assert forwarder.stats["events_dropped_shutdown"] == 1


@pytest.mark.asyncio
async def test_the_event_waiting_for_room_is_counted_when_the_sensor_stops(gateway):
    gateway.status = 503
    forwarder = _forwarder(
        gateway.url, ca_bundle=gateway.ca, batch_size=5, buffer_max_events=5
    )

    await forwarder.start()
    for event in _numbered(10):
        forwarder.input_queue.put_nowait(event)
    await _until(lambda: forwarder.get_status()["buffer"]["full"])
    await asyncio.wait_for(forwarder.stop(), timeout=10)

    # Five held, one taken from the queue and waiting for room, four never
    # taken: those are still on the queue.
    assert forwarder.stats["events_received"] == 6
    assert forwarder.stats["events_dropped_shutdown"] == 6
    assert forwarder.input_queue.qsize() == 4
    assert _accounted(forwarder)


@pytest.mark.asyncio
async def test_a_gateway_that_does_not_answer_does_not_keep_the_sensor_from_stopping(
    gateway, monkeypatch
):
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.2)
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    await forwarder._init_session()
    forwarder.accept(EVENTS[0])

    async def never(body):
        await asyncio.sleep(3600)

    forwarder._send = never

    await asyncio.wait_for(forwarder.stop(), timeout=5)

    assert forwarder.stats["events_dropped_shutdown"] == 1


@pytest.mark.asyncio
async def test_drops_are_summed_up_in_the_log(gateway, caplog):
    gateway.status = 422
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    await forwarder._init_session()
    try:
        for event in EVENTS:
            forwarder.accept(event)
        with caplog.at_level(logging.WARNING, logger=data_forwarder.__name__):
            while forwarder.buffer:  # refused together, then each alone
                await forwarder._flush_batch()
            forwarder._report_drops(force=True)
            forwarder._report_drops(force=True)  # nothing new: no second line
    finally:
        await forwarder.session.close()

    sums = [r.getMessage() for r in caplog.records if "since the last" in r.message]
    assert sums == [
        "Dropped 2 events since the last report (refused: 2); 2 since the "
        "sensor started"
    ]
    assert caplog.text.count("The data service refuses an event of type") == 2
    assert "(HTTP 422" in caplog.text


# -- what a collector is told about its events (#725) ----------------------


def _tracked(settled, name, **fields):
    """An event whose collector wants to know when the sensor is done with
    it; ``settled`` receives its name then."""
    event = dict(EVENTS[0], id=name, **fields)
    event[DELIVERY_KEY] = Delivery(lambda: settled.append(name))
    return event


@pytest.mark.asyncio
async def test_an_event_is_settled_when_the_gateway_accepts_it_and_not_before(
    gateway,
):
    gateway.status = 503
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    settled = []
    await forwarder._init_session()
    try:
        forwarder.accept(_tracked(settled, "a"))
        forwarder.accept(dict(EVENTS[0], id="untracked"))
        forwarder.accept(_tracked(settled, "b"))
        assert await forwarder._flush_batch() == RETRY
        assert settled == []  # kept: its collector must not move past it

        gateway.status = 200
        assert await forwarder._flush_batch() == SENT
    finally:
        await forwarder.session.close()

    assert settled == ["a", "b"]
    # The handle travels with the event and is no part of what is sent.
    sent = json.dumps(gateway.requests[-1]["json"])
    assert gateway.accepted_ids() == ["a", "untracked", "b"]
    assert DELIVERY_KEY not in sent and "Delivery" not in sent


@pytest.mark.asyncio
async def test_an_event_dropped_for_good_is_settled(gateway):
    # Its collector reading it again would get it dropped again.
    forwarder = _forwarder(
        gateway.url, ca_bundle=gateway.ca, buffer_max_bytes=MIN_BUFFER_BYTES
    )
    settled = []
    await forwarder._init_session()
    try:
        forwarder.accept(_tracked(settled, "nan", data={"value": float("nan")}))
        forwarder.accept(
            _tracked(settled, "huge", data={"pad": "x" * MIN_BUFFER_BYTES})
        )
        assert settled == ["nan", "huge"]

        gateway.status = 422
        forwarder.accept(_tracked(settled, "refused"))
        assert await forwarder._flush_batch() == REFUSED
    finally:
        await forwarder.session.close()
    unconfigured = _forwarder(gateway.url, ca_bundle=gateway.ca, api_key="")
    unconfigured.accept(_tracked(settled, "no key"))

    assert settled == ["nan", "huge", "refused", "no key"]
    assert forwarder.stats["events_dropped"] == 3
    assert unconfigured.stats["events_dropped_unconfigured"] == 1


@pytest.mark.asyncio
async def test_what_is_left_at_stop_is_not_settled_and_counted_by_what_becomes_of_it(
    gateway, caplog
):
    gateway.status = 503
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    settled = []
    replayable = _tracked(settled, "in a log file, with a saved position")
    memory_only = _tracked(settled, "in a log file, positions in memory")
    memory_only[DELIVERY_KEY].replayable = False
    await forwarder._init_session()
    for event in (replayable, memory_only, dict(EVENTS[0], id="from osquery")):
        forwarder.accept(event)

    with caplog.at_level(logging.WARNING, logger=data_forwarder.__name__):
        await forwarder.stop()

    # Settled, the log forwarder would save a position past lines the data
    # service never got.
    assert settled == []
    assert forwarder.stats["events_returned_to_source"] == 1
    assert forwarder.stats["events_dropped_shutdown"] == 2
    assert (
        "Stopped with 3 events the gateway had not accepted: 2 are dropped, 1 "
        "will be read again from their log source after the restart"
    ) in caplog.text
    assert _accounted(forwarder)


def test_the_encoded_batch_is_the_batch_the_data_service_expects():
    encoded = json.loads(
        encode_batch([encode_event(event, "sensor-a") for event in EVENTS])
    )
    built = build_batch(EVENTS, "sensor-a")

    assert set(encoded) == set(built) == {"batch_id", "events"}
    # The second event's timestamp does not parse and is replaced by now.
    assert encoded["events"][0] == built["events"][0]
    assert {k: v for k, v in encoded["events"][1].items() if k != "timestamp"} == {
        k: v for k, v in built["events"][1].items() if k != "timestamp"
    }
    assert json.loads(encode_batch([]))["events"] == []


def test_the_buffer_settings_are_validated():
    def errors(**settings):
        return DataLakeConfig(
            endpoint="https://gw", api_key=API_KEY, **settings
        ).validate()

    assert errors() == []
    assert errors(buffer_max_events=100, batch_size=100) == []
    assert "buffer_max_events (99)" in errors(buffer_max_events=99)[0]
    assert "buffer_max_bytes" in errors(buffer_max_bytes=MIN_BUFFER_BYTES - 1)[0]
    assert "retry_max_delay" in errors(retry_delay=10, retry_max_delay=9)[0]
    assert "whole number" in errors(buffer_max_events="many")[0]
    assert "whole number" in errors(retry_max_delay=True)[0]


@pytest.mark.asyncio
async def test_a_retry_attempts_key_is_said_to_be_unused(gateway, caplog):
    config = _build_config_from_dict(
        {
            "data_lake": {
                "endpoint": gateway.url,
                "api_key": API_KEY,
                "ca_bundle": gateway.ca,
                "retry_attempts": 3,
                "buffer_max_events": 250,
                "retry_max_delay": 60,
            }
        }
    )
    assert config.validate() == []
    assert config.data_lake.buffer_max_events == 250
    assert config.data_lake.retry_max_delay == 60
    forwarder = DataForwarder(config, asyncio.Queue())

    with caplog.at_level(logging.WARNING, logger=data_forwarder.__name__):
        await forwarder.start()
        await forwarder.stop()

    assert "data_lake.retry_attempts is set and no longer used" in caplog.text


@pytest.mark.asyncio
async def test_a_redirect_is_not_followed_with_the_key(gateway):
    gateway.status = 307
    gateway.location = "/elsewhere"
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)

    await _flush(forwarder)

    assert [r["path"] for r in gateway.requests] == ["/api/v1/data/ingest"]


@pytest.mark.asyncio
async def test_the_key_is_never_logged(gateway, caplog):
    caplog.set_level(logging.DEBUG)

    for status in (200, 401, 403, 500):
        gateway.status = status
        forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
        await _flush(forwarder)
        forwarder.get_status()

    untrusted = _forwarder(gateway.url)
    await _flush(untrusted)
    insecure = _forwarder(gateway.url, tls_verify=False)
    await _flush(insecure)
    await insecure.test_connection()
    await insecure.session.close()

    assert caplog.records, "nothing was logged, so the assertion below proves nothing"
    assert API_KEY not in caplog.text
    assert API_KEY.split(".", 1)[1] not in caplog.text
    assert API_KEY not in json.dumps(untrusted.get_status())


@pytest.mark.asyncio
async def test_test_connection_posts_an_empty_batch(gateway):
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)

    result = await forwarder.test_connection()
    await forwarder.session.close()

    assert result["success"] is True
    assert result["status_code"] == 200
    assert gateway.requests[0]["json"]["events"] == []
    assert gateway.requests[0]["headers"].get("X-API-Key") == API_KEY


@pytest.mark.asyncio
async def test_without_a_key_nothing_is_sent_and_events_are_dropped(gateway):
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, api_key="")

    await forwarder.start()
    try:
        assert [forwarder.accept(event) for event in EVENTS] == [False, False]
        assert await forwarder._flush_batch() is None
    finally:
        await forwarder.stop()

    assert forwarder.session is None
    assert gateway.requests == []
    assert not forwarder.buffer
    assert forwarder.stats["events_dropped_unconfigured"] == 2
    assert _accounted(forwarder)
    assert forwarder.get_status()["forwarding_enabled"] is False
    assert (await forwarder.test_connection())["success"] is False


@pytest.mark.asyncio
async def test_rate_limiting_is_retried_after_what_the_gateway_asks(gateway):
    gateway.status = 429
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, retry_max_delay=40)
    await forwarder._init_session()
    try:
        forwarder.accept(EVENTS[0])
        asked = {}
        for header in (None, "25", "3600", "soon", "-5", "nan"):
            gateway.retry_after = header
            assert await forwarder._flush_batch() == RETRY
            asked[header] = forwarder._backoff()
    finally:
        await forwarder.session.close()

    # No Retry-After, or one that is no number of seconds: ten seconds. A
    # number: that long, and never longer than retry_max_delay.
    assert asked == {None: 10, "25": 25, "3600": 40, "soon": 10, "-5": 10, "nan": 10}
    assert _held_ids(forwarder) == ["e1"]


def test_the_delay_doubles_with_each_failure_up_to_its_bound():
    assert [retry_delay(failures, 5, 300) for failures in range(0, 9)] == [
        0,
        5,
        10,
        20,
        40,
        80,
        160,
        300,
        300,
    ]
    assert retry_delay(1000, 5, 300) == 300
    assert retry_delay(3, 0, 300) == 0


@pytest.mark.asyncio
async def test_the_running_forwarder_backs_off_between_failed_attempts(
    gateway, monkeypatch
):
    gateway.outage.extend([503] * 6)
    forwarder = _forwarder(
        gateway.url,
        ca_bundle=gateway.ca,
        batch_size=2,
        retry_delay=5,
        retry_max_delay=60,
    )
    backoffs = []

    async def no_wait(seconds):
        backoffs.append(seconds)

    monkeypatch.setattr(forwarder, "_pause", no_wait)
    await forwarder.start()
    try:
        for event in EVENTS:
            await forwarder.input_queue.put(event)
        await _until(lambda: forwarder.stats["events_forwarded"] == 2)
    finally:
        await forwarder.stop()

    # After each of the six failures, and before the attempt that passed:
    # 5 s, then twice as long each time, up to retry_max_delay; each up to a
    # fifth shorter, so that sensors do not return together.
    assert len(backoffs) == 6
    for waited, full in zip(backoffs, [5, 10, 20, 40, 60, 60]):
        assert 0.8 * full <= waited <= full
    assert len(gateway.requests) == 7
    assert gateway.accepted_ids() == ["e1", "e2"]
    assert forwarder.failures == 0


@pytest.mark.parametrize(
    "sensor_type, expected",
    [
        ("process_events.processes", "process_event"),
        ("network.listening_ports", "network_connection"),
        ("user_events.logged_in_users", "user_event"),
        ("system_inventory.os_version", "system_inventory"),
        ("file_created", "file_change"),
        ("log.nginx_access", "security_event"),
        (None, "security_event"),
    ],
)
def test_event_types_map_to_the_data_service_vocabulary(sensor_type, expected):
    assert ingest_event_type(sensor_type) == expected
