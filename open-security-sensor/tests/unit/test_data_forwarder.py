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
"""

import asyncio
import datetime
import json
import logging
import sys
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

from sensor.core.config import DataLakeConfig, SensorConfig  # noqa: E402
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import (  # noqa: E402
    REFUSED,
    RETRY,
    SENT,
    DataForwarder,
    ingest_event_type,
)

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
    """Records every request; answers with ``status`` (and ``location``)."""

    def __init__(self):
        self.requests = []
        self.status = 200
        self.body = {"batch_id": "b", "events_received": 0, "events_ingested": 0}
        self.location = None

    async def handle(self, request):
        raw = await request.read()
        self.requests.append(
            {
                "method": request.method,
                "path": request.path,
                "headers": dict(request.headers),
                "json": json.loads(raw) if raw else None,
            }
        )
        headers = {"Location": self.location} if self.location else None
        return web.json_response(self.body, status=self.status, headers=headers)


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


def _forwarder(endpoint, **data_lake):
    settings = {"api_key": API_KEY, "retry_attempts": 3, "retry_delay": 0}
    settings.update(data_lake)
    config = SensorConfig(data_lake=DataLakeConfig(endpoint=endpoint, **settings))
    forwarder = DataForwarder(config, asyncio.Queue())
    forwarder.min_request_interval = 0
    return forwarder


async def _flush(forwarder, events=EVENTS):
    await forwarder._init_session()
    try:
        forwarder.batch_buffer.extend(events)
        await forwarder._flush_batch()
    finally:
        await forwarder.session.close()


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
    forwarder = _forwarder(gateway.url, retry_attempts=1)

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
    forwarder = _forwarder(url, ca_bundle=gateway.ca, retry_attempts=1)

    await _flush(forwarder)

    assert gateway.requests == []
    assert forwarder.stats["batches_sent"] == 0
    assert "certificate" in str(forwarder.stats["last_error"]).lower()


@pytest.mark.asyncio
async def test_a_refused_key_is_not_retried(gateway, caplog):
    gateway.status = 401
    gateway.body = {"error": "invalid_token"}
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)

    with caplog.at_level(logging.ERROR, logger=data_forwarder.__name__):
        await _flush(forwarder)

    assert len(gateway.requests) == 1
    assert forwarder.stats["batches_sent"] == 0
    assert "invalid, expired or revoked" in caplog.text


@pytest.mark.asyncio
async def test_a_missing_scope_is_reported_and_not_retried(gateway, caplog):
    gateway.status = 403
    gateway.body = {"error": "insufficient_scope", "required_scope": "data:ingest"}
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)

    with caplog.at_level(logging.ERROR, logger=data_forwarder.__name__):
        await _flush(forwarder)

    assert len(gateway.requests) == 1
    assert "data:ingest" in caplog.text


@pytest.mark.asyncio
async def test_a_server_error_is_retried_with_the_configured_attempts(gateway):
    gateway.status = 503
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, retry_attempts=3)

    await _flush(forwarder)

    assert len(gateway.requests) == 3
    assert forwarder.stats["events_failed"] == 2
    # Kept for the next flush: the data service may be back by then.
    assert forwarder.batch_buffer == EVENTS


@pytest.mark.asyncio
async def test_while_the_gateway_is_unavailable_the_buffer_stays_bounded(gateway):
    # The log forwarder stops reading when the queue is full; what the sender
    # holds while every batch fails must not grow either. It keeps the
    # oldest 100 events to retry and gives up on what comes after them.
    gateway.status = 503
    forwarder = _forwarder(
        gateway.url, ca_bundle=gateway.ca, retry_attempts=1, batch_size=5
    )
    events = [dict(EVENTS[0], id=f"e{index}") for index in range(150)]
    largest = 0
    await forwarder._init_session()
    try:
        for event in events:
            forwarder.batch_buffer.append(event)
            largest = max(largest, len(forwarder.batch_buffer))
            if len(forwarder.batch_buffer) >= forwarder.config.data_lake.batch_size:
                await forwarder._flush_batch()
    finally:
        await forwarder.session.close()

    assert largest <= 101
    assert [event["id"] for event in forwarder.batch_buffer] == [
        f"e{index}" for index in range(100)
    ]
    assert forwarder.stats["events_forwarded"] == 0


@pytest.mark.parametrize("status", [401, 403, 413, 422])
@pytest.mark.asyncio
async def test_a_refused_batch_is_dropped_and_does_not_block_the_next(
    gateway, status
):
    # It used to be put back in the buffer: sent again with every flush,
    # refused again, and whatever was collected meanwhile lost with it. One
    # batch the gateway found too large (413) stopped forwarding for good.
    gateway.status = status
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    await forwarder._init_session()
    try:
        forwarder.batch_buffer.extend(EVENTS)
        await forwarder._flush_batch()

        assert forwarder.batch_buffer == []
        assert forwarder.stats["events_failed"] == 2

        gateway.status = 200
        forwarder.batch_buffer.append(EVENTS[0])
        await forwarder._flush_batch()
    finally:
        await forwarder.session.close()

    assert forwarder.stats["events_forwarded"] == 1
    assert [len(r["json"]["events"]) for r in gateway.requests] == [2, 1]


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
        forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca, retry_attempts=1)
        await _flush(forwarder)
        forwarder.get_status()

    untrusted = _forwarder(gateway.url, retry_attempts=1)
    await _flush(untrusted)
    insecure = _forwarder(gateway.url, tls_verify=False, retry_attempts=1)
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
    forwarder.batch_buffer.extend(EVENTS)
    await forwarder._flush_batch()
    forwarder.running = False

    assert forwarder.session is None
    assert gateway.requests == []
    assert forwarder.batch_buffer == []
    assert forwarder.stats["events_dropped_unconfigured"] == 2
    assert forwarder.get_status()["forwarding_enabled"] is False
    assert (await forwarder.test_connection())["success"] is False


@pytest.mark.asyncio
async def test_send_outcomes(gateway):
    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    await forwarder._init_session()
    try:
        outcomes = {}
        for status in (200, 201, 400, 401, 403, 422, 500, 502):
            gateway.status = status
            outcomes[status] = await forwarder._send_http_request({"events": []})
    finally:
        await forwarder.session.close()

    assert outcomes == {
        200: SENT,
        201: SENT,
        400: REFUSED,
        401: REFUSED,
        403: REFUSED,
        422: REFUSED,
        500: RETRY,
        502: RETRY,
    }


@pytest.mark.asyncio
async def test_rate_limiting_is_retried(gateway, monkeypatch):
    gateway.status = 429
    waits = []
    real_sleep = asyncio.sleep

    async def no_wait(seconds):
        waits.append(seconds)
        await real_sleep(0)

    forwarder = _forwarder(gateway.url, ca_bundle=gateway.ca)
    await forwarder._init_session()
    monkeypatch.setattr(data_forwarder.asyncio, "sleep", no_wait)
    try:
        outcome = await forwarder._send_http_request({"events": []})
    finally:
        monkeypatch.undo()
        await forwarder.session.close()

    assert outcome == RETRY
    assert 10 in waits


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
