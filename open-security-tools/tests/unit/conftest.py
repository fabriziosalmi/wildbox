"""Shared fixtures for the tools unit tests.

``https_server`` runs a local HTTPS server that presents a self-signed
certificate, so the TLS tests exercise a real handshake against a certificate
that the system trust store does not accept. ``trust_server_certificate``
makes that same certificate trusted for one test (through ``SSL_CERT_FILE``,
which ``ssl.create_default_context`` reads), to show that verification passes
when the certificate is trusted rather than failing unconditionally.
"""

import datetime
import ipaddress
import ssl
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

HOST = "127.0.0.1"


@dataclass
class HttpsServer:
    host: str
    port: int
    cert_path: Path

    @property
    def url(self) -> str:
        return f"https://{self.host}:{self.port}/"


class _Handler(BaseHTTPRequestHandler):
    def _send_headers(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        self.send_header("Content-Length", "2")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        self._send_headers()
        self.wfile.write(b"ok")

    def do_HEAD(self) -> None:  # noqa: N802 - http.server naming
        self._send_headers()

    def log_message(self, format, *args) -> None:  # noqa: A002
        pass


def _write_self_signed_certificate(directory: Path) -> tuple:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wildbox-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address(HOST))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "server.pem"
    key_path = directory / "server.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def allow_loopback_targets(monkeypatch):
    """Let the SSRF guard accept 127.0.0.1, and only it, for one test.

    The tools refuse loopback targets on every connection (app.safe_http),
    so a test that talks to a server on 127.0.0.1 has to say so. Every other
    private, local or metadata address is still refused.
    """
    from app.input_validation import InputSanitizer

    original = InputSanitizer._is_blocked_ip
    loopback = ipaddress.ip_address(HOST)

    def is_blocked(addr):
        return False if addr == loopback else original(addr)

    monkeypatch.setattr(InputSanitizer, "_is_blocked_ip", staticmethod(is_blocked))


@pytest.fixture
def https_server(_https_server_process, allow_loopback_targets):
    """A local HTTPS server with a self-signed certificate, reachable by tools.

    The server runs on 127.0.0.1, so the SSRF guard is told to accept that
    one address for the test (see ``allow_loopback_targets``).
    """
    return _https_server_process


@pytest.fixture(scope="module")
def _https_server_process(tmp_path_factory):
    """A local HTTPS server presenting a self-signed certificate."""
    directory = tmp_path_factory.mktemp("tls")
    cert_path, key_path = _write_self_signed_certificate(directory)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)

    server = ThreadingHTTPServer((HOST, 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield HttpsServer(HOST, server.server_address[1], cert_path)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def trust_server_certificate(https_server, monkeypatch):
    """Make the test server's certificate the trust store for this test."""
    monkeypatch.setenv("SSL_CERT_FILE", str(https_server.cert_path))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)


class FakeRedis:
    """The few Redis commands app.task_ownership uses, in memory.

    Strings in, strings out, as a client created with decode_responses=True.
    ``ttl`` keeps the expiry each key was given, so tests can check it.
    """

    def __init__(self):
        self.kv = {}
        self.zsets = {}
        self.ttl = {}

    def pipeline(self):
        return _FakePipeline(self)

    def set(self, key, value, ex=None):
        self.kv[key] = value
        if ex is not None:
            self.ttl[key] = ex
        return True

    def get(self, key):
        return self.kv.get(key)

    def mget(self, keys):
        return [self.kv.get(key) for key in keys]

    def delete(self, *keys):
        removed = 0
        for key in keys:
            removed += int(self.kv.pop(key, None) is not None)
            removed += int(self.zsets.pop(key, None) is not None)
        return removed

    def expire(self, key, seconds):
        self.ttl[key] = seconds
        return True

    def zadd(self, key, mapping):
        self.zsets.setdefault(key, {}).update(mapping)
        return len(mapping)

    def zrem(self, key, *members):
        zset = self.zsets.get(key, {})
        return sum(int(zset.pop(member, None) is not None) for member in members)

    def zremrangebyscore(self, key, low, high):
        low = float(low)
        high = float(high)
        zset = self.zsets.get(key, {})
        doomed = [m for m, score in zset.items() if low <= score <= high]
        for member in doomed:
            del zset[member]
        return len(doomed)

    def zrevrange(self, key, start, end):
        ordered = sorted(
            self.zsets.get(key, {}).items(), key=lambda item: item[1], reverse=True
        )
        members = [member for member, _ in ordered]
        return members[start:] if end == -1 else members[start : end + 1]


class _FakePipeline:
    def __init__(self, redis):
        self._redis = redis
        self._calls = []

    def __getattr__(self, name):
        def queue(*args, **kwargs):
            self._calls.append((name, args, kwargs))
            return self

        return queue

    def execute(self):
        return [getattr(self._redis, name)(*a, **kw) for name, a, kw in self._calls]


@pytest.fixture
def fake_redis():
    return FakeRedis()


# --- a real Redis ------------------------------------------------------------
#
# What the service keeps in Redis to share it between processes (the hourly
# operation limit, the asynchronous run counters) is tested against a Redis
# server, from more than one connection and more than one process: a stand-in
# written in Python would only show that the stand-in agrees with itself.
#
# TOOLS_TEST_REDIS_URL names the server to use; CI starts one for this suite
# (.github/workflows/test.yml), and a server that is named but does not answer
# fails the tests instead of skipping them. Without the variable a
# ``redis-server`` found on PATH is started on a free port for the session.
# With neither, these tests are skipped and say why.

REDIS_URL_VARIABLE = "TOOLS_TEST_REDIS_URL"


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def _wait_for_redis(url: str, seconds: float) -> bool:
    import time

    import redis

    client = redis.Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            try:
                if client.ping():
                    return True
            except (redis.RedisError, OSError):
                time.sleep(0.1)
        return False
    finally:
        client.close()


@pytest.fixture(scope="session")
def redis_url(tmp_path_factory):
    """The URL of a Redis server the tests may write to.

    The tests name every key after a random caller or a random prefix and
    delete what they wrote; nothing is flushed.
    """
    import os
    import shutil
    import subprocess

    configured = os.environ.get(REDIS_URL_VARIABLE)
    if configured:
        if not _wait_for_redis(configured, 10):
            pytest.fail(f"{REDIS_URL_VARIABLE} is set and no Redis answers there")
        yield configured
        return

    binary = shutil.which("redis-server")
    if binary is None:
        pytest.skip(
            f"needs a Redis server: set {REDIS_URL_VARIABLE} or install redis-server"
        )
    port = _free_port()
    process = subprocess.Popen(
        [
            binary,
            "--port",
            str(port),
            "--bind",
            HOST,
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            str(tmp_path_factory.mktemp("redis")),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"redis://{HOST}:{port}/0"
    try:
        if not _wait_for_redis(url, 10):
            pytest.fail("the redis-server started for the tests does not answer")
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture
def redis_client(redis_url):
    """A connection of its own to the test Redis, closed after the test."""
    import redis

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    yield client
    client.close()


class InMemoryOperationLimiter:
    """The operation limiter's interface, for tests that are not about it.

    Enforces the limit, in this process only. The limiter the service uses
    (app.security.rate_limit) is tested against a Redis server in
    test_operation_rate_limit.py.
    """

    def __init__(self):
        self.runs = {}

    def allow(self, user_id, operation, limit):
        taken = self.runs.get((user_id, operation), 0)
        if taken >= limit:
            return False
        self.runs[(user_id, operation)] = taken + 1
        return True


@pytest.fixture
def operation_limiter(monkeypatch):
    """Replace the service's operation limiter with an in-process one."""
    from app.security import rate_limit

    limiter = InMemoryOperationLimiter()
    monkeypatch.setattr(rate_limit, "_limiter", limiter)
    return limiter


@pytest.fixture
def task_ownership(fake_redis, monkeypatch):
    """The service's owner records, backed by a FakeRedis, for one test."""
    from app import task_ownership as module

    ownership = module.TaskOwnership(fake_redis)
    monkeypatch.setattr(module, "_ownership", ownership)
    return ownership
