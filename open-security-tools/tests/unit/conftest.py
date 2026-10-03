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


@pytest.fixture(scope="module")
def https_server(tmp_path_factory):
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


@pytest.fixture
def task_ownership(fake_redis, monkeypatch):
    """The service's owner records, backed by a FakeRedis, for one test."""
    from app import task_ownership as module

    ownership = module.TaskOwnership(fake_redis)
    monkeypatch.setattr(module, "_ownership", ownership)
    return ownership
