"""The gateway's mock upstream hands each answer to the socket in one piece (#776).

``open-security-gateway/test/mock_identity.py`` is identity and every
upstream of the gateway's harness. Its handler wrote without a buffer, so the
headers of an answer went to the socket in one write and the body in a
second. On a connection that is kept open, as every connection nginx holds
to an upstream is, the kernel keeps the second segment back until the first
is acknowledged, and the other end delays that acknowledgement: about 40 ms
on Linux, for each request the gateway proxied. The harness sends thousands.

A time would be the wrong thing to assert: it depends on the kernel and on
the load of the machine. What is counted here is what causes it, the writes
the handler makes to the socket for one answer. The mock is started in this
process with the writer of each connection recorded.
"""

import http.client
import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MOCK = REPO_ROOT / "open-security-gateway" / "test" / "mock_identity.py"
SECRET = "mock-proof-of-origin-for-this-test"


@pytest.fixture(scope="module")
def mock():
    spec = importlib.util.spec_from_file_location("wildbox_mock_identity_776", MOCK)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.EXPECTED_SECRET = SECRET
    sent = []

    class Recording(module.Handler):
        def setup(self):
            super().setup()
            # The object that writes to the socket: the raw stream under a
            # buffered writer, or the writer itself when there is no buffer.
            raw = getattr(self.wfile, "raw", self.wfile)
            write = raw.write

            def recorded(data):
                sent.append(bytes(data))
                return write(data)

            raw.write = recorded

    server = ThreadingHTTPServer(("127.0.0.1", 0), Recording)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], sent
    server.shutdown()
    server.server_close()


def ask(connection, method, path, body=None, headers=None):
    """One request on a connection that stays open: (status, headers, body)."""
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    return response.status, dict(response.getheaders()), response.read()


def authorization(token):
    return json.dumps({"token": token, "token_type": "bearer"}).encode()


CASES = [
    ("GET", "/api/v1/tools/echo", None, {}, 200),
    ("POST", "/api/v1/data/ingest", b'{"a": 1}', {}, 200),
    ("GET", "/health", None, {}, 200),
    (
        "POST",
        "/internal/authorize",
        authorization("valid-bearer-token"),
        {"X-Gateway-Secret": SECRET},
        200,
    ),
    (
        "POST",
        "/internal/authorize",
        authorization("not-a-token"),
        {"X-Gateway-Secret": SECRET},
        401,
    ),
    ("POST", "/internal/authorize", authorization("valid-bearer-token"), {}, 403),
    ("GET", "/api/v1/redirect-fixture/append-slash", None, {}, 301),
]


@pytest.mark.parametrize("method,path,body,headers,expected", CASES)
def test_an_answer_is_one_write_to_the_socket(
    mock, method, path, body, headers, expected
):
    port, sent = mock
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        # The second request of a connection is the one that waited: ask
        # twice, and count the second answer.
        ask(connection, method, path, body, headers)
        del sent[:]
        status, _headers, answer = ask(connection, method, path, body, headers)
    finally:
        connection.close()

    assert status == expected
    assert len(sent) == 1, [len(piece) for piece in sent]
    # And that one write is the whole answer: its status line and its body.
    assert sent[0].startswith(b"HTTP/1.1 %d " % expected)
    assert sent[0].endswith(answer)


def test_the_answers_of_one_connection_do_not_run_into_each_other(mock):
    """A buffer that was not flushed would hold an answer back, or join two."""
    port, sent = mock
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        del sent[:]
        paths = [f"/api/v1/tools/echo-{number}" for number in range(5)]
        answers = [ask(connection, "GET", path) for path in paths]
    finally:
        connection.close()

    assert [status for status, _headers, _body in answers] == [200] * 5
    assert [json.loads(body)["path"] for _status, _headers, body in answers] == paths
    assert len(sent) == 5


def test_a_head_request_gets_headers_and_no_body(mock):
    port, sent = mock
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        del sent[:]
        status, headers, body = ask(connection, "HEAD", "/api/v1/tools/echo")
        # The connection is still usable: nothing of a body was left on it.
        again, _headers, echoed = ask(connection, "GET", "/api/v1/tools/after-head")
    finally:
        connection.close()

    assert (status, body) == (200, b"")
    assert int(headers["Content-Length"]) > 0
    assert again == 200
    assert json.loads(echoed)["path"] == "/api/v1/tools/after-head"
    assert len(sent) == 2
