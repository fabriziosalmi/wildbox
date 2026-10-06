"""The gateway's mock identity answers errors as identity does (#736).

The gateway's auth tests run against ``open-security-gateway/test/
mock_identity.py``. It answered ``{"detail": "..."}``, FastAPI's default,
for 400, 401 and 403; identity answers the body every service shares,
``{"error": {"code", "message", "type", "request_id"}}``. The gateway reads
only the status today, so no test was wrong, but a gateway that came to read
the body would have been tested against a shape identity does not produce.

These start the mock in this process and compare what it answers with what
``open_security_shared.errors`` builds, and its words with identity's own.
"""

import importlib.util
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from open_security_shared.errors import error_body

REPO_ROOT = Path(__file__).resolve().parents[2]
MOCK = REPO_ROOT / "open-security-gateway" / "test" / "mock_identity.py"
IDENTITY = REPO_ROOT / "open-security-identity" / "app"
SECRET = "mock-proof-of-origin-for-this-test"
REQUEST_ID = "req-736-mock"


@pytest.fixture(scope="module")
def mock():
    spec = importlib.util.spec_from_file_location("wildbox_mock_identity_736", MOCK)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.EXPECTED_SECRET = SECRET
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def authorize(base, body, secret=SECRET, request_id=REQUEST_ID):
    """POST /internal/authorize; return (status, parsed body)."""
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Gateway-Secret"] = secret
    if request_id:
        headers["X-Request-ID"] = request_id
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    request = urllib.request.Request(
        f"{base}/internal/authorize", data=data, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_a_missing_gateway_secret_is_the_canonical_403(mock):
    status, body = authorize(mock, {"token": "x", "token_type": "bearer"}, secret="")
    assert status == 403
    assert body == error_body(403, "Invalid gateway secret", request_id=REQUEST_ID)


def test_a_wrong_gateway_secret_is_the_canonical_403(mock):
    status, body = authorize(
        mock, {"token": "x", "token_type": "bearer"}, secret="not-the-secret"
    )
    assert status == 403
    assert body == error_body(403, "Invalid gateway secret", request_id=REQUEST_ID)


def test_an_unknown_token_is_the_canonical_401(mock):
    status, body = authorize(mock, {"token": "no-such-token", "token_type": "bearer"})
    assert status == 401
    assert body == error_body(
        401, "Could not validate credentials", request_id=REQUEST_ID
    )


def test_an_unknown_api_key_is_the_canonical_401(mock):
    status, body = authorize(mock, {"token": "wsk_none.x", "token_type": "api_key"})
    assert status == 401
    assert body == error_body(401, "Invalid or inactive API key", request_id=REQUEST_ID)


def test_a_body_that_is_not_json_is_the_canonical_422(mock):
    status, body = authorize(mock, b'{"token": ')
    assert status == 422
    assert body == error_body(
        422, "Request validation failed", "ValidationError", REQUEST_ID
    )


def test_the_request_id_is_the_one_the_gateway_sent_or_unknown(mock):
    _, body = authorize(mock, {"token": "x", "token_type": "bearer"}, request_id="")
    assert body["error"]["request_id"] == "unknown"


def test_no_error_has_a_top_level_detail(mock):
    for token_type in ("bearer", "api_key"):
        _, body = authorize(mock, {"token": "nope", "token_type": token_type})
        assert set(body) == {"error"}
    assert '"detail"' not in MOCK.read_text(encoding="utf-8")


def test_the_mock_speaks_in_the_words_of_identity():
    """Every message of the mock is one identity raises on that path."""
    source = MOCK.read_text(encoding="utf-8")
    messages = set(re.findall(r'self\._error\(\s*\d+,\s*"([^"]+)"', source))
    assert len(messages) >= 5, messages
    identity = "".join(
        (IDENTITY / name).read_text(encoding="utf-8")
        for name in ("internal.py", "auth.py")
    )
    shared = (REPO_ROOT / "open-security-shared" / "errors.py").read_text(
        encoding="utf-8"
    )
    for message in sorted(messages):
        assert f'"{message}"' in identity or f'"{message}"' in shared, message
