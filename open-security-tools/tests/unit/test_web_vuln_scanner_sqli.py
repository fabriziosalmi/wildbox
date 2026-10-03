"""SQL injection indicator check in the web vulnerability scanner (#507).

The check read ``await response.text().lower()``, which calls ``.lower()`` on
the coroutine and raises ``AttributeError`` before any comparison, so it
never reported a finding. A local HTTP server that answers the injected
``id`` parameter with a database error must now produce SQLi-001.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from app.tools.web_vuln_scanner import main as scanner
from app.tools.web_vuln_scanner.schemas import WebVulnScannerInput


class _SqlErrorHandler(BaseHTTPRequestHandler):
    leak_error = True

    def do_GET(self):  # noqa: N802 - http.server API
        query = parse_qs(urlparse(self.path).query)
        body = "<html><body>ok</body></html>"
        if self.leak_error and "'" in "".join(query.get("id", [])):
            body = "<html><body>You have an error in your SQL syntax</body></html>"
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def http_server(request, allow_loopback_targets):
    handler = type("Handler", (_SqlErrorHandler,), {"leak_error": request.param})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
    server.server_close()


def _scan(url):
    return asyncio.run(scanner.execute_tool(WebVulnScannerInput(target_url=url)))


def _sqli(result):
    return [v for v in result.vulnerabilities if v.id == "SQLi-001"]


@pytest.mark.parametrize("http_server", [True], indirect=True)
def test_database_error_in_response_is_reported(http_server):
    result = _scan(http_server)

    assert result.success is True
    findings = _sqli(result)
    assert findings, "SQL error in the response was not reported"
    assert "sql syntax" in findings[0].evidence


@pytest.mark.parametrize("http_server", [False], indirect=True)
def test_clean_response_reports_no_sql_injection(http_server):
    assert _sqli(_scan(http_server)) == []
