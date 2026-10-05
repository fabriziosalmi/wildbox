"""The task's result_url is a path a client can follow (#716).

It was the service's own ``/v1/analyze/{task_id}``. A client reaches the
agents service only through the gateway, which publishes ``/v1/<x>`` as
``/api/v1/agents/<x>``; ``/v1/analyze/...`` on the gateway is not the task.

The path is a constant: nothing in it is taken from the request, so a
``Host`` or ``X-Forwarded-*`` header a client sends cannot move it. The
last test reads the gateway's configuration and follows the path through
the rewrite the gateway applies, so the constant and the gateway's route
cannot drift apart.
"""

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

SERVICE_ROOT = Path(__file__).resolve().parents[2]
GATEWAY_CONF = (
    SERVICE_ROOT.parent
    / "open-security-gateway"
    / "nginx"
    / "conf.d"
    / "wildbox_gateway.conf"
)
sys.path.insert(0, str(SERVICE_ROOT))

from app import main  # noqa: E402

SECRET = "gateway-secret-for-tests"
OWNER = {
    "user_id": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "team_id": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "role": "member",
}
OTHER = {
    "user_id": "0b3f0e4c-8d1a-4c2e-9f5b-1a2b3c4d5e6f",
    "team_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "role": "admin",
}
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        value = self.store.get(key)
        if value is None:
            return None
        return value if isinstance(value, bytes) else str(value).encode()

    def setex(self, key, ttl, value):
        self.store[key] = value

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)

    def pipeline(self):
        return self

    def execute(self):
        return []


class PendingResult:
    def __init__(self, task_id, app=None):
        self.id = task_id
        self.state = "PENDING"
        self.info = None
        self.result = None


@pytest.fixture
def client(monkeypatch):
    """The app with Redis, Celery and the rate limit replaced."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "redis_client", FakeRedis())
    monkeypatch.setattr(main.limiter, "enabled", False)
    monkeypatch.setattr(main, "AsyncResult", PendingResult)
    monkeypatch.setattr(
        main.run_threat_enrichment_task,
        "delay",
        lambda **kwargs: SimpleNamespace(id="celery-task-1"),
    )
    return TestClient(main.app)


def headers(caller=OWNER, **extra):
    sent = {
        "X-Wildbox-User-ID": caller["user_id"],
        "X-Wildbox-Team-ID": caller["team_id"],
        "X-Wildbox-Role": caller["role"],
        "X-Gateway-Secret": SECRET,
    }
    sent.update(extra)
    return sent


def submit(client, **extra_headers):
    response = client.post(
        "/v1/analyze",
        json={"ioc": {"type": "domain", "value": "example.com"}},
        headers=headers(**extra_headers),
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_result_url_is_the_gateway_path_of_the_task(client):
    body = submit(client)

    assert re.fullmatch(UUID, body["task_id"])
    assert body["result_url"] == f"/api/v1/agents/analyze/{body['task_id']}"


def test_reading_the_task_gives_the_same_result_url(client):
    task_id = submit(client)["task_id"]

    read = client.get(f"/v1/analyze/{task_id}", headers=headers())

    assert read.status_code == 200, read.text
    assert read.json()["result_url"] == f"/api/v1/agents/analyze/{task_id}"


def test_result_url_names_no_scheme_and_no_host(client):
    """A path only: the client resolves it against the address it called."""
    result_url = submit(client)["result_url"]

    assert result_url.startswith("/") and not result_url.startswith("//")
    assert "://" not in result_url
    assert "open-security-agents" not in result_url
    # The regression itself: /v1/analyze/{id} is not a gateway path.
    assert not result_url.startswith("/v1/")


@pytest.mark.parametrize(
    "header, value",
    [
        ("Host", "evil.example"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Forwarded-Proto", "gopher"),
        ("X-Forwarded-Prefix", "/evil"),
        ("X-Forwarded-Path", "/evil"),
        ("X-Script-Name", "/evil"),
        ("X-Original-URI", "/evil/analyze"),
        ("Forwarded", "host=evil.example;proto=gopher"),
    ],
)
def test_no_request_header_changes_result_url(client, header, value):
    body = submit(client, **{header: value})

    assert body["result_url"] == f"/api/v1/agents/analyze/{body['task_id']}"
    assert "evil" not in str(body)


def test_the_schema_says_what_result_url_is():
    schema = main.app.openapi()["components"]["schemas"]["AnalysisTaskStatus"]

    assert (
        "/api/v1/agents/analyze/{task_id}"
        in schema["properties"]["result_url"]["description"]
    )


def gateway_rewrite():
    """The gateway's agents location: (pattern, upstream path template).

    ``location ~ ^/api/v1/agents/(.*)$ { proxy_pass http://agents_service/v1/$1...; }``
    sends the captured remainder to ``/v1/<remainder>`` on the service.
    """
    text = GATEWAY_CONF.read_text()
    match = re.search(
        r"^\s*location\s+~\s+(\^/api/v1/agents/\S+)\s*\{(.*?)^\s{4}\}",
        text,
        re.DOTALL | re.MULTILINE,
    )
    assert match, "the gateway has no regex location for the agents service"
    pattern, block = match.groups()
    upstream = re.search(
        r"^\s*proxy_pass\s+http://agents_service(/\S*?)(?:\$is_args\$args)?;",
        block,
        re.MULTILINE,
    )
    assert upstream, "the agents location has no proxy_pass with a path"
    return pattern, upstream.group(1)


@pytest.mark.skipif(
    not GATEWAY_CONF.is_file(), reason="the gateway's configuration is not here"
)
def test_the_gateway_routes_result_url_to_the_task(client):
    """Follow result_url as the gateway would, and read the task it names:
    its owner gets it, and anybody else is told it does not exist."""
    pattern, template = gateway_rewrite()
    body = submit(client)
    routed = re.fullmatch(pattern, body["result_url"])
    assert routed, f"{body['result_url']} is not under the gateway's agents route"
    service_path = template.replace("$1", routed.group(1))

    mine = client.get(service_path, headers=headers(OWNER))
    theirs = client.get(service_path, headers=headers(OTHER))

    assert mine.status_code == 200, f"{service_path}: {mine.text}"
    assert mine.json()["task_id"] == body["task_id"]
    # The handler's own 404 for a task that is not the caller's, not the
    # router's for a path it does not serve.
    assert theirs.status_code == 404
    assert theirs.json()["error"]["message"] == "Task not found"
