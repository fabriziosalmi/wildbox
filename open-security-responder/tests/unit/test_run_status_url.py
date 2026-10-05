"""The execute response's status_url is a path a client can follow (#654).

It was the responder's own ``/v1/runs/{run_id}``. A client reaches the
responder only through the gateway, which publishes ``/v1/<x>`` as
``/api/v1/responder/<x>``; ``/v1/runs/...`` on the gateway is the dashboard
or a 404, never the run.

The path is a constant: nothing in it is taken from the request, so a
``Host`` or ``X-Forwarded-*`` header a client sends cannot move it. The
last test reads the gateway's configuration and follows the path through
the rewrite the gateway applies, so the constant and the gateway's route
cannot drift apart.
"""

import os
import re
import sys
import uuid
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

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

import app.main as main_module  # noqa: E402

RUN_ID = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"


@pytest.fixture
def started(monkeypatch):
    monkeypatch.setattr(
        main_module,
        "start_execution",
        lambda playbook_id, trigger_data=None, caller=None: RUN_ID,
    )
    monkeypatch.setattr(
        main_module.playbook_parser,
        "get_playbook",
        lambda playbook_id: SimpleNamespace(name="Simple Logging Test"),
    )


def headers(**extra):
    sent = {
        "X-Wildbox-User-ID": str(uuid.uuid4()),
        "X-Wildbox-Team-ID": str(uuid.uuid4()),
        "X-Wildbox-Role": "member",
        "X-Gateway-Secret": os.environ["GATEWAY_INTERNAL_SECRET"],
    }
    sent.update(extra)
    return sent


def execute(**extra_headers):
    response = TestClient(main_module.app).post(
        "/v1/playbooks/simple_notification/execute",
        json={},
        headers=headers(**extra_headers),
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_status_url_is_the_gateway_path_of_the_run(started):
    body = execute()
    assert body["run_id"] == RUN_ID
    assert body["status_url"].startswith("/api/v1/responder/")
    assert body["status_url"] == f"/api/v1/responder/runs/{RUN_ID}"


def test_status_url_names_no_scheme_and_no_host(started):
    """A path only: the client resolves it against the address it called."""
    status_url = execute()["status_url"]
    assert status_url.startswith("/") and not status_url.startswith("//")
    assert "://" not in status_url
    assert "open-security-responder" not in status_url


@pytest.mark.parametrize(
    "header, value",
    [
        ("Host", "evil.example"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Forwarded-Proto", "gopher"),
        ("X-Forwarded-Prefix", "/evil"),
        ("X-Forwarded-Path", "/evil"),
        ("X-Script-Name", "/evil"),
        ("X-Original-URI", "/evil/playbooks/simple_notification/execute"),
        ("Forwarded", "host=evil.example;proto=gopher"),
    ],
)
def test_no_request_header_changes_status_url(started, header, value):
    body = execute(**{header: value})
    assert body["status_url"] == f"/api/v1/responder/runs/{RUN_ID}"
    assert "evil" not in str(body)


def test_the_other_fields_of_the_answer_are_unchanged(started):
    assert execute() == {
        "run_id": RUN_ID,
        "playbook_id": "simple_notification",
        "playbook_name": "Simple Logging Test",
        "status": "accepted",
        "status_url": f"/api/v1/responder/runs/{RUN_ID}",
        "message": "Playbook 'Simple Logging Test' execution started",
    }


def test_the_schema_documents_the_202_and_its_status_url():
    """It said 200 with no body schema, so status_url was undocumented."""
    operation = main_module.app.openapi()["paths"][
        "/v1/playbooks/{playbook_id}/execute"
    ]["post"]
    assert "200" not in operation["responses"]
    schema = operation["responses"]["202"]["content"]["application/json"]["schema"]
    name = schema["$ref"].rsplit("/", 1)[-1]
    model = main_module.app.openapi()["components"]["schemas"][name]
    assert "status_url" in model["required"]
    assert "/api/v1/responder/runs/{run_id}" in (
        model["properties"]["status_url"]["description"]
    )


def gateway_rewrite():
    """(public prefix, upstream prefix) of the gateway's responder location.

    ``location /api/v1/responder/ { ... proxy_pass http://responder_service/v1/; }``
    makes nginx replace the location prefix with the proxy_pass path.
    """
    text = GATEWAY_CONF.read_text()
    match = re.search(
        r"^\s*location\s+(/api/v1/responder/)\s*\{(.*?)^\s{4}\}",
        text,
        re.DOTALL | re.MULTILINE,
    )
    assert match, "the gateway has no location for the responder"
    public_prefix, block = match.groups()
    upstream = re.search(
        r"^\s*proxy_pass\s+http://responder_service(/\S*);", block, re.MULTILINE
    )
    assert upstream, "the responder location has no proxy_pass with a path"
    return public_prefix, upstream.group(1)


@pytest.mark.skipif(
    not GATEWAY_CONF.is_file(), reason="the gateway's configuration is not here"
)
def test_the_gateway_routes_status_url_to_the_run(started, monkeypatch):
    """Follow status_url as the gateway would, and read the run it names."""
    public_prefix, upstream_prefix = gateway_rewrite()
    status_url = execute()["status_url"]
    assert status_url.startswith(
        public_prefix
    ), f"{status_url} is not under the gateway's responder route {public_prefix}"
    service_path = upstream_prefix + status_url[len(public_prefix) :]

    asked = []

    def get_execution_state(run_id):
        asked.append(run_id)
        return None

    monkeypatch.setattr(
        main_module.workflow_engine, "get_execution_state", get_execution_state
    )
    response = TestClient(main_module.app).get(service_path, headers=headers())
    # The run-status route answered, for this run: 404 "not found" from the
    # handler (no such run is stored), not the router's 404 for an unknown
    # path, which never reaches the engine.
    assert asked == [RUN_ID], f"{service_path} is not the run-status route"
    assert response.status_code == 404
    assert RUN_ID in response.text


def test_the_service_path_alone_is_not_what_the_client_is_given(started):
    """The regression itself: /v1/runs/{id} is not a gateway path."""
    assert not execute()["status_url"].startswith("/v1/")
