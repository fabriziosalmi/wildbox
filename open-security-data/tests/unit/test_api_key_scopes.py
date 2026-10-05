"""The data service checks API-key scopes itself (#637).

The gateway requires a scope of every request it forwards here: data:ingest
to post telemetry, read or write for everything else. It used to be the only
check. The service was told the user, the team and the role, so a sensor's
data:ingest key was indistinguishable from its owner's session, and a
mistake in the gateway's scope map would have opened the team's data to
that key with nothing behind it.

The gateway now forwards what the credential is (X-Wildbox-Auth-Type) and an
API key's scopes (X-Wildbox-Scopes), and these tests send requests the way
the gateway forwards them, headers and all, with no authentication
override:

* the ingest route takes a session, and a key holding data:ingest or a
  scope that implies it, and refuses every other key;
* every other route of the service refuses a data:ingest key, whatever the
  method. The routes are read from the application, so one added without
  the dependency fails here;
* a request that does not say what its credential is, or says it in a way
  the gateway never writes, is refused.

The ingest runs against an in-memory SQLite database.
"""

import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api import main  # noqa: E402
from app.models import SensorMetadata, TelemetryEvent  # noqa: E402

SECRET = "unit-test-gateway-secret-at-least-32-chars"
USER_ID = str(uuid.uuid4())
TEAM_ID = str(uuid.uuid4())
INGEST = "/api/v1/ingest"

# Routes that are not the API: no caller identity, nothing of a team's.
PUBLIC_PATHS = {
    "/health",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/docs/oauth2-redirect",
}


@compiles(UUID, "sqlite")
def _uuid_on_sqlite(_type, _compiler, **_kw):
    return "CHAR(32)"


@pytest.fixture(autouse=True)
def _gateway_secret(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    tables = [TelemetryEvent.__table__, SensorMetadata.__table__]
    TelemetryEvent.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine, autoflush=False)()
    # The database only: authentication is the service's own.
    main.app.dependency_overrides[main.get_db] = lambda: session
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.clear()
        session.close()
        engine.dispose()


def gateway(auth_type=None, scopes=None):
    """The headers the gateway forwards for a member."""
    headers = {
        "X-Wildbox-User-ID": USER_ID,
        "X-Wildbox-Team-ID": TEAM_ID,
        "X-Wildbox-Role": "member",
        "X-Gateway-Secret": SECRET,
    }
    if auth_type is not None:
        headers["X-Wildbox-Auth-Type"] = auth_type
    if scopes is not None:
        headers["X-Wildbox-Scopes"] = scopes
    return headers


def batch():
    return {
        "batch_id": str(uuid.uuid4()),
        "events": [
            {
                "sensor_id": "sensor-1",
                "event_type": "network_connection",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_host": "web-1",
                "event_data": {"type": "network.listening_ports"},
            }
        ],
    }


def refusal(response):
    """The code and the required scope of a 403, from the shared error body."""
    details = response.json()["error"]["details"]
    return details["code"], details["required_scope"]


def api_routes():
    """(method, path) for every API route, path parameters filled in."""
    found = []
    for route in main.app.routes:
        if not isinstance(route, APIRoute) or route.path in PUBLIC_PATHS:
            continue
        path = re.sub(r"\{[^}]+\}", "x", route.path)
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            found.append((method, path))
    return sorted(found)


# --- The ingest route --------------------------------------------------------


def test_the_sensor_key_ingests(client):
    response = client.post(
        INGEST, json=batch(), headers=gateway("api_key", "data:ingest")
    )

    assert response.status_code == 200, response.text
    assert response.json()["events_ingested"] == 1


@pytest.mark.parametrize(
    "scopes", ["data:write", "write", "admin", "*", "read data:ingest"]
)
def test_a_key_whose_scopes_imply_ingest_ingests(client, scopes):
    """What satisfied the route at the gateway before still does."""
    response = client.post(INGEST, json=batch(), headers=gateway("api_key", scopes))

    assert response.status_code == 200, response.text


def test_a_session_ingests(client):
    assert (
        client.post(INGEST, json=batch(), headers=gateway("session")).status_code == 200
    )


def test_a_service_calling_for_a_user_ingests(client):
    assert (
        client.post(INGEST, json=batch(), headers=gateway("service")).status_code == 200
    )


@pytest.mark.parametrize(
    "scopes", ["read", "data:read", "data:delete", "tools:execute", "tools:admin"]
)
def test_a_key_without_the_scope_does_not_ingest(client, scopes):
    response = client.post(INGEST, json=batch(), headers=gateway("api_key", scopes))

    assert response.status_code == 403
    assert refusal(response) == ("INSUFFICIENT_SCOPE", "data:ingest")
    assert (
        client.get("/api/v1/telemetry/events", headers=gateway("session")).json() == []
    )


def test_a_key_with_no_scopes_at_all_does_not_ingest(client):
    """An empty scope list reaches the service as no scopes header."""
    response = client.post(INGEST, json=batch(), headers=gateway("api_key"))

    assert response.status_code == 403
    assert refusal(response) == ("INSUFFICIENT_SCOPE", "data:ingest")


def test_a_request_that_does_not_state_its_credential_does_not_ingest(client):
    """A gateway from before these headers; nothing was stored."""
    response = client.post(INGEST, json=batch(), headers=gateway())

    assert response.status_code == 403
    assert refusal(response) == ("GATEWAY_AUTH_TYPE_REQUIRED", "data:ingest")
    assert (
        client.get("/api/v1/telemetry/events", headers=gateway("session")).json() == []
    )


@pytest.mark.parametrize(
    "auth_type,scopes",
    [
        ("api_key", "data:ingest,write"),
        ("api_key", ""),
        ("apikey", "data:ingest"),
        ("api_key", "data:ingest "),
    ],
)
def test_a_malformed_credential_description_is_refused(client, auth_type, scopes):
    response = client.post(INGEST, json=batch(), headers=gateway(auth_type, scopes))

    assert response.status_code == 400


def test_the_scope_does_not_replace_the_proof_of_origin(client):
    headers = gateway("api_key", "data:ingest")
    headers["X-Gateway-Secret"] = "not-the-gateway-secret-not-the-gateway"

    assert client.post(INGEST, json=batch(), headers=headers).status_code == 403


# --- Every other route -------------------------------------------------------


def test_the_application_has_the_routes_this_file_walks():
    routes = api_routes()

    assert ("POST", INGEST) in routes
    assert ("GET", "/api/v1/telemetry/events") in routes
    assert ("POST", "/api/v1/indicators/lookup") in routes
    assert len(routes) >= 14
    assert all(path.startswith("/api/v1/") for _, path in routes)


def test_the_sensor_key_is_refused_on_every_other_route(client):
    """data:ingest posts telemetry and nothing else, in the service as well."""
    headers = gateway("api_key", "data:ingest")
    for method, path in api_routes():
        if (method, path) == ("POST", INGEST):
            continue
        response = client.request(method, path, headers=headers)

        assert (
            response.status_code == 403
        ), f"{method} {path}: {response.status_code} {response.text[:200]}"
        expected = "read" if method == "GET" else "write"
        assert refusal(response) == ("INSUFFICIENT_SCOPE", expected), f"{method} {path}"


def test_no_route_serves_a_request_that_does_not_state_its_credential(client):
    for method, path in api_routes():
        response = client.request(method, path, headers=gateway())

        assert response.status_code == 403, f"{method} {path}: {response.status_code}"
        assert refusal(response)[0] == "GATEWAY_AUTH_TYPE_REQUIRED", f"{method} {path}"


def test_a_read_key_reads_and_does_not_write(client):
    headers = gateway("api_key", "read")

    assert client.get("/api/v1/telemetry/events", headers=headers).status_code == 200
    assert client.get("/api/v1/sensors", headers=headers).status_code == 200
    response = client.post(
        "/api/v1/indicators/lookup", json={"indicators": []}, headers=headers
    )
    assert response.status_code == 403
    assert refusal(response) == ("INSUFFICIENT_SCOPE", "write")


def test_a_resource_scope_is_not_the_generic_one(client):
    """The gateway requires the generic read here; data:read does not satisfy it."""
    response = client.get(
        "/api/v1/telemetry/events", headers=gateway("api_key", "data:read")
    )

    assert response.status_code == 403
    assert refusal(response) == ("INSUFFICIENT_SCOPE", "read")


def test_a_session_reads(client):
    """Unchanged for the dashboard: a session is not limited by scopes."""
    assert (
        client.get("/api/v1/telemetry/events", headers=gateway("session")).status_code
        == 200
    )
    assert client.get("/api/v1/sensors", headers=gateway("session")).status_code == 200
