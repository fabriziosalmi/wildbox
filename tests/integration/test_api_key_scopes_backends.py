"""API-key scopes reach the services, which check them again (#637).

The gateway enforced an API key's scopes and forwarded the user, the team and
the role alone: no service could tell a sensor's data:ingest key from its
owner's session, so the gateway's scope map was the only check there was.
The gateway now forwards what the credential is (X-Wildbox-Auth-Type) and an
API key's scopes (X-Wildbox-Scopes), and data, tools and guardian require
the scope again on what they are told.

Through the gateway, as any client:

  * a session, a key holding the scope and a key that is not limited are
    served by each of the three services. A service refuses a request that
    does not state its credential, so being served is itself the proof that
    the gateway states it, and states scopes the service accepts;
  * what a client puts in those two headers never reaches a service: a
    session that claims to be a data:ingest key is still served as a
    session, and a key that claims wider scopes is refused by the gateway.

And at the data and tools services directly, with the gateway's own secret,
playing a gateway whose scope map let the wrong key through: the service
refuses it by itself. That is the second check, working alone. These need
GATEWAY_INTERNAL_SECRET in the environment and are skipped without it.

Each module run registers its own account and keys at identity.
"""

import os
import secrets
import uuid

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
TIMEOUT = 30

IDENTITY_API = f"{GATEWAY_URL}/api/v1/identity"
DATA_API = f"{GATEWAY_URL}/api/v1/data"
TOOL = f"{GATEWAY_URL}/api/v1/tools/hash_generator"
GUARDIAN_ASSETS = f"{GATEWAY_URL}/api/v1/guardian/assets/assets/"

TOOL_INPUT = {"input_text": "wildbox"}


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _account():
    """A new account, owner of its own team: its session token."""
    address = f"scopes-backends-{secrets.token_hex(6)}@example.com"
    password = f"Scopes-Backends-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": address, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": address, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    return login.json()["access_token"]


def _key(token, scopes):
    """An API key of the account; ``scopes`` None for one that is not limited."""
    body = {"name": f"scopes-{secrets.token_hex(4)}"}
    if scopes is not None:
        body["scopes"] = scopes
    created = requests.post(
        f"{IDENTITY_API}/api-keys", json=body, headers=_bearer(token), timeout=TIMEOUT
    )
    assert created.status_code in (200, 201), created.text[:200]
    # identity writes "not limited" out as ["*"] (WILDBO-DOM-07).
    assert created.json()["scopes"] == (
        scopes if scopes is not None else ["*"]
    ), created.json()
    return {"X-API-Key": created.json()["key"]}


def _batch():
    return {
        "events": [
            {
                "sensor_id": f"scopes-{uuid.uuid4().hex[:8]}",
                "event_type": "security_event",
                "timestamp": "2026-10-05T10:00:00+00:00",
                "event_data": {"test": "scopes reach the backends"},
            }
        ]
    }


@pytest.fixture(scope="module")
def account():
    token = _account()
    return {
        "session": _bearer(token),
        "ingest": _key(token, ["data:ingest"]),
        "read": _key(token, ["read"]),
        "execute": _key(token, ["tools:execute"]),
        "tools_read": _key(token, ["tools:read"]),
        "data_read": _key(token, ["data:read"]),
        "unlimited": _key(token, None),
    }


def _served(response):
    assert response.status_code == 200, f"{response.status_code} {response.text[:300]}"
    return response


# --- Through the gateway: the credential is stated, and accepted -------------


def test_a_session_is_served_by_every_service_that_checks_a_scope(account):
    """Each of these refuses a request that does not say what it is."""
    session = account["session"]

    ingested = _served(
        requests.post(
            f"{DATA_API}/ingest", json=_batch(), headers=session, timeout=TIMEOUT
        )
    )
    assert ingested.json()["events_ingested"] == 1
    _served(
        requests.get(f"{DATA_API}/telemetry/events", headers=session, timeout=TIMEOUT)
    )
    _served(requests.post(TOOL, json=TOOL_INPUT, headers=session, timeout=TIMEOUT))
    _served(requests.get(GUARDIAN_ASSETS, headers=session, timeout=TIMEOUT))


def test_a_key_is_served_where_its_scope_allows(account):
    """The scopes the gateway forwards satisfy the service as they did the gateway."""
    ingested = _served(
        requests.post(
            f"{DATA_API}/ingest",
            json=_batch(),
            headers=account["ingest"],
            timeout=TIMEOUT,
        )
    )
    assert ingested.json()["events_ingested"] == 1
    _served(
        requests.get(
            f"{DATA_API}/telemetry/events", headers=account["read"], timeout=TIMEOUT
        )
    )
    _served(
        requests.post(
            TOOL, json=TOOL_INPUT, headers=account["execute"], timeout=TIMEOUT
        )
    )
    _served(
        requests.get(GUARDIAN_ASSETS, headers=account["data_read"], timeout=TIMEOUT)
    )


def test_a_key_that_is_not_limited_is_served_everywhere(account):
    """Its "*" is forwarded as it is, and satisfies every service."""
    key = account["unlimited"]

    _served(
        requests.post(f"{DATA_API}/ingest", json=_batch(), headers=key, timeout=TIMEOUT)
    )
    _served(requests.get(f"{DATA_API}/telemetry/events", headers=key, timeout=TIMEOUT))
    _served(requests.post(TOOL, json=TOOL_INPUT, headers=key, timeout=TIMEOUT))
    _served(requests.get(GUARDIAN_ASSETS, headers=key, timeout=TIMEOUT))


def test_the_gateway_still_refuses_first(account):
    """The services' check is behind the gateway's, not instead of it."""
    for response in (
        requests.get(
            f"{DATA_API}/telemetry/events", headers=account["ingest"], timeout=TIMEOUT
        ),
        requests.post(
            TOOL, json=TOOL_INPUT, headers=account["tools_read"], timeout=TIMEOUT
        ),
        requests.post(
            GUARDIAN_ASSETS, json={}, headers=account["data_read"], timeout=TIMEOUT
        ),
    ):
        assert response.status_code == 403, response.text[:200]
        # The gateway's own body: the error at the top level.
        assert response.json().get("error") == "insufficient_scope", response.text[:200]


# --- Through the gateway: a client's own headers are dropped -----------------


@pytest.mark.parametrize(
    "forged",
    [
        # Would make the services refuse a read, a tool run and a guardian read.
        {"X-Wildbox-Auth-Type": "api_key", "X-Wildbox-Scopes": "data:ingest"},
        # Would make them answer 400: not something the gateway writes.
        {"X-Wildbox-Auth-Type": "root", "X-Wildbox-Scopes": "everything, please"},
        # Would make them refuse a request that states no scope at all.
        {"X-Wildbox-Auth-Type": "api_key"},
    ],
)
def test_a_session_is_served_whatever_credential_headers_it_sends(account, forged):
    headers = {**account["session"], **forged}

    _served(
        requests.get(f"{DATA_API}/telemetry/events", headers=headers, timeout=TIMEOUT)
    )
    _served(requests.post(TOOL, json=TOOL_INPUT, headers=headers, timeout=TIMEOUT))
    _served(requests.get(GUARDIAN_ASSETS, headers=headers, timeout=TIMEOUT))


def test_a_key_does_not_widen_its_scopes_with_a_header(account):
    forged = {"X-Wildbox-Auth-Type": "session", "X-Wildbox-Scopes": "*"}

    read = requests.get(
        f"{DATA_API}/telemetry/events",
        headers={**account["ingest"], **forged},
        timeout=TIMEOUT,
    )
    assert read.status_code == 403, read.text[:200]
    assert read.json().get("error") == "insufficient_scope"

    run = requests.post(
        TOOL,
        json=TOOL_INPUT,
        headers={**account["tools_read"], **forged},
        timeout=TIMEOUT,
    )
    assert run.status_code == 403, run.text[:200]
    assert run.json().get("required_scope") == "tools:execute"


# --- At the services: the second check, alone --------------------------------


def _as_gateway(auth_type=None, scopes=None):
    """The headers a gateway forwards, with the gateway's own secret."""
    secret = os.environ.get("GATEWAY_INTERNAL_SECRET", "")
    if not secret:
        pytest.skip("GATEWAY_INTERNAL_SECRET not set (e.g. fork PR without secrets)")
    headers = {
        "X-Wildbox-User-ID": str(uuid.uuid4()),
        "X-Wildbox-Team-ID": str(uuid.uuid4()),
        "X-Wildbox-Role": "member",
        "X-Gateway-Secret": secret,
    }
    if auth_type is not None:
        headers["X-Wildbox-Auth-Type"] = auth_type
    if scopes is not None:
        headers["X-Wildbox-Scopes"] = scopes
    return headers


def _refused(response, code):
    assert response.status_code == 403, f"{response.status_code} {response.text[:300]}"
    assert code in response.text, response.text[:300]


def test_the_data_service_refuses_a_sensor_key_the_gateway_let_through(service_urls):
    """A gateway whose map sent a data:ingest key to a read or a write."""
    data = service_urls["data"]
    sensor_key = _as_gateway("api_key", "data:ingest")

    _refused(
        requests.get(
            f"{data}/api/v1/telemetry/events", headers=sensor_key, timeout=TIMEOUT
        ),
        "INSUFFICIENT_SCOPE",
    )
    _refused(
        requests.get(f"{data}/api/v1/sensors", headers=sensor_key, timeout=TIMEOUT),
        "INSUFFICIENT_SCOPE",
    )
    _refused(
        requests.post(
            f"{data}/api/v1/indicators/lookup",
            json={"indicators": []},
            headers=sensor_key,
            timeout=TIMEOUT,
        ),
        "INSUFFICIENT_SCOPE",
    )
    # And serves it where the scope allows.
    _served(
        requests.post(
            f"{data}/api/v1/ingest", json=_batch(), headers=sensor_key, timeout=TIMEOUT
        )
    )


def test_the_data_service_refuses_an_ingest_without_the_scope(service_urls):
    data = service_urls["data"]

    _refused(
        requests.post(
            f"{data}/api/v1/ingest",
            json=_batch(),
            headers=_as_gateway("api_key", "read"),
            timeout=TIMEOUT,
        ),
        "INSUFFICIENT_SCOPE",
    )
    _refused(
        requests.post(
            f"{data}/api/v1/ingest",
            json=_batch(),
            headers=_as_gateway("api_key"),
            timeout=TIMEOUT,
        ),
        "INSUFFICIENT_SCOPE",
    )
    # A gateway that does not state the credential: refused, not trusted.
    _refused(
        requests.post(
            f"{data}/api/v1/ingest",
            json=_batch(),
            headers=_as_gateway(),
            timeout=TIMEOUT,
        ),
        "GATEWAY_AUTH_TYPE_REQUIRED",
    )
    malformed = requests.post(
        f"{data}/api/v1/ingest",
        json=_batch(),
        headers=_as_gateway("api_key", "data:ingest,write"),
        timeout=TIMEOUT,
    )
    assert malformed.status_code == 400, malformed.text[:200]


def test_the_tools_service_refuses_a_read_only_key_the_gateway_let_through(
    service_urls,
):
    """A gateway whose map required tools:read, or read, to run a tool."""
    run = f"{service_urls['tools']}/api/tools/hash_generator"

    for scopes in ("tools:read", "read", "data:write"):
        _refused(
            requests.post(
                run,
                json=TOOL_INPUT,
                headers=_as_gateway("api_key", scopes),
                timeout=TIMEOUT,
            ),
            "INSUFFICIENT_SCOPE",
        )
    _refused(
        requests.post(run, json=TOOL_INPUT, headers=_as_gateway(), timeout=TIMEOUT),
        "GATEWAY_AUTH_TYPE_REQUIRED",
    )
    # Reading stays with the gateway; running needs the scope.
    _served(
        requests.get(
            f"{run}/info", headers=_as_gateway("api_key", "tools:read"), timeout=TIMEOUT
        )
    )
    _served(
        requests.post(
            run,
            json=TOOL_INPUT,
            headers=_as_gateway("api_key", "tools:execute"),
            timeout=TIMEOUT,
        )
    )
    _served(
        requests.post(
            run, json=TOOL_INPUT, headers=_as_gateway("session"), timeout=TIMEOUT
        )
    )
