"""guardian checks API-key scopes itself (#637).

The gateway requires a scope of every request it forwards to guardian:
data:read to read, data:write to change, data:delete to delete. It used to
be the only check: guardian was told the user, the team and the role, so a
mistake in the gateway's scope map had nothing behind it.

The gateway now forwards what the credential is (X-Wildbox-Auth-Type) and an
API key's scopes (X-Wildbox-Scopes). GatewayAuthMiddleware, the one way into
the API, requires the same scope again, and GatewayHeaderAuthentication
hands the credential to DRF as ``request.auth``. The requests below are sent
the way the gateway forwards them.
"""

import uuid

import pytest
from apps.core.authentication import GatewayHeaderAuthentication
from apps.core.gateway_middleware import (
    GatewayAuthMiddleware,
    GatewayUser,
    required_scope,
)
from django.contrib.auth.models import User
from django.test import Client, RequestFactory

_GW_SECRET = "test-gateway-secret"
_ASSETS = "/api/v1/assets/assets/"
_ASSET = "/api/v1/assets/assets/00000000-0000-4000-8000-000000000000/"


@pytest.fixture
def client(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    return Client(raise_request_exception=False)


def gateway(auth_type=None, scopes=None, role="admin"):
    """The headers the gateway forwards; auth type and scopes when given."""
    headers = {
        "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_TEAM_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_ROLE": role,
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
    }
    if auth_type is not None:
        headers["HTTP_X_WILDBOX_AUTH_TYPE"] = auth_type
    if scopes is not None:
        headers["HTTP_X_WILDBOX_SCOPES"] = scopes
    return headers


def call(client, method, url, headers):
    kwargs = {"secure": True, **headers}
    if method in ("post", "put", "patch"):
        kwargs.update(data={}, content_type="application/json")
    return getattr(client, method)(url, **kwargs)


def refused_for(response):
    """The scope a 403 says was required, or None when it is not a scope refusal."""
    if response.status_code != 403:
        return None
    body = response.json()
    return (
        body.get("required_scope") if body.get("code") == "INSUFFICIENT_SCOPE" else None
    )


# --- The scope of each method ------------------------------------------------


@pytest.mark.parametrize(
    "method,expected",
    [
        ("GET", "data:read"),
        ("HEAD", "data:read"),
        ("OPTIONS", "data:read"),
        ("POST", "data:write"),
        ("PUT", "data:write"),
        ("PATCH", "data:write"),
        ("DELETE", "data:delete"),
    ],
)
def test_the_required_scope_is_the_gateway_s(method, expected):
    """As the gateway maps /api/v1/guardian/ (auth_handler.lua)."""
    assert required_scope(method) == expected


@pytest.mark.django_db
@pytest.mark.parametrize(
    "method,url,scopes,needed",
    [
        ("get", _ASSETS, "data:ingest", "data:read"),
        ("get", _ASSETS, "tools:read", "data:read"),
        ("get", _ASSETS, "data:delete", "data:read"),
        ("post", _ASSETS, "data:read", "data:write"),
        ("post", _ASSETS, "read", "data:write"),
        ("put", _ASSET, "data:read", "data:write"),
        ("patch", _ASSET, "data:ingest", "data:write"),
        ("delete", _ASSET, "data:write", "data:delete"),
        ("delete", _ASSET, "write", "data:delete"),
        ("delete", _ASSET, "data:read data:write", "data:delete"),
    ],
)
def test_a_key_without_the_scope_is_refused(client, method, url, scopes, needed):
    response = call(client, method, url, gateway("api_key", scopes))

    assert refused_for(response) == needed, response.content[:300]
    assert response.json()["error"] == "insufficient_scope"
    # Refused before anything was written, the user's mirror row included.
    assert User.objects.count() == 0


@pytest.mark.django_db
@pytest.mark.parametrize(
    "method,url,scopes",
    [
        ("get", _ASSETS, "data:read"),
        ("get", _ASSETS, "data:write"),
        ("get", _ASSETS, "read"),
        ("get", _ASSETS, "*"),
        ("post", _ASSETS, "data:write"),
        ("post", _ASSETS, "write"),
        ("delete", _ASSET, "data:delete"),
        ("delete", _ASSET, "data:admin"),
        ("delete", _ASSET, "admin"),
    ],
)
def test_a_key_with_the_scope_reaches_the_view(client, method, url, scopes):
    """What the gateway let through before, guardian still serves."""
    response = call(client, method, url, gateway("api_key", scopes))

    # The view's own answer, whatever it is: a list, a validation error for
    # the empty body, a 404 for an asset that does not exist.
    assert refused_for(response) is None, response.content[:300]
    assert response.status_code in (200, 400, 404), response.content[:300]


@pytest.mark.django_db
@pytest.mark.parametrize("auth_type", ["session", "service"])
@pytest.mark.parametrize(
    "method,url", [("get", _ASSETS), ("post", _ASSETS), ("delete", _ASSET)]
)
def test_a_session_and_a_service_are_not_limited_by_scopes(
    client, auth_type, method, url
):
    response = call(client, method, url, gateway(auth_type))

    assert response.status_code in (200, 400, 404), response.content[:300]


@pytest.mark.django_db
def test_a_key_with_no_scopes_is_refused(client):
    """An empty scope list reaches the service as no scopes header."""
    response = call(client, "get", _ASSETS, gateway("api_key"))

    assert refused_for(response) == "data:read"


# --- A request that does not say what its credential is ----------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "method,url", [("get", _ASSETS), ("post", _ASSETS), ("delete", _ASSET)]
)
def test_a_request_that_does_not_state_its_credential_is_refused(client, method, url):
    """A gateway from before these headers, or a caller that does not say."""
    response = call(client, method, url, gateway())

    assert response.status_code == 403, response.content[:300]
    body = response.json()
    assert body["code"] == "GATEWAY_AUTH_TYPE_REQUIRED"
    assert "X-Wildbox-Auth-Type" in body["message"]
    assert User.objects.count() == 0


@pytest.mark.django_db
def test_scopes_without_an_auth_type_are_not_enough(client):
    response = call(client, "get", _ASSETS, gateway(None, "*"))

    assert response.status_code == 403
    assert response.json()["code"] == "GATEWAY_AUTH_TYPE_REQUIRED"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "auth_type,scopes",
    [
        ("jwt", None),
        ("API_KEY", "data:read"),
        ("api_key", "data:read,data:write"),
        ("api_key", "data:read  data:write"),
        ("api_key", ""),
        ("session", "Everything!"),
        ("session", "data:read\tdata:write"),
    ],
)
def test_a_malformed_credential_description_is_refused(client, auth_type, scopes):
    """Not read leniently: the gateway does not write these."""
    response = call(client, "get", _ASSETS, gateway(auth_type, scopes))

    assert response.status_code == 400, response.content[:300]
    assert response.json()["code"] == "INVALID_GATEWAY_HEADERS"
    assert User.objects.count() == 0


@pytest.mark.django_db
def test_scopes_limit_whatever_carries_them(client):
    """The gateway sends none for a session; if one arrives, it is a limit."""
    response = call(client, "post", _ASSETS, gateway("session", "data:read"))

    assert refused_for(response) == "data:write"


@pytest.mark.django_db
def test_the_scope_does_not_replace_the_proof_of_origin(client):
    headers = gateway("api_key", "*")
    headers["HTTP_X_GATEWAY_SECRET"] = "not-the-secret"

    response = call(client, "get", _ASSETS, headers)

    assert response.status_code == 403
    assert response.json()["code"] == "GATEWAY_SECRET_REQUIRED"


# --- What the views are given ------------------------------------------------


def _authenticated(monkeypatch, **credential):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    request = RequestFactory().get(_ASSETS, **gateway(**credential))
    assert GatewayAuthMiddleware(lambda r: None).process_request(request) is None
    return request


@pytest.mark.django_db
def test_the_gateway_user_carries_the_credential(monkeypatch):
    request = _authenticated(
        monkeypatch, auth_type="api_key", scopes="data:read tools:read"
    )

    assert request.gateway_user.auth_type == "api_key"
    assert request.gateway_user.scopes == ("data:read", "tools:read")
    assert request.gateway_user.has_scope("data:read")
    assert not request.gateway_user.has_scope("data:delete")


@pytest.mark.django_db
def test_a_session_has_no_scopes_and_every_scope(monkeypatch):
    request = _authenticated(monkeypatch, auth_type="session")

    assert request.gateway_user.auth_type == "session"
    assert request.gateway_user.scopes is None
    assert request.gateway_user.has_scope("data:delete")


@pytest.mark.django_db
def test_drf_gets_the_credential_as_request_auth(monkeypatch):
    request = _authenticated(monkeypatch, auth_type="api_key", scopes="data:read")

    class DrfRequest:
        _request = request

    user, auth = GatewayHeaderAuthentication().authenticate(DrfRequest())

    assert user is request.user
    assert auth is request.gateway_user
    assert auth.has_scope("data:read") and not auth.has_scope("data:write")


def test_a_gateway_user_built_without_a_credential_has_no_scope():
    user = GatewayUser(
        user_id=str(uuid.uuid4()), team_id=str(uuid.uuid4()), role="owner"
    )

    assert user.auth_type is None and user.scopes is None
    assert not user.has_scope("data:read")
