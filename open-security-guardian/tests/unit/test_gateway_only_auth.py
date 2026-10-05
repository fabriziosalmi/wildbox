"""guardian accepts gateway-authenticated requests only (#629).

guardian used to accept its own ``APIKey`` rows from an ``X-API-Key`` header
on a direct request, beside the gateway. Such a request authenticated as role
admin with ``is_superuser`` set, without identity, key revocation, team
scoping or the gateway's rate limits. ``APIKeyAuthentication`` did the same
for DRF, also from ``Authorization: Bearer``.

The key rows these tests use are written into ``core_apikey`` with raw SQL,
in the table's shape from migration 0001: that is what a deployment upgraded
from a release with the model still holds until 0002 runs, and the code that
read them is what these tests guard against coming back.
"""

import uuid

import pytest
from apps.core.gateway_middleware import GatewayAuthMiddleware
from django.contrib.auth.models import User
from django.db import connection
from django.test import Client, RequestFactory

_GW_SECRET = "test-gateway-secret"
_LEGACY_KEY = "gsk_" + "0" * 32
_ASSETS = "/api/v1/assets/assets/"


@pytest.fixture
def client(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    return Client(raise_request_exception=False)


@pytest.fixture
def legacy_key_row(db):
    """An active, unexpired guardian key row owned by a staff superuser."""
    owner = User.objects.create(
        username="legacy-key-owner", is_staff=True, is_superuser=True
    )
    with connection.cursor() as cursor:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS core_apikey ("
            " id integer PRIMARY KEY AUTOINCREMENT,"
            " created_at datetime NOT NULL, updated_at datetime NOT NULL,"
            " name varchar(255) NOT NULL, key varchar(255) NOT NULL UNIQUE,"
            " is_active bool NOT NULL, last_used datetime NULL,"
            " expires_at datetime NULL, can_read bool NOT NULL,"
            " can_write bool NOT NULL, can_delete bool NOT NULL,"
            " rate_limit integer NOT NULL,"
            " user_id integer NOT NULL REFERENCES auth_user (id))"
        )
        cursor.execute(
            "INSERT INTO core_apikey (created_at, updated_at, name, key,"
            " is_active, last_used, expires_at, can_read, can_write,"
            " can_delete, rate_limit, user_id) VALUES"
            " ('2026-01-01 00:00:00', '2026-01-01 00:00:00', 'legacy', %s,"
            " 1, NULL, NULL, 1, 1, 1, 1000, %s)",
            [_LEGACY_KEY, owner.pk],
        )
    return owner


def _gateway_headers(role="admin"):
    return {
        "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_TEAM_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_ROLE": role,
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        "HTTP_X_WILDBOX_AUTH_TYPE": "session",
    }


def _assert_gateway_only(response):
    assert response.status_code == 403, response.content[:300]
    body = response.json()
    assert body["code"] == "GATEWAY_AUTH_REQUIRED", body
    assert "through the API gateway" in body["message"], body


@pytest.mark.django_db
@pytest.mark.parametrize("method", ["get", "post", "delete"])
def test_a_direct_x_api_key_request_is_refused(client, legacy_key_row, method):
    response = getattr(client, method)(_ASSETS, secure=True, HTTP_X_API_KEY=_LEGACY_KEY)
    _assert_gateway_only(response)


@pytest.mark.django_db
def test_a_direct_bearer_key_request_is_refused(client, legacy_key_row):
    # APIKeyAuthentication also read the key from Authorization: Bearer.
    response = client.get(
        _ASSETS, secure=True, HTTP_AUTHORIZATION=f"Bearer {_LEGACY_KEY}"
    )
    _assert_gateway_only(response)


@pytest.mark.django_db
def test_a_direct_request_without_any_credential_is_refused(client):
    _assert_gateway_only(client.get(_ASSETS, secure=True))


@pytest.mark.django_db
def test_a_key_never_authenticates_or_grants_superuser(legacy_key_row, monkeypatch):
    """The middleware leaves no user on the request, privileged or not."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    request = RequestFactory().get(_ASSETS, HTTP_X_API_KEY=_LEGACY_KEY)

    response = GatewayAuthMiddleware(lambda r: None).process_request(request)

    assert response is not None and response.status_code == 403
    assert not hasattr(request, "gateway_user")
    assert not hasattr(request, "user")
    assert not hasattr(request, "api_key")


@pytest.mark.django_db
def test_forged_gateway_headers_with_a_key_are_refused(client, legacy_key_row):
    """A key does not make up for a missing gateway secret."""
    headers = _gateway_headers(role="owner")
    del headers["HTTP_X_GATEWAY_SECRET"]
    response = client.get(_ASSETS, secure=True, HTTP_X_API_KEY=_LEGACY_KEY, **headers)
    assert response.status_code == 403, response.content[:300]
    assert response.json()["code"] == "GATEWAY_SECRET_REQUIRED"
    # No mirror user was created for the forged identity.
    assert not User.objects.filter(username=headers["HTTP_X_WILDBOX_USER_ID"]).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("role", ["owner", "admin", "member"])
def test_a_gateway_request_is_accepted(client, role):
    response = client.get(_ASSETS, secure=True, **_gateway_headers(role))
    assert response.status_code == 200, response.content[:300]
    assert isinstance(response.json()["results"], list)


@pytest.mark.django_db
def test_a_gateway_member_with_a_key_stays_a_member(client, legacy_key_row):
    """A key alongside a member's gateway identity does not raise the role."""
    headers = _gateway_headers(role="member")
    response = client.post(
        _ASSETS,
        data={"name": "x", "asset_type": "server"},
        content_type="application/json",
        secure=True,
        HTTP_X_API_KEY=_LEGACY_KEY,
        **headers,
    )
    assert response.status_code == 403, response.content[:300]
    mirror = User.objects.get(username=headers["HTTP_X_WILDBOX_USER_ID"])
    assert mirror.is_superuser is False
    assert mirror.is_staff is False


def test_drf_authenticates_from_the_gateway_only(settings):
    classes = settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]
    assert classes == ["apps.core.authentication.GatewayHeaderAuthentication"]


@pytest.mark.django_db
def test_the_api_key_table_is_dropped():
    """Migration 0002 removes guardian's key table and the audit log's FK."""
    tables = connection.introspection.table_names()
    assert "core_apikey" not in tables
    with connection.cursor() as cursor:
        columns = [
            column.name
            for column in connection.introspection.get_table_description(
                cursor, "core_auditlog"
            )
        ]
    assert "api_key_id" not in columns
