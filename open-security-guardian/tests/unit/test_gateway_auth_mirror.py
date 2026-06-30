"""Regression tests for #110: gateway auth must yield a persistable DB user.

Guardian's models FK to ``django.contrib.auth.User`` (integer PK). The gateway
authenticates UUID users from the identity service, so the old middleware put a
non-persistable ``GatewayUser`` on ``request.user`` and every write that set
``created_by=request.user`` raised -> 500. The middleware now mirrors the
identity user into a real ``auth.User`` row.
"""
import uuid

import pytest
from django.contrib.auth.models import User
from django.test import RequestFactory

from apps.core.gateway_middleware import GatewayAuthMiddleware, GatewayUser
from apps.reporting.models import ReportTemplate

# Since #163 the middleware fails closed: it returns 503 unless
# GATEWAY_INTERNAL_SECRET is configured and the matching X-Gateway-Secret header
# is present. Provide both so these tests exercise the authenticated path.
_GW_SECRET = "test-gateway-secret"


@pytest.fixture(autouse=True)
def _configure_gateway_secret(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)


def _gateway_request(role="admin", user_id=None):
    req = RequestFactory().post("/api/v1/reporting/templates/")
    req.META["HTTP_X_WILDBOX_USER_ID"] = user_id or str(uuid.uuid4())
    req.META["HTTP_X_WILDBOX_TEAM_ID"] = str(uuid.uuid4())
    req.META["HTTP_X_WILDBOX_ROLE"] = role
    req.META["HTTP_X_GATEWAY_SECRET"] = _GW_SECRET
    assert GatewayAuthMiddleware(lambda r: None).process_request(req) is None
    return req


@pytest.mark.django_db
def test_gateway_request_user_is_real_db_user():
    req = _gateway_request("admin")
    assert isinstance(req.user, User)
    assert isinstance(req.user.pk, int)
    assert req.user.is_authenticated is True
    # rich gateway attributes are still available on request.gateway_user
    assert req.gateway_user.role == "admin"
    assert req.gateway_user.team_id


@pytest.mark.django_db
def test_created_by_fk_persists():
    """The actual #110 repro: a write setting created_by must succeed."""
    req = _gateway_request("member")
    tmpl = ReportTemplate.objects.create(
        name="t", report_type="vulnerability", template_content="x",
        created_by=req.user,
    )
    tmpl.refresh_from_db()
    assert tmpl.created_by_id == req.user.pk


@pytest.mark.django_db
def test_raw_gatewayuser_object_is_not_persistable():
    """Guards the root cause: a GatewayUser cannot be used as an FK value."""
    gu = GatewayUser(user_id=str(uuid.uuid4()), team_id=str(uuid.uuid4()), role="admin")
    with pytest.raises(ValueError):
        ReportTemplate.objects.create(
            name="t", report_type="vulnerability", template_content="x", created_by=gu,
        )


@pytest.mark.django_db
@pytest.mark.parametrize("role,expected", [("owner", True), ("admin", True), ("member", False)])
def test_has_perm_parity_with_old_gatewayuser(role, expected):
    """owner/admin privileged, member not — matching the old GatewayUser.has_perm."""
    req = _gateway_request(role)
    assert req.user.has_perm("vulnerabilities.view_all_vulnerabilities") is expected


@pytest.mark.django_db
def test_same_identity_uuid_maps_to_same_row():
    uid = str(uuid.uuid4())
    r1 = _gateway_request("member", user_id=uid)
    r2 = _gateway_request("member", user_id=uid)
    assert r1.user.pk == r2.user.pk
