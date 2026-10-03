"""Unit tests for #181: enforce the gateway role on mutating viewsets and
tighten GatewayUser.has_perm().

Pure permission-logic tests — no DB access required.
"""

from types import SimpleNamespace

import pytest
from apps.core.gateway_middleware import GatewayUser
from apps.core.permissions import IsGatewayAdminOrReadOnly, RequireGatewayRole
from rest_framework.test import APIRequestFactory

factory = APIRequestFactory()


def _request(method, role="member", authenticated=True):
    req = getattr(factory, method.lower())("/x")
    req.user = SimpleNamespace(
        is_authenticated=authenticated,
        is_staff=role in ("owner", "admin"),
        is_superuser=role == "owner",
    )
    req.gateway_user = SimpleNamespace(role=role) if authenticated else None
    return req


# --- IsGatewayAdminOrReadOnly ------------------------------------------------
@pytest.mark.parametrize(
    "role,allowed", [("owner", True), ("admin", True), ("member", False)]
)
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_mutations_require_admin_role(role, allowed, method):
    assert (
        IsGatewayAdminOrReadOnly().has_permission(_request(method, role), None)
        is allowed
    )


@pytest.mark.parametrize("role", ["owner", "admin", "member"])
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_safe_methods_allowed_for_any_authenticated(role, method):
    assert (
        IsGatewayAdminOrReadOnly().has_permission(_request(method, role), None) is True
    )


def test_unauthenticated_denied_everywhere():
    perm = IsGatewayAdminOrReadOnly()
    assert perm.has_permission(_request("GET", authenticated=False), None) is False
    assert perm.has_permission(_request("POST", authenticated=False), None) is False


@pytest.mark.parametrize("is_staff,is_superuser", [(True, False), (True, True)])
def test_staff_flags_are_not_a_role_without_gateway_user(is_staff, is_superuser):
    # The legacy API-key path set these flags and no gateway_user, and the
    # permission read them as admin/owner (#629). Without a gateway identity
    # the caller is a member, whatever the flags say.
    req = factory.post("/x")
    req.user = SimpleNamespace(
        is_authenticated=True, is_staff=is_staff, is_superuser=is_superuser
    )
    req.gateway_user = None
    assert IsGatewayAdminOrReadOnly().has_permission(req, None) is False
    assert RequireGatewayRole("owner", "admin")().has_permission(req, None) is False


# --- RequireGatewayRole ------------------------------------------------------
def test_require_gateway_role_gates_all_methods():
    Perm = RequireGatewayRole("owner", "admin")()
    assert Perm.has_permission(_request("GET", "admin"), None) is True
    assert Perm.has_permission(_request("POST", "owner"), None) is True
    # A member is denied even read, since this gate has no public-read side.
    assert Perm.has_permission(_request("GET", "member"), None) is False


# --- GatewayUser.has_perm() (tightened) --------------------------------------
@pytest.mark.parametrize(
    "perm,role,expected",
    [
        ("guardian.view_asset", "member", True),
        ("guardian.read_finding", "member", True),
        ("guardian.add_asset", "member", False),
        ("guardian.change_asset", "member", False),
        ("guardian.delete_asset", "member", False),
        ("guardian.view_all_assets", "member", False),  # cross-tenant scope
        ("guardian.approve_review", "member", False),  # no loose "view" substring match
        ("guardian.delete_asset", "admin", True),
        ("guardian.delete_asset", "owner", True),
    ],
)
def test_has_perm_tightened(perm, role, expected):
    assert GatewayUser("u", "t", role).has_perm(perm) is expected
