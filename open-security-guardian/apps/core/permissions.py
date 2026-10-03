"""
Custom permissions for the Guardian application.

Mutating requests are gated on the caller's gateway role (owner/admin); plain
members get read-only access at the service layer (#181). The role comes from
``request.gateway_user`` (set by GatewayAuthMiddleware) and nowhere else: the
legacy API-key path that left it unset is gone (#629), so a request without a
gateway identity is never more than a member.
"""

from rest_framework.permissions import BasePermission, SAFE_METHODS


def _gateway_role(request):
    """Return the caller's gateway role ("owner" | "admin" | "member")."""
    gu = getattr(request, "gateway_user", None)
    if gu is not None and getattr(gu, "role", None):
        return gu.role
    # No gateway identity: the staff flags of request.user are not a role.
    # They were the fallback for guardian's own API keys, which set them on
    # the user to grant admin beside the gateway (#629).
    return "member"


def _is_authenticated(request):
    user = getattr(request, "user", None)
    return bool(user and user.is_authenticated)


class IsGatewayAdminOrReadOnly(BasePermission):
    """Any authenticated user may read (safe methods); only owner/admin (by
    gateway role) may perform a mutating request. Enforces #181 at the service
    layer so a plain member cannot run admin-only writes even by calling the
    service directly behind the gateway."""

    def has_permission(self, request, view):
        if not _is_authenticated(request):
            return False
        if request.method in SAFE_METHODS:
            return True
        return _gateway_role(request) in ("owner", "admin")

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


def RequireGatewayRole(*roles):
    """Permission factory requiring the caller's gateway role to be one of
    ``roles`` for ALL methods (no public-read side)::

        permission_classes = [RequireGatewayRole("owner", "admin")]
    """
    allowed = tuple(roles)

    class _RequireGatewayRole(BasePermission):
        def has_permission(self, request, view):
            return _is_authenticated(request) and _gateway_role(request) in allowed

        def has_object_permission(self, request, view, obj):
            return self.has_permission(request, view)

    _RequireGatewayRole.__name__ = "RequireGatewayRole_" + "_".join(allowed or ("none",))
    return _RequireGatewayRole


# The role/domain permission classes below keep their names (used across the
# viewsets) but now enforce the read-for-members / mutate-for-admins policy.
class IsAssetManager(IsGatewayAdminOrReadOnly):
    """Asset management: read for any authenticated user, mutate for owner/admin."""


class IsComplianceManager(IsGatewayAdminOrReadOnly):
    """Compliance management: read for members, mutate for owner/admin."""


class IsSecurityAnalyst(IsGatewayAdminOrReadOnly):
    """Security analysis: read for members, mutate for owner/admin."""


class IsVulnerabilityManager(IsGatewayAdminOrReadOnly):
    """Vulnerability management: read for members, mutate for owner/admin."""
