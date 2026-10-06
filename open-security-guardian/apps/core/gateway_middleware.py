"""
Gateway Authentication Middleware for Guardian (Django)

This middleware trusts X-Wildbox-* headers injected by the API gateway
after successful authentication. In production, all traffic MUST go through
the gateway which validates credentials and injects these trusted headers.

API-key scopes (#637). The gateway requires a scope of every request it
forwards to guardian: data:read to read, data:write to change, data:delete
to delete. It used to be the only check. The gateway now forwards what the
credential is (X-Wildbox-Auth-Type) and an API key's scopes
(X-Wildbox-Scopes), and this middleware, the one way into the API, checks
the same scope again with the rules every other service uses
(open_security_shared.scopes). A session is not limited by scopes; a
request that does not say what its credential is is refused.
"""

import hmac
import logging
import os
import uuid
from datetime import timedelta
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings

from open_security_shared.scopes import (
    credential_allows,
    parse_auth_type,
    parse_scopes,
    scope_for_method,
)


logger = logging.getLogger(__name__)

# What the gateway requires on /api/v1/guardian/, by method (ROUTE_SCOPES /
# required_scope_for_request in the gateway's auth_handler.lua).
SCOPE_READ = "data:read"
SCOPE_WRITE = "data:write"
SCOPE_DELETE = "data:delete"


def required_scope(method):
    """The scope a guardian request needs: read, write, or delete."""
    return scope_for_method(method, SCOPE_READ, SCOPE_WRITE, SCOPE_DELETE)


def _mirror_db_user(user_id, role):
    """Return the local ``auth.User`` mirror for an identity-service user.

    Guardian's models FK to ``django.contrib.auth.User`` (an *integer* PK),
    but the gateway authenticates against the identity service, whose users
    are UUIDs. A ``GatewayUser`` (UUID pk, not a DB row) cannot be persisted
    into those FKs, so ``created_by=request.user`` raised on every write and
    every mutating endpoint returned 500.

    We mirror the identity user into ``auth_user`` keyed by its UUID (stored
    in ``username``); display name / email stay owned by identity and are not
    synced here. The role is reflected on the *in-memory* instance only (never
    persisted) so ``has_perm`` keeps the previous ``GatewayUser`` semantics:
    owner/admin are privileged, members are not.
    """
    user, _ = User.objects.get_or_create(
        username=str(user_id),
        defaults={'is_active': True},
    )
    privileged = role in ('owner', 'admin')
    user.is_staff = privileged
    user.is_superuser = privileged
    return user


#: A membership row's last_seen is rewritten at most this often: a request
#: every second is not a database write every second. It only has to be far
#: below settings.TEAM_MEMBERSHIP_MAX_AGE (a day at the least), so that a
#: member who keeps using guardian never looks stale.
MEMBERSHIP_REFRESH_INTERVAL = timedelta(minutes=5)


def _record_membership(user, team_id):
    """Record that ``user`` acts as a member of ``team_id``, now (#642, #676).

    The gateway authenticated this request, so identity says the user is in
    the team at this moment. That is what a membership row is worth, and
    why it expires (apps.core.tenancy.current_memberships): a user identity
    has removed from the team no longer gets here to refresh it.
    """
    from apps.core.memberships import revoked_recently
    from apps.core.models import TeamMembership

    now = timezone.now()
    membership = TeamMembership.objects.filter(team_id=team_id, user=user).first()
    if membership is not None:
        if membership.last_seen < now - MEMBERSHIP_REFRESH_INTERVAL:
            TeamMembership.objects.filter(pk=membership.pk).update(last_seen=now)
        return

    # No row. identity may have just said that this membership ended, and
    # this request have been authenticated a moment before it did: recording
    # it would make the former member one of the team's users again for a
    # whole window (#724; apps.core.memberships).
    if revoked_recently(user.username, team_id, now):
        logger.info(
            "[GATEWAY-AUTH] Membership of %s in %s not recorded: identity "
            "ended it moments ago",
            user.username,
            team_id,
        )
        return
    membership, created = TeamMembership.objects.get_or_create(
        team_id=team_id, user=user, defaults={'last_seen': now}
    )
    # The notice may have arrived between the check and the row. It is
    # written before the rows are deleted, so one of the two sees the other:
    # either the deletion removed this row, or the note is there now.
    if created and revoked_recently(user.username, team_id):
        TeamMembership.objects.filter(pk=membership.pk).delete()


class GatewayUser:
    """
    User object constructed from gateway headers.
    
    This class provides a Django-compatible user object that can be used
    in views and serializers, populated from gateway authentication headers.
    """
    
    def __init__(self, user_id, team_id, role="member", auth_type=None, scopes=None):
        self.id = user_id
        self.pk = user_id  # Django REST framework compatibility
        self.user_id = user_id
        self.team_id = team_id
        self.role = role
        # How the caller authenticated at the gateway (#637): "session",
        # "api_key" or "service", or None when the request did not say.
        self.auth_type = auth_type
        # The scopes of an API key, or None when the gateway forwarded none
        # (a session or a service, which are not limited by scopes).
        self.scopes = scopes
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
        self.is_staff = (role in ["owner", "admin"])
        self.is_superuser = (role == "owner")

    def __str__(self):
        return f"GatewayUser(user_id={self.user_id}, team_id={self.team_id}, role={self.role})"
    
    def __repr__(self):
        return self.__str__()
    
    def has_perm(self, perm, obj=None):
        """Check if the user has a Django-style permission.

        Owner/admin get everything. A member gets ONLY read permissions
        (``view_*`` / ``read_*``) and never cross-tenant ``*_all`` scopes or any
        add/change/delete/manage perm. Matching is on the perm codename
        (``app_label.codename``) by prefix, not a loose substring, so a perm
        like ``approve_review`` can't slip through on the word "view".
        """
        if self.role in ("owner", "admin"):
            return True
        if self.role != "member":
            return False
        codename = perm.split(".", 1)[-1] if isinstance(perm, str) else ""
        if "_all" in codename:  # cross-tenant view_all_* etc.
            return False
        return codename.startswith(("view_", "read_")) or codename in ("view", "read")
    
    def has_module_perms(self, app_label):
        """Check if user has module permissions."""
        return self.role in ["owner", "admin", "member"]

    def has_scope(self, required):
        """Whether the caller's credential may do what needs ``required``.

        The middleware already requires the scope of the request's method.
        This is for a view that needs a narrower rule of its own; DRF views
        reach the same object as ``request.auth``.
        """
        return credential_allows(self.auth_type, self.scopes, required)


class GatewayAuthMiddleware(MiddlewareMixin):
    """
    Middleware to handle gateway-based authentication.
    
    Reads X-Wildbox-* headers injected by the gateway and creates
    a GatewayUser object attached to the request.
    
    A request under /api/ is authenticated by the gateway's headers, with the
    shared secret as proof of origin, or it is refused. There is no other way
    in: guardian keeps no credentials of its own (#629).
    """
    
    def process_request(self, request):
        """Process incoming request and authenticate via gateway headers."""
        
        # Skip for non-API endpoints
        if not request.path.startswith('/api/'):
            return None
        
        # Skip for documentation endpoints
        if request.path in ['/api/schema/', '/docs/', '/redoc/']:
            return None
        
        # Skip for health check
        if request.path == '/health/':
            return None
        
        # Gateway headers: the only authentication guardian accepts.
        user_id_header = request.META.get('HTTP_X_WILDBOX_USER_ID')
        team_id_header = request.META.get('HTTP_X_WILDBOX_TEAM_ID')

        if user_id_header and team_id_header:
            # Proof-of-origin: X-Wildbox-* headers are only trustworthy when the
            # request carries the shared gateway secret. The service port is
            # reachable directly, so without this a client could forge
            # X-Wildbox-User-ID/Role and authenticate as anyone. Enforced when the
            # secret is configured.
            gw_secret = os.getenv('GATEWAY_INTERNAL_SECRET')
            if not gw_secret:
                # Fail closed: without the secret we cannot verify the request
                # came from the gateway, so the X-Wildbox-* headers can't be trusted.
                logger.error("[GATEWAY-AUTH] GATEWAY_INTERNAL_SECRET not configured — refusing to trust gateway headers (fail-closed).")
                return JsonResponse({
                    'error': 'service_misconfigured',
                    'message': 'GATEWAY_INTERNAL_SECRET is not set; the service cannot verify gateway origin.',
                    'code': 'GATEWAY_SECRET_NOT_CONFIGURED',
                }, status=503)
            provided = request.META.get('HTTP_X_GATEWAY_SECRET', '')
            if not hmac.compare_digest(provided, gw_secret):
                logger.warning("[GATEWAY-AUTH] Rejected X-Wildbox-* headers without a valid gateway secret")
                return JsonResponse({
                    'error': 'forbidden',
                    'message': 'Direct access is not permitted; requests must traverse the gateway.',
                    'code': 'GATEWAY_SECRET_REQUIRED',
                }, status=403)
            try:
                # Validate UUIDs
                user_id = uuid.UUID(user_id_header)
                team_id = uuid.UUID(team_id_header)
                
                # Extract role
                role = request.META.get('HTTP_X_WILDBOX_ROLE', 'member')

                # What the credential is and what it may do (#637). Read
                # strictly: a value the gateway never writes raises, and is
                # answered 400 below, not taken for "no limit".
                auth_type = parse_auth_type(request.META.get('HTTP_X_WILDBOX_AUTH_TYPE'))
                scopes = parse_scopes(request.META.get('HTTP_X_WILDBOX_SCOPES'))

                # The scope the gateway required of this request, checked
                # again before anything is read or written, the user's
                # mirror row included.
                needed = required_scope(request.method)
                if not credential_allows(auth_type, scopes, needed):
                    return self._refuse_scope(request, auth_type, needed)

                # Create GatewayUser object
                request.gateway_user = GatewayUser(
                    user_id=str(user_id),
                    team_id=str(team_id),
                    role=role,
                    auth_type=auth_type,
                    scopes=scopes,
                )

                # request.user must be a real auth.User so that created_by /
                # assigned_to FKs (integer PK) can be persisted; the rich
                # gateway attributes remain on request.gateway_user.
                request.user = _mirror_db_user(str(user_id), role)
                # The team this user acts in: what a team may reference
                # when it names a user (#642).
                _record_membership(request.user, team_id)

                logger.info(
                    f"[GATEWAY-AUTH] Authenticated user {user_id} from gateway headers "
                    f"(team: {team_id}, role: {role})"
                )
                
                return None
                
            except (ValueError, AttributeError) as e:
                logger.error(f"[GATEWAY-AUTH] Invalid gateway headers: {e}")
                return JsonResponse({
                    'error': 'invalid_gateway_headers',
                    'message': 'Gateway provided malformed authentication headers',
                    'code': 'INVALID_GATEWAY_HEADERS'
                }, status=400)
        
        # Anything else did not come through the gateway. guardian used to
        # accept its own APIKey rows from an X-API-Key header here, as an admin
        # and a superuser, beside the gateway: that path skipped identity, key
        # revocation, team scoping and the gateway's rate limits (#629). It is
        # gone. A direct request is refused whatever header it carries, with
        # the answer the other services give (open-security-shared's
        # gateway_auth).
        logger.warning(
            "[GATEWAY-AUTH] Refused %s %s: no gateway authentication headers",
            request.method,
            request.path,
        )
        return JsonResponse({
            'error': 'Gateway authentication required',
            'message': (
                'This service must be accessed through the API gateway. '
                'Direct access is not permitted.'
            ),
            'code': 'GATEWAY_AUTH_REQUIRED',
        }, status=403)

    @staticmethod
    def _refuse_scope(request, auth_type, needed):
        """403 for a credential that may not do what needs ``needed``."""
        if auth_type is None:
            # Not a key without the scope: nothing says what the credential
            # is. A gateway from before #637 does not send the header.
            logger.warning(
                "[GATEWAY-AUTH] Refused %s %s: the gateway did not state the auth type",
                request.method,
                request.path,
            )
            return JsonResponse({
                'error': 'Gateway authentication required',
                'message': (
                    'The gateway did not say how the caller authenticated '
                    '(X-Wildbox-Auth-Type). Upgrade the gateway together with this service.'
                ),
                'code': 'GATEWAY_AUTH_TYPE_REQUIRED',
                'required_scope': needed,
            }, status=403)
        logger.warning(
            "[GATEWAY-AUTH] Refused %s %s: the API key lacks scope %s",
            request.method,
            request.path,
            needed,
        )
        return JsonResponse({
            'error': 'insufficient_scope',
            'message': 'This API key is not authorized for this operation.',
            'code': 'INSUFFICIENT_SCOPE',
            'required_scope': needed,
        }, status=403)

    def process_response(self, request, response):
        """Process outgoing response."""
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        
        return response


# Helper function for views to check gateway authentication
def require_gateway_auth(view_func):
    """
    Decorator to ensure request has gateway authentication.
    
    Usage:
        @require_gateway_auth
        def my_view(request):
            user = request.gateway_user
            ...
    """
    def wrapper(request, *args, **kwargs):
        if not hasattr(request, 'gateway_user'):
            return JsonResponse({
                'error': 'authentication_required',
                'message': 'This endpoint requires gateway authentication',
                'code': 'GATEWAY_AUTH_REQUIRED'
            }, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def require_role(*required_roles):
    """
    Decorator to check if user has required role.
    
    Usage:
        @require_role('owner', 'admin')
        def admin_view(request):
            ...
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not hasattr(request, 'gateway_user'):
                return JsonResponse({
                    'error': 'authentication_required',
                    'message': 'Authentication required',
                    'code': 'NO_AUTH'
                }, status=401)
            
            if request.gateway_user.role not in required_roles:
                return JsonResponse({
                    'error': 'insufficient_permissions',
                    'message': f'This action requires one of these roles: {", ".join(required_roles)}',
                    'code': 'INSUFFICIENT_ROLE'
                }, status=403)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
