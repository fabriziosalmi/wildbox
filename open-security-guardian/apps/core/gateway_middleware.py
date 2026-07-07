"""
Gateway Authentication Middleware for Guardian (Django)

This middleware trusts X-Wildbox-* headers injected by the API gateway
after successful authentication. In production, all traffic MUST go through
the gateway which validates credentials and injects these trusted headers.
"""

import hmac
import logging
import os
import uuid
from django.contrib.auth.models import User
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings


logger = logging.getLogger(__name__)


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


class GatewayUser:
    """
    User object constructed from gateway headers.
    
    This class provides a Django-compatible user object that can be used
    in views and serializers, populated from gateway authentication headers.
    """
    
    def __init__(self, user_id, team_id, role="member"):
        self.id = user_id
        self.pk = user_id  # Django REST framework compatibility
        self.user_id = user_id
        self.team_id = team_id
        self.role = role
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


class GatewayAuthMiddleware(MiddlewareMixin):
    """
    Middleware to handle gateway-based authentication.
    
    Reads X-Wildbox-* headers injected by the gateway and creates
    a GatewayUser object attached to the request.
    
    Priority:
    1. Gateway headers (production mode)
    2. Legacy API key (backward compatibility during migration)
    3. Reject request
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
        
        # Priority 1: Gateway headers (production mode)
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

                # Create GatewayUser object
                request.gateway_user = GatewayUser(
                    user_id=str(user_id),
                    team_id=str(team_id),
                    role=role
                )

                # request.user must be a real auth.User so that created_by /
                # assigned_to FKs (integer PK) can be persisted; the rich
                # gateway attributes remain on request.gateway_user.
                request.user = _mirror_db_user(str(user_id), role)

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
        
        # Priority 2: Legacy API key (backward compatibility)
        # Check for X-API-Key header for direct access during migration
        api_key_header = request.META.get('HTTP_X_API_KEY')
        
        if api_key_header:
            logger.warning(
                f"[GATEWAY-AUTH] Legacy API key authentication used for {request.path} - "
                "migrate to gateway authentication"
            )
            
            # Import here to avoid circular dependency
            from apps.core.models import APIKey
            
            try:
                key_obj = APIKey.objects.select_related('user').get(
                    key=api_key_header,
                    is_active=True
                )
                
                if key_obj.is_expired():
                    return JsonResponse({
                        'error': 'api_key_expired',
                        'message': 'The provided API key has expired'
                    }, status=401)
                
                # Legacy keys get full access during migration.
                request.gateway_user = GatewayUser(
                    user_id=str(key_obj.user.id),
                    team_id=str(getattr(key_obj, 'team_id', '00000000-0000-0000-0000-000000000001')),
                    role='admin'
                )
                # key_obj.user is already a real auth.User row — use it directly
                # (privileged in-memory to match the legacy admin role) so writes
                # persist instead of 500ing.
                db_user = key_obj.user
                db_user.is_staff = True
                db_user.is_superuser = True
                request.user = db_user
                request.api_key = key_obj  # Keep for backward compatibility
                
                return None
                
            except APIKey.DoesNotExist:
                return JsonResponse({
                    'error': 'invalid_api_key',
                    'message': 'The provided API key is not valid'
                }, status=401)
        
        # No authentication provided
        return JsonResponse({
            'error': 'authentication_required',
            'message': 'Authentication required. Provide X-API-Key header or access via gateway.',
            'code': 'NO_AUTH'
        }, status=401)
    
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
