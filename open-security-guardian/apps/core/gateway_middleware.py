"""
Gateway Authentication Middleware for Guardian (Django)

This middleware trusts X-Wildbox-* headers injected by the API gateway
after successful authentication. In production, all traffic MUST go through
the gateway which validates credentials and injects these trusted headers.
"""

import logging
import uuid
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings


logger = logging.getLogger(__name__)


class GatewayUser:
    """
    User object constructed from gateway headers.
    
    This class provides a Django-compatible user object that can be used
    in views and serializers, populated from gateway authentication headers.
    """
    
    def __init__(self, user_id, team_id, plan="free", role="member"):
        self.id = user_id
        self.pk = user_id  # Django REST framework compatibility
        self.user_id = user_id
        self.team_id = team_id
        self.plan = plan
        self.role = role
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
        self.is_staff = (role in ["owner", "admin"])
        self.is_superuser = (role == "owner")
    
    def __str__(self):
        return f"GatewayUser(user_id={self.user_id}, team_id={self.team_id}, plan={self.plan}, role={self.role})"
    
    def __repr__(self):
        return self.__str__()
    
    def has_perm(self, perm):
        """Check if user has permission (basic implementation)."""
        # Admin role has all permissions
        if self.role in ["owner", "admin"]:
            return True
        # Members have read permissions
        if "view" in perm or "read" in perm:
            return True
        return False
    
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
            try:
                # Validate UUIDs
                user_id = uuid.UUID(user_id_header)
                team_id = uuid.UUID(team_id_header)
                
                # Extract plan and role
                plan = request.META.get('HTTP_X_WILDBOX_PLAN', 'free')
                role = request.META.get('HTTP_X_WILDBOX_ROLE', 'member')
                
                # Create GatewayUser object
                request.gateway_user = GatewayUser(
                    user_id=str(user_id),
                    team_id=str(team_id),
                    plan=plan,
                    role=role
                )
                
                # Also set as request.user for Django compatibility
                request.user = request.gateway_user
                
                logger.info(
                    f"[GATEWAY-AUTH] Authenticated user {user_id} from gateway headers "
                    f"(team: {team_id}, plan: {plan}, role: {role})"
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
                
                # Create GatewayUser from API key
                request.gateway_user = GatewayUser(
                    user_id=str(key_obj.user.id),
                    team_id=str(getattr(key_obj, 'team_id', '00000000-0000-0000-0000-000000000001')),
                    plan='enterprise',  # Legacy keys get full access during migration
                    role='admin'
                )
                request.user = request.gateway_user
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


def require_plan(*required_plans):
    """
    Decorator to check if user has required subscription plan.
    
    Usage:
        @require_plan('pro', 'business', 'enterprise')
        def premium_view(request):
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
            
            if request.gateway_user.plan not in required_plans:
                return JsonResponse({
                    'error': 'plan_upgrade_required',
                    'message': f'This feature requires one of these plans: {", ".join(required_plans)}',
                    'code': 'PLAN_UPGRADE_REQUIRED',
                    'current_plan': request.gateway_user.plan
                }, status=402)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


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
