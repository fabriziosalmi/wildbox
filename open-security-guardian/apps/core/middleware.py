"""
Core Middleware - Custom middleware for Guardian

The Guardian: Proactive Vulnerability Management
"""

import json
import time
import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings
from apps.core.models import APIKey, AuditLog


logger = logging.getLogger(__name__)


class APIKeyMiddleware(MiddlewareMixin):
    """Middleware to handle API key authentication for specific endpoints."""
    
    def process_request(self, request):
        """Process incoming request."""
        # Skip for non-API endpoints
        if not request.path.startswith('/api/'):
            return None
        
        # Skip for documentation endpoints
        if request.path in ['/api/schema/', '/docs/', '/redoc/']:
            return None
        
        # Skip for health check
        if request.path == '/health/':
            return None
        
        # Check for API key
        api_key = self.get_api_key(request)
        if not api_key:
            return JsonResponse({
                'error': 'API key required',
                'message': 'Please provide API key in X-API-Key header or Authorization header'
            }, status=401)
        
        # Validate API key
        try:
            key_obj = APIKey.objects.select_related('user').get(
                key=api_key,
                is_active=True
            )
            
            if key_obj.is_expired():
                return JsonResponse({
                    'error': 'API key expired',
                    'message': 'The provided API key has expired'
                }, status=401)
            
            # Store API key in request for later use
            request.api_key = key_obj
            
        except APIKey.DoesNotExist:
            return JsonResponse({
                'error': 'Invalid API key',
                'message': 'The provided API key is not valid'
            }, status=401)
        
        return None
    
    def get_api_key(self, request):
        """Extract API key from request headers."""
        # Try X-API-Key header first
        api_key = request.META.get('HTTP_X_API_KEY')
        
        if not api_key:
            # Try Authorization header with Bearer token
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            if auth_header and auth_header.startswith('Bearer '):
                api_key = auth_header[7:]  # Remove 'Bearer ' prefix
        
        return api_key


class RequestLoggingMiddleware(MiddlewareMixin):
    """Middleware to log all API requests."""
    
    def process_request(self, request):
        """Log incoming request."""
        request.start_time = time.time()
        
        # Only log API requests
        if request.path.startswith('/api/'):
            logger.info(
                "API Request",
                extra={
                    'method': request.method,
                    'path': request.path,
                    'user': getattr(request, 'user', None),
                    'ip_address': self.get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                }
            )
    
    def process_response(self, request, response):
        """Log response details."""
        if hasattr(request, 'start_time') and request.path.startswith('/api/'):
            duration = time.time() - request.start_time
            
            logger.info(
                "API Response",
                extra={
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                    'duration_ms': round(duration * 1000, 2),
                    'user': getattr(request, 'user', None),
                    'ip_address': self.get_client_ip(request),
                }
            )
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class AuditMiddleware(MiddlewareMixin):
    """Middleware to create audit logs for important actions."""
    
    def process_response(self, request, response):
        """Create audit log entry for significant actions."""
        # Only audit API requests
        if not request.path.startswith('/api/'):
            return response
        
        # Skip health checks and documentation
        if request.path in ['/health/', '/api/schema/', '/docs/', '/redoc/']:
            return response
        
        # Only audit write operations
        if request.method not in ['POST', 'PUT', 'PATCH', 'DELETE']:
            return response
        
        # Only audit successful operations
        if response.status_code >= 400:
            return response
        
        try:
            # Determine action based on method
            action_map = {
                'POST': 'CREATE',
                'PUT': 'UPDATE',
                'PATCH': 'UPDATE',
                'DELETE': 'DELETE',
            }
            
            # Extract resource information from path
            path_parts = request.path.strip('/').split('/')
            resource_type = path_parts[2] if len(path_parts) > 2 else 'unknown'
            resource_id = path_parts[3] if len(path_parts) > 3 else ''
            
            # Create audit log entry
            AuditLog.objects.create(
                user=getattr(request, 'user', None),
                api_key=getattr(request, 'api_key', None),
                action=action_map.get(request.method, 'UNKNOWN'),
                resource_type=resource_type,
                resource_id=resource_id,
                description=f"{request.method} {request.path}",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                metadata={
                    'status_code': response.status_code,
                    'method': request.method,
                    'path': request.path,
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
