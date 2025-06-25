"""
Core Authentication - API Key authentication

The Guardian: Proactive Vulnerability Management
"""

from django.contrib.auth.models import AnonymousUser
from rest_framework import authentication
from rest_framework import exceptions
from apps.core.models import APIKey


class APIKeyAuthentication(authentication.BaseAuthentication):
    """API Key based authentication."""
    
    def authenticate(self, request):
        """Authenticate request using API key."""
        api_key = self.get_api_key(request)
        
        if not api_key:
            return None
        
        try:
            key_obj = APIKey.objects.select_related('user').get(
                key=api_key,
                is_active=True
            )
            
            # Check if key is expired
            if key_obj.is_expired():
                raise exceptions.AuthenticationFailed('API key expired')
            
            # Update last used timestamp
            key_obj.update_last_used()
            
            return (key_obj.user, key_obj)
            
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid API key')
    
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
    
    def authenticate_header(self, request):
        """Return authentication header."""
        return 'Bearer'
