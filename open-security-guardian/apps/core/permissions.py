"""
Custom permissions for the Guardian application.
"""

from rest_framework.permissions import BasePermission


class IsAssetManager(BasePermission):
    """
    Permission class that allows access to asset management functions.
    Currently allows any authenticated user, but can be extended
    to check for specific roles or groups.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has asset management permissions.
        """
        # For now, any authenticated user can manage assets
        # This can be extended to check for specific groups or roles
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user has permission to access specific asset object.
        """
        # For now, any authenticated user can access any asset
        # This can be extended to check ownership or team membership
        return request.user and request.user.is_authenticated


class IsComplianceManager(BasePermission):
    """
    Permission class for compliance management functions.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsSecurityAnalyst(BasePermission):
    """
    Permission class for security analysis functions.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsVulnerabilityManager(BasePermission):
    """
    Permission class for vulnerability management functions.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
