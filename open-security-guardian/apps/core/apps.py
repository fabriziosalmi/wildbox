"""
Core Application Configuration

The Guardian: Proactive Vulnerability Management
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'
    verbose_name = 'Core System'
    
    def ready(self):
        """Initialize the application when Django starts."""
        # Import signal handlers
        from . import signals  # noqa
