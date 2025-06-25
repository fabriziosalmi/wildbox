"""
Scanners App Configuration

Django app for vulnerability scanner integration and management.
"""

from django.apps import AppConfig


class ScannersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.scanners'
    verbose_name = 'Vulnerability Scanners'
    
    def ready(self):
        """Import signals when app is ready"""
        try:
            from . import signals
        except ImportError:
            pass
