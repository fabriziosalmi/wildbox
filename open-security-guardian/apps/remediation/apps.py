"""
Remediation App Configuration

Django app for vulnerability remediation workflow management.
"""

from django.apps import AppConfig


class RemediationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.remediation'
    verbose_name = 'Vulnerability Remediation'
    
    def ready(self):
        """Import signals when app is ready"""
        try:
            from . import signals
        except ImportError:
            pass
