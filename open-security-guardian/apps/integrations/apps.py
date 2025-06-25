"""
Integrations App Configuration

Django app for external system integrations (JIRA, ServiceNow, SIEM, etc.).
"""

from django.apps import AppConfig


class IntegrationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.integrations'
    verbose_name = 'External Integrations'
    
    def ready(self):
        """Import signals when app is ready"""
        try:
            from . import signals
        except ImportError:
            pass
