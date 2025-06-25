"""
Core Application - Shared utilities and base classes

The Guardian: Proactive Vulnerability Management
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'
    verbose_name = 'Core System'
