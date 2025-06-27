"""
Open Security Guardian - Main Django Package

The Guardian: Proactive Vulnerability Management
"""

__version__ = "1.0.0"
__author__ = "Wildbox Security"
__description__ = "Proactive Vulnerability Management Platform"

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app

__all__ = ('celery_app',)
