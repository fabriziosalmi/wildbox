"""
Open Security Guardian - Main Django Package

The Guardian: Proactive Vulnerability Management
"""

# The version of the service, stated here only: guardian/settings.py gives
# it to the API schema. This said 1.0.0 and the schema 0.1.6 (#665).
__version__ = "0.1.6"
__author__ = "Wildbox Security"
__description__ = "Proactive Vulnerability Management Platform"

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app

__all__ = ('celery_app',)
