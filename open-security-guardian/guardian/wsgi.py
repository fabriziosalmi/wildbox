"""
WSGI config for Open Security Guardian

The Guardian: Proactive Vulnerability Management
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'guardian.settings')

application = get_wsgi_application()
