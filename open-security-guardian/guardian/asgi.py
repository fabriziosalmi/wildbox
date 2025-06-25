"""
ASGI config for Open Security Guardian

The Guardian: Proactive Vulnerability Management
"""

import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'guardian.settings')

application = get_asgi_application()
