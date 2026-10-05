"""Test settings for the Guardian service.

Sets safe defaults for the environment variables ``guardian.settings`` requires
at import time, then re-exports everything. This keeps the unit suite
self-contained: in-memory SQLite, no external Postgres / Redis / broker.

Used by ``pytest.ini`` (``DJANGO_SETTINGS_MODULE = guardian.settings_test``).
"""
import os

# Force DEBUG off so the dev-only INSTALLED_APPS (django_extensions, etc.) are
# not pulled in — and so an ambient .env (e.g. a repo-root one picked up by
# settings' load_dotenv) can't make the suite non-deterministic.
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret-key-do-not-use-in-prod")
os.environ.setdefault("DATABASE_URL", "sqlite://:memory:")
os.environ.setdefault("CELERY_BROKER_URL", "memory://")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ALLOWED_HOSTS", "*")
os.environ.setdefault("DJANGO_DEBUG", "True")
# A deployment with a mail server, so that the suite exercises sending
# (pytest-django swaps the SMTP backend for Django's in-memory one, and no
# test reaches a server). A test of a deployment without one empties
# settings.EMAIL_HOST. No GUARDIAN_CONTACTS_SECRET: identity is asked only
# by the tests that stand one in (tests/unit/identity_stub.py).
os.environ.setdefault("EMAIL_HOST", "smtp.test.invalid")
os.environ.setdefault("DEFAULT_FROM_EMAIL", "guardian@test.invalid")

from guardian.settings import *  # noqa: F401,F403,E402
