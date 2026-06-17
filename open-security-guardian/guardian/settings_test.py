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

from guardian.settings import *  # noqa: F401,F403,E402
