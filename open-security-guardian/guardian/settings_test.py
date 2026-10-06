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
# A deployment whose operator allows a lab, so that the suite exercises
# discoveries and scans: the documentation ranges (RFC 5737, RFC 3849), which
# the scan target policy refuses like any other address that is not public
# (#748) and which route nowhere. The fixtures and the tests name networks in
# them. Nothing else internal is allowed; a test of a deployment that allows
# nothing, which is the default, empties settings.SCAN_ALLOWED_INTERNAL_TARGETS
# (tests/unit/test_scan_target_policy.py).
os.environ.setdefault(
    "GUARDIAN_ALLOWED_INTERNAL_TARGETS",
    "192.0.2.0/24,198.51.100.0/24,203.0.113.0/24,2001:db8::/32",
)

from guardian.settings import *  # noqa: F401,F403,E402
