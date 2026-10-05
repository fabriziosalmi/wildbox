"""The unit suite runs as a development environment, and says so.

Only ``ENVIRONMENT=development`` is a development environment. Every other
value, and no value at all, is held to the start-up checks: the data service
refuses to start without ``SECRET_KEY`` and ``DATABASE_URL``, or with
``DEBUG`` on (#736). The test modules import the application without them,
which was enough while a missing ``ENVIRONMENT`` meant development (#722)
and while the checks were for the exact value ``production`` only.

Declared here, before any test module imports ``app.config``. The tests
about other environments start the service in a process of their own, with
the environment they name (``test_api_docs_exposure.py``,
``test_startup_checks.py``).
"""

import os

os.environ.setdefault("ENVIRONMENT", "development")
