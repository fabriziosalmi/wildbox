"""The unit suite runs as a development environment, and says so.

Only ``ENVIRONMENT=development`` is a development environment. Every other
value, and no value at all, is held to the start-up checks: identity refuses
to start without ``API_KEY_HASH_SECRET`` (#736). The test modules import the
application with the two settings it cannot do without and no more, which
was enough while a missing ``ENVIRONMENT`` meant development (#722) and while
the secret was required for the exact value ``production`` only.

Declared here, before any test module imports ``app.config``. A test that is
about another environment starts the application in a process of its own
with the environment it names (``test_api_docs_exposure.py``,
``test_api_key_hash_secret.py``).
"""

import os

os.environ.setdefault("ENVIRONMENT", "development")
