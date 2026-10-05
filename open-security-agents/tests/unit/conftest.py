"""Settings every unit test of the agents service starts from.

Loaded before any test module, so before ``app.config`` builds its settings.
"""

import os

# The analysis limiter counts in the service's Redis by default
# (app/rate_limit.py). The unit tests run without one: they keep the counters
# in the process, which is the limiter's other supported storage.
os.environ.setdefault("ANALYZE_RATE_LIMIT_STORAGE_URI", "memory://")

# The worker fails a task at once when no model key is set (#717). The unit
# tests replace the agent or its model, so no test calls a model API and this
# value is never sent anywhere; tests of the unconfigured case clear it.
os.environ.setdefault("ANTHROPIC_API_KEY", "unit-tests-do-not-call-the-model")
