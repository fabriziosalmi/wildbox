"""identity serves its API schema and documentation pages in development only.

/docs, /redoc and /openapi.json map every route, admin and internal ones
included. identity served the two pages unconditionally (#496), then turned
all three off for the exact value ``production`` only, so ``staging`` still
published them (#679). The rule is now the one every service shares
(``open_security_shared.api_docs``): served when ``ENVIRONMENT`` is
``development``, 404 in any other environment.

Every FastAPI service has this test, with the same shape. The application is
built when its module is imported, from the environment of that moment, so
each case imports it in a fresh interpreter: reloading it in this one would
leave the other tests of the session with an application built for another
environment. The probe does not enter the lifespan, so it needs no database.
"""

import json
import os
import string
import subprocess
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]

# Where the application object lives, as uvicorn names it.
APP = "app.main:app"

# What the settings need before the module can be imported; test-only values.
SETTINGS = {
    "DATABASE_URL": "postgresql://test:test@localhost:5432/test",
    "JWT_SECRET_KEY": "a" * 32,
    # Required when ENVIRONMENT=production; needs enough distinct characters.
    "API_KEY_HASH_SECRET": string.ascii_letters[:40],
}

DOCS, REDOC, SCHEMA = "/docs", "/redoc", "/openapi.json"
IN_DEVELOPMENT = {DOCS: 200, REDOC: 200, SCHEMA: 200}
OUTSIDE_DEVELOPMENT = {DOCS: 404, REDOC: 404, SCHEMA: 404}

MARKER = "API_DOCS_PROBE "
PROBE = f"""
import importlib, json, sys
from fastapi.testclient import TestClient

module, _, attribute = sys.argv[1].partition(":")
client = TestClient(getattr(importlib.import_module(module), attribute))
statuses = {{path: client.get(path).status_code for path in sys.argv[2:]}}
print({MARKER!r} + json.dumps(statuses))
"""


def statuses(environment, **overrides):
    """The status of each documentation path under ENVIRONMENT=environment."""
    env = {**os.environ, **SETTINGS, "ENVIRONMENT": environment, **overrides}
    result = subprocess.run(
        [sys.executable, "-c", PROBE, APP, DOCS, REDOC, SCHEMA],
        cwd=SERVICE_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    lines = [line for line in result.stdout.splitlines() if line.startswith(MARKER)]
    assert len(lines) == 1, result.stdout[-2000:]
    return json.loads(lines[0][len(MARKER) :])


@pytest.mark.parametrize(
    "environment, expected",
    [
        ("development", IN_DEVELOPMENT),
        ("production", OUTSIDE_DEVELOPMENT),
        # The rule asks for "development"; it does not exclude "production".
        # An environment it does not know is closed.
        ("staging", OUTSIDE_DEVELOPMENT),
    ],
)
def test_schema_and_docs_are_served_in_development_only(environment, expected):
    assert statuses(environment) == expected
