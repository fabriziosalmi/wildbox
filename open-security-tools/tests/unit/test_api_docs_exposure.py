"""tools serves its API schema in development only, and no documentation page.

/openapi.json maps every route of the service, and tools served it in every
environment (#679). The rule is now the one every service shares
(``open_security_shared.api_docs``): served when ``ENVIRONMENT`` is
``development``, 404 in any other environment.

tools is the one service without /docs and /redoc, in any environment: its
standalone web UI, which served them, is gone (#581), and FastAPI's own pages
load their scripts from a CDN, which the service's Content-Security-Policy
(``script-src 'self'``) blocks.

Every FastAPI service has this test, with the same shape. The application is
built when its module is imported, from the environment of that moment, so
each case imports it in a fresh interpreter: reloading it in this one would
leave the other tests of the session with an application built for another
environment. The probe does not enter the lifespan, so it needs no database.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]

# Where the application object lives, as uvicorn names it.
APP = "app.main:app"

# What the settings need before the module can be imported; test-only values.
SETTINGS = {
    "API_KEY": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
}

DOCS, REDOC, SCHEMA = "/docs", "/redoc", "/openapi.json"
IN_DEVELOPMENT = {DOCS: 404, REDOC: 404, SCHEMA: 200}
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
def test_schema_is_served_in_development_only_and_docs_never(environment, expected):
    assert statuses(environment) == expected
