"""data tells a caller one version (#743).

``app/api/main.py`` passed the literal ``"0.1.6"`` to ``FastAPI(version=...)``
and again to ``install_observability(service_version=...)``, beside the
``__version__`` of ``app/__init__.py``: three places to change at a release.
Both now read ``app.__version__``, so the OpenAPI schema and the
``X-API-Version`` header of every response cannot disagree.

The application is built when its module is imported, so the probe runs in a
fresh interpreter, like the API documentation test. It does not enter the
lifespan and needs no database.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[2]
APP = "app.api.main:app"

# What the settings need before the module can be imported; test-only values.
SETTINGS = {
    "SECRET_KEY": "x" * 40,
    "DATABASE_URL": "postgresql://test:test@localhost:5432/test",
    "DEBUG": "false",
}

MARKER = "SERVICE_VERSION_PROBE "
PROBE = f"""
import importlib, json, sys
from fastapi.testclient import TestClient

module, _, attribute = sys.argv[1].partition(":")
app = getattr(importlib.import_module(module), attribute)
response = TestClient(app).get("/no-such-route")
print({MARKER!r} + json.dumps({{
    "schema": app.version,
    "header": response.headers.get("X-API-Version"),
    "package": importlib.import_module("app").__version__,
}}))
"""


def probe():
    result = subprocess.run(
        [sys.executable, "-c", PROBE, APP],
        cwd=SERVICE_ROOT,
        env={**os.environ, **SETTINGS, "ENVIRONMENT": "production"},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    (line,) = [ln for ln in result.stdout.splitlines() if ln.startswith(MARKER)]
    return json.loads(line[len(MARKER) :])


def test_the_schema_and_the_header_carry_the_packages_version():
    versions = probe()

    assert re.fullmatch(r"\d+\.\d+\.\d+", versions["package"])
    assert versions == {
        "schema": versions["package"],
        "header": versions["package"],
        "package": versions["package"],
    }


def test_the_application_module_writes_no_version():
    source = (SERVICE_ROOT / "app" / "api" / "main.py").read_text(encoding="utf-8")

    assert re.findall(r"""version\s*=\s*["']\d+\.\d+\.\d+["']""", source) == []
