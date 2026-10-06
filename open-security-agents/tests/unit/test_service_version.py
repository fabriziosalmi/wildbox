"""agents tells a caller one version (#743).

``app/main.py`` has ``SERVICE_VERSION``, "one version, in one place", and
passed it to ``FastAPI(version=...)`` and to the root endpoint. The
``X-API-Version`` header of every response came from a second literal,
``install_observability(service_version="0.1.6")``: the place a release
forgets. It reads the same name now.

The application is built when its module is imported, so the probe runs in a
fresh interpreter, like the API documentation test. It does not enter the
lifespan and needs neither Redis nor a model provider.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[2]
APP = "app.main:app"

# What the settings need before the module can be imported; test-only values.
SETTINGS = {
    "SECRET_KEY": "x" * 40,
    "GATEWAY_INTERNAL_SECRET": "y" * 40,
}

MARKER = "SERVICE_VERSION_PROBE "
PROBE = f"""
import importlib, json, sys
from fastapi.testclient import TestClient

module_name, _, attribute = sys.argv[1].partition(":")
module = importlib.import_module(module_name)
app = getattr(module, attribute)
response = TestClient(app).get("/no-such-route")
print({MARKER!r} + json.dumps({{
    "schema": app.version,
    "header": response.headers.get("X-API-Version"),
    "constant": module.SERVICE_VERSION,
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


def test_the_schema_and_the_header_carry_the_one_version():
    versions = probe()

    assert re.fullmatch(r"\d+\.\d+\.\d+", versions["constant"])
    assert versions == {
        "schema": versions["constant"],
        "header": versions["constant"],
        "constant": versions["constant"],
    }


def test_the_version_is_written_once_in_the_application_module():
    source = (SERVICE_ROOT / "app" / "main.py").read_text(encoding="utf-8")

    assert re.findall(r"""["'](\d+\.\d+\.\d+)["']""", source) == [
        re.search(r'SERVICE_VERSION = "([^"]+)"', source).group(1)
    ]
