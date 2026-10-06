"""No log level makes the service log the requests it signs (#755).

A scan signs every request with the credentials of the account it scans.
botocore, at DEBUG, logs the canonical request it signs, with the session
token among its headers, and urllib3 the URL of each call. ``LOG_LEVEL`` is
the operator's to set, to DEBUG among others, so those libraries are held to
warnings and errors in both processes: the API, through the shared error
handlers, and the worker, which makes no application and says so itself.
"""

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

SERVICE = Path(__file__).resolve().parents[2]

PROCESS = """
import logging
import {module}
logging.getLogger().setLevel(logging.DEBUG)
names = ("botocore", "botocore.auth", "botocore.endpoint", "boto3", "urllib3", "httpx")
print(*(logging.getLogger(n).getEffectiveLevel() for n in names))
"""


@pytest.mark.parametrize("module", ["app.main", "app.worker"])
def test_the_cloud_and_http_libraries_log_warnings_only(module, tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", PROCESS.format(module=module)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(SERVICE),
            "ENVIRONMENT": "development",
            "LOG_LEVEL": "DEBUG",
            "SECRET_KEY": "test-only-secret-key-at-least-32-chars-long",
            "CSPM_CREDENTIAL_KEY": "dGVzdC1vbmx5LWtleS1ub3QtdXNlZC1mb3ItY3J5cHRvISE=",
        },
        timeout=180,
    )

    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.split()[-6:] == [str(logging.WARNING)] * 6
